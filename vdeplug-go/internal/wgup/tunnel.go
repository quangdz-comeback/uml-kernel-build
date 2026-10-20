package wgup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// debugf logs tunnel internals when VDE_DEBUG is set.
var debugf = func(f string, a ...any) {
	if os.Getenv("VDE_DEBUG") != "" {
		log.Printf("[vde_plug-go] wg: "+f, a...)
	}
}

// Mode picks how the tunnel hands out the tunnel address.
type Mode int

const (
	// Standalone (no switch): the Address= is the guest's own address.
	// netstack never owns it and does not NAT it; matching traffic is
	// forwarded statelessly, and replies route back to the guest.
	ModeStandalone Mode = iota
	// Switch (hub+peers): guests keep the slirp NAT; the stack owns the
	// tunnel address, so NAT flows egress with it as their source.
	ModeSwitch
)

const (
	wgNIC        = 2
	wgDefaultMTU = 1420
	wgUpTimeout  = 15 * time.Second
)

// Tunnel is a live wireguard device bridged into the netstack.
type Tunnel struct {
	dev    *device.Device
	ep     *channel.Endpoint
	logf   func(string, ...any)
	cancel context.CancelFunc
	stop   sync.Once
	done   chan struct{}
}

// Attach builds the wireguard device and wires it into s as a second NIC.
//
// Standalone: no netstack address is assigned for the tunnel — the guest
// owns the tunnel Address= — and IP forwarding is enabled for each family
// the AllowedIPs cover, so guest traffic sourced from the tunnel address
// crosses statelessly and replies route back to the guest NIC.
//
// Switch: the tunnel Address= is assigned to the tunnel NIC, so netstack's
// own NAT flows source it, and return traffic demuxes back into those
// flows. Forwarding stays off.
//
// AllowedIPs always become routes into the tunnel NIC; addRoute carries
// them into the running stack's route table.
func Attach(s *stack.Stack, guestNIC tcpip.NICID, conf *Conf, mode Mode, addRoute func(tcpip.Route), logf func(string, ...any)) (*Tunnel, error) {
	mtu := conf.MTU
	if mtu <= 0 {
		mtu = wgDefaultMTU
	}
	ep := channel.New(512, uint32(mtu), "")
	if err := s.CreateNIC(wgNIC, ep); err != nil {
		return nil, fmt.Errorf("wireguard NIC: %s", err)
	}
	// No duplicate-address probing on the tunnel NIC either: the segment
	// behind it is a point-to-point tunnel.
	dadOff(s, wgNIC)

	switch mode {
	case ModeSwitch:
		for _, a := range conf.Addresses {
			if err := addAddress(s, wgNIC, a); err != nil {
				return nil, err
			}
		}
	case ModeStandalone:
		// Stateless transport: the guest owns the tunnel address and the
		// stack forwards, it does not terminate. Promiscuous mode (set for
		// the NAT path) would make gVisor acquire a temporary address for
		// every destination and answer flows locally — hijacking exactly
		// the traffic this mode must forward — so it goes off again. The
		// guest's v4 slirp NAT keeps working through the forwarder path on
		// the switch side; a standalone instance is tunnel-families only.
		s.SetPromiscuousMode(guestNIC, false)
		// Replies to the tunnel address must reach the guest, which owns
		// it — the stack forwards, it does not answer.
		for _, a := range conf.Addresses {
			addRoute(tcpip.Route{Destination: subnetOf(a), NIC: guestNIC})
		}
		if hasFamily(conf.AllowedIPs, 4) {
			s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
		}
		if hasFamily(conf.AllowedIPs, 6) {
			s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)
		}
	}
	for _, a := range conf.AllowedIPs {
		addRoute(tcpip.Route{Destination: subnetOf(a), NIC: wgNIC})
	}

	// Resolve (and log) the endpoint before handing it to the device. The
	// device's IpcSet parses literal IPs only — wg-quick resolves hostnames
	// the same way before configuring. A name that does not resolve yet is
	// not fatal: the tunnel still comes up when it later does, and the
	// handshake watcher reports the wait.
	resolved := conf.Endpoint
	if udpAddr, err := net.ResolveUDPAddr("udp", conf.Endpoint); err == nil {
		resolved = udpAddr.String()
		logf("wireguard: endpoint %s resolved to %s", conf.Endpoint, resolved)
	} else {
		logf("wireguard: endpoint %s did not resolve yet (%v)", conf.Endpoint, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	b := &bridge{ep: ep, mtu: mtu, ctx: ctx, events: make(chan tun.Event, 8), logf: logf}
	dev := device.NewDevice(b, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(deviceConfig(conf, resolved)); err != nil {
		dev.Close()
		cancel()
		return nil, fmt.Errorf("wireguard device: %s", err)
	}
	// Bring the device up. A kernel tun signals EventUp on "ip link set
	// up"; without it the device stays down forever — no bind, and
	// IpcSet skips peer.Start() because !isUp() — so traffic would
	// silently vanish with no handshake and no error.
	b.events <- tun.EventUp

	t := &Tunnel{dev: dev, ep: ep, logf: logf, cancel: cancel, done: make(chan struct{})}
	logf("wireguard: tunnel up (mode %s) conf %s endpoint %s (%s) mtu %d keepalive %ds allowed %v",
		modeName(mode), conf.Path, conf.Endpoint, resolved, mtu, conf.Keepalive, cidrStrings(conf.AllowedIPs))
	go t.watchHandshake(conf)
	return t, nil
}

// dadOff disables IPv6 duplicate address detection on a NIC — there is no
// other v6 speaker behind the tunnel to answer DAD probes.
func dadOff(s *stack.Stack, nic tcpip.NICID) {
	if ep6, _ := s.GetNetworkEndpoint(nic, ipv6.ProtocolNumber); ep6 != nil {
		if dad, ok := ep6.(interface{ SetDADConfigurations(stack.DADConfigurations) }); ok {
			dad.SetDADConfigurations(stack.DADConfigurations{DupAddrDetectTransmits: 0})
		}
	}
}

// deviceConfig renders the uapi config: hex keys, one peer. The string
// contains the private key and is never logged or stored. endpoint is a
// pre-resolved host:port — IpcSet parses literal addresses only.
func deviceConfig(conf *Conf, endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%x\n", conf.PrivateKey)
	fmt.Fprintf(&b, "public_key=%x\n", conf.PeerKey)
	if conf.PresharedKey != nil {
		fmt.Fprintf(&b, "preshared_key=%x\n", conf.PresharedKey)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	for _, a := range conf.AllowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", a.String())
	}
	if conf.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", conf.Keepalive)
	}
	return b.String()
}

// watchHandshake polls the device for the peer's first handshake and
// reports either outcome; a slow tunnel is logged, never a crash. Only
// handshake timestamps are read out of IpcGet — the reply also carries the
// private key and is discarded wholesale.
func (t *Tunnel) watchHandshake(conf *Conf) {
	defer t.stop.Do(func() { close(t.done) })
	deadline := time.Now().Add(wgUpTimeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	warned := false
	for {
		select {
		case <-t.done:
			return
		case <-ticker.C:
		}
		if hs, ok := handshakeTime(t.dev); ok && !hs.IsZero() {
			t.logf("wireguard: handshake with %s completed", conf.Endpoint)
			return
		}
		if !warned && time.Now().After(deadline) {
			warned = true
			t.logf("wireguard: no handshake from %s within %s — endpoint unreachable or keys/peer mismatch; tunnel keeps trying",
				conf.Endpoint, wgUpTimeout)
		}
	}
}

// handshakeTime extracts the peer's last-handshake timestamp from the
// device. The IpcGet reply contains secrets: parse two fields and drop the
// rest untouched.
func handshakeTime(dev *device.Device) (time.Time, bool) {
	out, err := dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	secs, nsecs := int64(0), int64(0)
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := cut(line, "last_handshake_time_sec="); ok {
			secs, _ = strconv.ParseInt(rest, 10, 64)
		} else if rest, ok := cut(line, "last_handshake_time_nsec="); ok {
			nsecs, _ = strconv.ParseInt(rest, 10, 64)
		}
	}
	if secs == 0 {
		return time.Time{}, false
	}
	return time.Unix(secs, nsecs), true
}

func cut(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return s, false
}

// Close tears the device and its netstack NIC down.
func (t *Tunnel) Close() {
	t.cancel()
	t.dev.Close()
	t.ep.Close()
}

// ── bridge: wireguard tun.Device over the netstack NIC ─────────────────

// bridge is the tun.Device the wireguard device talks to. Read hands it
// packets the stack routed to the tunnel NIC (to encrypt), Write injects
// decrypted packets back into the stack.
type bridge struct {
	ep     *channel.Endpoint
	mtu    int
	ctx    context.Context
	once   sync.Once
	events chan tun.Event
	logf   func(string, ...any)
	flowed sync.Once
}

func (b *bridge) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	pkt := b.ep.ReadContext(b.ctx)
	if pkt == nil {
		return 0, errors.New("wireguard link closed")
	}
	defer pkt.DecRef()
	view := pkt.ToView().AsSlice()
	if debugf != nil && len(view) >= 40 {
		debugf("wg out: %d bytes %s > %s",
			len(view), net.IP(view[8:24]), net.IP(view[24:40]))
	}
	buf := bufs[0][offset:]
	if len(view) > len(buf) {
		return 0, io.ErrShortBuffer
	}
	copy(buf, view)
	sizes[0] = len(view)
	return 1, nil
}

func (b *bridge) Write(bufs [][]byte, offset int) (int, error) {
	n := 0
	for _, buf := range bufs {
		p := buf[offset:]
		if len(p) == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch p[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			continue
		}
		if b.logf != nil {
			b.flowed.Do(func() { b.logf("wireguard: tunnel data flowing") })
		}
		if debugf != nil {
			debugf("wg in: %d bytes proto v%d", len(p), p[0]>>4)
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(p),
		})
		pkt.NetworkProtocolNumber = proto
		b.ep.InjectInbound(proto, pkt)
		n++
	}
	return n, nil
}

func (b *bridge) MTU() (int, error)        { return b.mtu, nil }
func (b *bridge) Name() (string, error)    { return "wg0", nil }
func (b *bridge) BatchSize() int           { return 1 }
func (b *bridge) File() *os.File           { return nil }
func (b *bridge) Events() <-chan tun.Event { return b.events }

func (b *bridge) Close() error {
	b.once.Do(func() { close(b.events) })
	b.ep.Close()
	return nil
}

// ── small helpers ──────────────────────────────────────────────────────

func addAddress(s *stack.Stack, nic tcpip.NICID, ipnet net.IPNet) error {
	proto, addr, err := protoAddr(ipnet)
	if err != nil {
		return err
	}
	if terr := s.AddProtocolAddress(nic, tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); terr != nil {
		return fmt.Errorf("AddProtocolAddress(%s): %s", ipnet.String(), terr)
	}
	return nil
}

func protoAddr(ipnet net.IPNet) (tcpip.NetworkProtocolNumber, tcpip.Address, error) {
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		return ipv4.ProtocolNumber, tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), nil
	}
	ip16 := ipnet.IP.To16()
	if ip16 == nil {
		return 0, tcpip.Address{}, fmt.Errorf("%s: not an IP", ipnet.String())
	}
	return ipv6.ProtocolNumber, tcpip.AddrFrom16(as16(ipnet.IP)), nil
}

func subnetOf(ipnet net.IPNet) tcpip.Subnet {
	bits, _ := ipnet.Mask.Size()
	if ip4 := ipnet.IP.To4(); ip4 != nil {
		return tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}),
			PrefixLen: bits,
		}.Subnet()
	}
	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom16(as16(ipnet.IP)),
		PrefixLen: bits,
	}.Subnet()
}

// Subnet converts an AllowedIPs entry for callers outside the package.
func Subnet(ipnet net.IPNet) tcpip.Subnet { return subnetOf(ipnet) }

func hasFamily(cidrs []net.IPNet, family byte) bool {
	for _, c := range cidrs {
		if (c.IP.To4() != nil) == (family == 4) {
			return true
		}
	}
	return false
}

func cidrStrings(cidrs []net.IPNet) []string {
	out := make([]string, len(cidrs))
	for i, c := range cidrs {
		out[i] = c.String()
	}
	return out
}

func modeName(m Mode) string {
	if m == ModeSwitch {
		return "switch"
	}
	return "standalone"
}

func as16(ip net.IP) [16]byte {
	var out [16]byte
	copy(out[:], ip.To16())
	return out
}
