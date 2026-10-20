// Package nat wires gVisor netstack as the userspace NAT for one UML guest,
// replacing libslirp:
//
//   - TCP: per-connection Forwarder with a goroutine pair pumping 64 KiB
//     buffers to/from the host socket (the aggregation libslirp lacks).
//   - UDP: per-flow forwarders; DNS is relayed to the host resolver.
//   - ICMP echo to the gateway is answered by netstack itself.
//
// Address mapping matches libslirp: the gateway address (10.0.2.2) maps to
// host loopback, the nameserver address (10.0.2.3) is a DNS proxy.
package nat

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"uml-kernel-build/vdeplug-go/internal/link"
)

const (
	nicID       = 1
	copyBufSize = 64 * 1024
	udpIdle     = 30 * time.Second
)

// debugf logs NAT internals when VDE_DEBUG is set.
func (n *NAT) debugf(f string, a ...any) {
	if os.Getenv("VDE_DEBUG") != "" {
		log.Printf("[vde_plug-go] nat: "+f, a...)
	}
}

// Options for building the NAT stack.
type Options struct {
	GatewayIP  string // 10.0.2.2
	Nameserver string // 10.0.2.3
	Network    string // 10.0.2.0/24
	IPv6       bool
	MTU        int
}

// NAT owns the netstack instance and its host-side plumbing.
type NAT struct {
	Stack *stack.Stack
	EP    *link.EtherEndpoint

	resolvers  []string
	localAddrs map[string]bool // our addresses on the segment (v4+v6)
	dnsAddrs   map[string]bool // addresses serving DNS proxy
	wg         sync.WaitGroup

	// TunnelSubnets, when set (switch-mode wireguard), sends forwarder
	// flows for matching destinations through this stack instead of host
	// sockets — they leave the tunnel NIC sourced from the tunnel address.
	tunnelMu      sync.Mutex
	TunnelSubnets []tcpip.Subnet
}

// NIC is the guest-facing NIC id.
func (n *NAT) NIC() tcpip.NICID { return nicID }

// AddRoute appends one route to the running stack's table.
func (n *NAT) AddRoute(r tcpip.Route) {
	n.Stack.SetRouteTable(append(n.Stack.GetRouteTable(), r))
}

// SetTunnelSubnets installs the destinations the wireguard tunnel covers.
func (n *NAT) SetTunnelSubnets(subs []tcpip.Subnet) {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()
	n.TunnelSubnets = subs
}

// dialsTunnel reports whether a destination leaves through the tunnel
// rather than a host socket.
func (n *NAT) dialsTunnel(dst tcpip.Address) bool {
	n.tunnelMu.Lock()
	defer n.tunnelMu.Unlock()
	for _, s := range n.TunnelSubnets {
		if s.Contains(dst) {
			return true
		}
	}
	return false
}

// New builds the netstack stack and attaches ep as the Ethernet device.
func New(ep *link.EtherEndpoint, opts Options) (*NAT, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
	})

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("CreateNIC: %s", err)
	}
	// Duplicate address detection off: this segment has no other v6
	// speaker to answer DAD probes, so addresses would sit TENTATIVE
	// forever and the gateway would stay deaf to Neighbor Solicitations.
	if ep6, _ := s.GetNetworkEndpoint(nicID, ipv6.ProtocolNumber); ep6 != nil {
		if dad, ok := ep6.(interface{ SetDADConfigurations(stack.DADConfigurations) }); ok {
			dad.SetDADConfigurations(stack.DADConfigurations{DupAddrDetectTransmits: 0})
		}
	}
	// The guest's frames carry its own MAC and 10.0.2.15 source; without
	// these the stack treats them as spoofed/foreign and sheds them.
	s.SetSpoofing(nicID, true)
	s.SetPromiscuousMode(nicID, true)

	n := &NAT{
		Stack:      s,
		EP:         ep,
		resolvers:  resolvers(),
		localAddrs: map[string]bool{},
		dnsAddrs:   map[string]bool{},
	}

	// The gateway address answers ARP/ICMP/TCP on the segment. The DNS
	// address is a second local address so 10.0.2.3:53 reaches us too.
	for _, addr := range []string{opts.GatewayIP, opts.Nameserver} {
		ip4 := net.ParseIP(addr).To4()
		if ip4 == nil {
			// A malformed gateway/nameserver in config.yaml must fail with
			// a readable message, not a nil-index panic deep in setup.
			return nil, fmt.Errorf("nat: %q is not a valid IPv4 address", addr)
		}
		a4 := tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: a4.WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("AddProtocolAddress(%s): %s", addr, err)
		}
		n.localAddrs[addr] = true
		if addr == opts.Nameserver {
			n.dnsAddrs[addr] = true
		}
	}

	// Connected route for the guest subnet. A default route via our own
	// address would hairpin.
	sub, err := subnetOf(opts.Network)
	if err != nil {
		return nil, err
	}
	routes := []tcpip.Route{{Destination: sub, NIC: nicID}}

	// IPv6 mirrors libslirp's in6_enabled layout: site-local fec0::/64
	// with the gateway at ::2 and DNS at ::3 (guests typically configure
	// fec0::15 statically, like the shipped image does).
	if opts.IPv6 {
		for _, a := range []string{"fec0::2", "fec0::3"} {
			if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
				Protocol:          ipv6.ProtocolNumber,
				AddressWithPrefix: tcpip.AddrFrom16(as16(net.ParseIP(a))).WithPrefix(),
			}, stack.AddressProperties{}); err != nil {
				return nil, fmt.Errorf("AddProtocolAddress(%s): %s", a, err)
			}
			n.localAddrs[a] = true
			if a == "fec0::3" {
				n.dnsAddrs[a] = true
			}
		}
		routes = append(routes, tcpip.Route{
			// fec0::/64, the whole guest link — WithPrefix() alone would
			// make this a point subnet (/128) and strand every other
			// guest address.
			Destination: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom16(as16(net.ParseIP("fec0::"))),
				PrefixLen: 64,
			}.Subnet(),
			NIC: nicID,
		})
	}
	s.SetRouteTable(routes)

	tcpFwd := tcp.NewForwarder(s, 0, 1024, n.tcpHandler)
	s.SetTransportProtocolHandler(header.TCPProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		return n.udpHandler(r)
	})
	s.SetTransportProtocolHandler(header.UDPProtocolNumber, udpFwd.HandlePacket)

	return n, nil
}

func subnetOf(cidr string) (tcpip.Subnet, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return tcpip.Subnet{}, fmt.Errorf("network %q: %w", cidr, err)
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return tcpip.Subnet{}, fmt.Errorf("network %q: not IPv4", cidr)
	}
	mask := ipnet.Mask
	return tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}),
		tcpip.MaskFromBytes(append([]byte(nil), mask...)),
	)
}

// as16 converts a 16-byte net.IP into the array form netstack wants.
func as16(ip net.IP) [16]byte {
	var out [16]byte
	copy(out[:], ip.To16())
	return out
}

// ── TCP ────────────────────────────────────────────────────────────────

func (n *NAT) tcpHandler(r *tcp.ForwarderRequest) {
	id := r.ID()
	n.debugf("tcp fwd: dst=%s:%d", id.LocalAddress, id.LocalPort)
	// The guest's destination is the LOCAL side of the 4-tuple: one of our
	// own addresses (gateway/DNS) maps to host loopback, tunnel-covered
	// destinations dial back through this stack (switch-mode wireguard
	// egress — the flow leaves with the tunnel address as source), and
	// everything else is dialed literally on the host.
	dst := id.LocalAddress.String()
	var hostConn net.Conn
	var err error
	switch {
	case n.localAddrs[dst]:
		dst = "127.0.0.1"
		hostConn, err = net.Dial("tcp", net.JoinHostPort(dst, strconv.Itoa(int(id.LocalPort))))
	case n.dialsTunnel(id.LocalAddress):
		proto := ipv4.ProtocolNumber
		if id.LocalAddress.Len() == 16 {
			proto = ipv6.ProtocolNumber
		}
		n.debugf("tunnel dial %s:%d", id.LocalAddress, id.LocalPort)
		hostConn, err = gonet.DialTCP(n.Stack, tcpip.FullAddress{
			Addr: id.LocalAddress,
			Port: id.LocalPort,
		}, proto)
		if err != nil {
			n.debugf("tunnel dial failed: %s", err)
		}
	default:
		hostConn, err = net.Dial("tcp", net.JoinHostPort(dst, strconv.Itoa(int(id.LocalPort))))
	}
	if err != nil {
		r.Complete(true) // RST: connection-refused semantics
		return
	}

	go func() {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			hostConn.Close()
			return
		}
		guest := gonet.NewTCPConn(&wq, ep)
		done := func() { guest.Close(); hostConn.Close() }
		go pump(hostConn, guest, done)
		pump(guest, hostConn, done)
	}()
}

func pump(dst io.Writer, src io.Reader, done func()) {
	buf := make([]byte, copyBufSize)
	io.CopyBuffer(dst, src, buf)
	done()
}

// ── UDP ────────────────────────────────────────────────────────────────

// udpHandler forwards one guest UDP flow to the host. DNS traffic to the
// nameserver address goes to the host resolver; flows to the gateway go to
// host loopback; everything else is dialed literally.
func (n *NAT) udpHandler(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dstIP := id.LocalAddress.String()
	dstPort := id.LocalPort
	if os.Getenv("VDE_DEBUG") != "" {
		log.Printf("[vde_plug-go] udpfwd: dst=%s:%d src=%s:%d", dstIP, dstPort, id.RemoteAddress, id.RemotePort)
	}

	go func() {
		host := n.dialUDP(dstIP, dstPort)
		if host == nil {
			return // let netstack send port-unreachable
		}
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			host.Close()
			return
		}
		guest := gonet.NewUDPConn(&wq, ep)
		n.relayUDP(guest, host)
	}()
	return true
}

func (n *NAT) dialUDP(dstIP string, dstPort uint16) net.Conn {
	if dstPort == 53 && n.dnsAddrs[dstIP] {
		for _, server := range n.resolvers {
			c, err := net.Dial("udp", net.JoinHostPort(server, "53"))
			if err == nil {
				return c
			}
		}
		return nil
	}
	if n.localAddrs[dstIP] {
		dstIP = "127.0.0.1"
	}
	// Tunnel-covered destinations dial through this stack: the flow leaves
	// the tunnel NIC with the tunnel address as source (switch-mode wg).
	dst := tcpip.AddrFrom16(as16(net.ParseIP(dstIP)))
	if t4 := dst.To4(); t4.Len() == 4 {
		dst = t4
	}
	if n.dialsTunnel(dst) {
		var laddr *tcpip.FullAddress
		var proto tcpip.NetworkProtocolNumber = ipv6.ProtocolNumber
		if dst.Len() == 4 {
			proto = ipv4.ProtocolNumber
		}
		c, err := gonet.DialUDP(n.Stack, laddr, &tcpip.FullAddress{Addr: dst, Port: dstPort}, proto)
		if err != nil {
			return nil
		}
		return c
	}
	c, err := net.Dial("udp", net.JoinHostPort(dstIP, strconv.Itoa(int(dstPort))))
	if err != nil {
		return nil
	}
	return c
}

// relayUDP copies guest datagrams to the host socket and replies back.
// One request/response per flow iteration; idle flows die after udpIdle.
func (n *NAT) relayUDP(guest *gonet.UDPConn, host net.Conn) {
	defer guest.Close()
	defer host.Close()
	buf := make([]byte, 65536)
	for {
		guest.SetReadDeadline(time.Now().Add(udpIdle))
		nread, _, err := guest.ReadFrom(buf)
		if err != nil {
			return
		}
		host.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := host.Write(buf[:nread]); err != nil {
			return
		}
		host.SetReadDeadline(time.Now().Add(5 * time.Second))
		nwrote, err := host.Read(buf)
		if err != nil {
			return
		}
		guest.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := guest.WriteTo(buf[:nwrote], nil); err != nil {
			return
		}
	}
}

// resolvers reads the host's /etc/resolv.conf nameservers.
func resolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// Close releases netstack resources on shutdown.
func (n *NAT) Close() {
	n.Stack.Close()
}
