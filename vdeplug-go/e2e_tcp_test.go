// The DIRECT-mode e2e: the uml-nt kernel's wire (D8 — framed TCP
// localhost, the kernel dials, the helper listens) driven by a fake
// guest built on the SAME production bridge (link.EtherEndpoint +
// gVisor netstack) the helper uses. Covers: framing both directions,
// the frame-layer DHCP server (DISCOVER → OFFER with the right lease),
// and the NAT44 path (guest TCP to the gateway address → host loopback
// → an HTTP server) with real TCP end to end.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"uml-kernel-build/vdeplug-go/internal/link"
	"uml-kernel-build/vdeplug-go/internal/transport"
)

const (
	guestIPv4 = "10.0.2.15"
	gwIPv4    = "10.0.2.2"
)

// freePort reserves an ephemeral port, then releases it for the helper
// to bind (a tiny race, standard practice for test helpers).
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// directHelper spawns a helper in direct mode (tcplisten://) with the
// slirp uplink and returns nothing — failures surface in its stderr.
func directHelper(t *testing.T, dir, descr string, port int) {
	t.Helper()
	bin := filepath.Join(dir, "vdeplug-go")
	if _, err := os.Stat(bin); err != nil {
		src, err := os.ReadFile(binSrc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, src, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("uplink: slirp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	cmd := exec.Command(bin, "--descr", descr,
		fmt.Sprintf("tcplisten://127.0.0.1:%d", port), "slirp://")
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("helper %s logs:\n%s", descr, logs.String())
		}
	})
}

// fakeGuest is the kernel side of the direct wire: the production
// link.EtherEndpoint bridging a gVisor netstack over the framed TCP
// connection, plus a raw-frame tap for DHCP (which bypasses the stack,
// like a real guest's raw-socket DHCP client).
type fakeGuest struct {
	wire   transport.Conn
	stack  *stack.Stack
	frames chan []byte
	closed chan struct{}
	mac    [6]byte
}

func startFakeGuest(t *testing.T, helperPort int, mac [6]byte) *fakeGuest {
	t.Helper()

	// Dial the helper (the kernel's role in D8).
	var conn net.Conn
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp",
			fmt.Sprintf("127.0.0.1:%d", helperPort), time.Second)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kernel dial: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	wire := transport.NewConnFromNet(conn)

	// The production bridge, test side: netstack NIC over the wire.
	ep := link.New(wire, 1500, tcpip.LinkAddress(mac[:]))
	ep.SetSink(func(frame []byte) { wire.SendFrame(frame) })
	go func() { _ = ep.Start() }()

	g := &fakeGuest{
		wire:   wire,
		frames: make(chan []byte, 128),
		closed: make(chan struct{}),
		mac:    mac,
	}

	// Wire reader: every frame both feeds the stack (netstack sheds
	// what it cannot route — broadcast DHCP included) and lands in
	// the assertions channel (copies — the buffer is reused).
	go func() {
		buf := make([]byte, link.FrameMax)
		for {
			n, err := wire.RecvFrame(buf)
			if err != nil {
				close(g.closed)
				return
			}
			frame := make([]byte, n)
			copy(frame, buf[:n])
			ep.Inject(frame)
			select {
			case g.frames <- frame:
			default:
			}
		}
	}()

	// The guest's netstack: static 10.0.2.15/24, gateway on-link.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{arp.NewProtocol, ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("guest CreateNIC: %s", err)
	}
	ip4 := tcpip.AddrFrom4([4]byte{10, 0, 2, 15})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: ip4.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("guest addr: %s", err)
	}
	// Connected route for 10.0.2.0/24 (WithPrefix() would be a /32 —
	// the NAT's own trick for its addresses, not for routes).
	_, sub4, err := net.ParseCIDR("10.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ipnet := sub4.IP.To4()
	subnet, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{ipnet[0], ipnet[1], ipnet[2], ipnet[3]}),
		tcpip.MaskFromBytes(sub4.Mask),
	)
	s.SetRouteTable([]tcpip.Route{{
		Destination: subnet, NIC: 1,
	}})
	g.stack = s
	return g
}

// newHTTPServer serves body on host loopback (the NAT's literal dial
// target when the guest connects to the gateway address).
func newHTTPServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// recvFrame waits for a frame passing the predicate (copies returned).
func (g *fakeGuest) recvFrame(t *testing.T, what string, timeout time.Duration,
	want func(frame []byte) bool) []byte {
	t.Helper()
	d := time.After(timeout)
	for {
		select {
		case frame := <-g.frames:
			if want(frame) {
				return frame
			}
			continue
		case <-g.closed:
			t.Fatalf("guest link died waiting for %s", what)
		case <-d:
			t.Fatalf("no %s within %v", what, timeout)
		}
	}
}

// dhcpDiscover builds a full Ethernet broadcast DISCOVER (raw path, as
// a guest DHCP client would).
func (g *fakeGuest) dhcpDiscover(t *testing.T, xid []byte) {
	t.Helper()
	req, err := dhcpv4.New(
		dhcpv4.WithMessageType(dhcpv4.MessageTypeDiscover),
		dhcpv4.WithTransactionID(dhcpv4.TransactionID(xid)),
		dhcpv4.WithHwAddr(net.HardwareAddr(g.mac[:])),
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := req.ToBytes()

	f := make([]byte, 14+20+8+len(payload))
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], g.mac[:])
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := header.IPv4(f[14:])
	ip.Encode(&header.IPv4Fields{
		SrcAddr:     tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		DstAddr:     tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		TotalLength: uint16(20 + 8 + len(payload)),
	})
	udp := header.UDP(f[34:])
	udp.Encode(&header.UDPFields{
		SrcPort: 68, DstPort: 67, Length: uint16(8 + len(payload)),
	})
	copy(udp.Payload(), payload)

	if err := g.wire.SendFrame(f); err != nil {
		t.Fatalf("DHCP DISCOVER send: %v", err)
	}
}

// httpGet dials dst (the gateway = host loopback through the NAT) with
// real TCP and fetches path, returning the body.
func (g *fakeGuest) httpGet(t *testing.T, port uint16, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	addr := tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
		Port: port,
	}
	c, err := gonet.DialContextTCP(ctx, g.stack, addr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("guest TCP dial 10.0.2.2:%d: %s", port, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: gw\r\n\r\n", path)
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("guest HTTP write: %v", err)
	}
	var body bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return body.String()
}

// isDHCPPayload matches frames carrying a DHCP reply for our xid.
func isDHCPPayload(xid []byte) func([]byte) bool {
	return func(frame []byte) bool {
		if len(frame) < 14+20+8+4 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
			return false
		}
		ip := header.IPv4(frame[14:])
		if ip.Protocol() != uint8(header.UDPProtocolNumber) {
			return false
		}
		udp := header.UDP(ip.Payload())
		if udp.SourcePort() != 67 || udp.DestinationPort() != 68 {
			return false
		}
		return bytes.Contains(udp.Payload(), xid)
	}
}

// dhcpPayloadOf extracts the DHCP bytes from a reply frame.
func dhcpPayloadOf(frame []byte) []byte {
	ip := header.IPv4(frame[14:])
	udp := header.UDP(ip.Payload())
	return udp.Payload()
}

// TestDirectTCPDHCPLease: the framed TCP wire carries DHCP end to end
// and the frame-layer server hands out the first pool address.
func TestDirectTCPDHCPLease(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	directHelper(t, dir, "dhcp", port)

	mac := [6]byte{0x02, 0xaa, 0x00, 0x00, 0x00, 0x2a}
	g := startFakeGuest(t, port, mac)

	xid := []byte{0xde, 0xad, 0xbe, 0xef}
	g.dhcpDiscover(t, xid)
	frame := g.recvFrame(t, "DHCP OFFER", 10*time.Second, isDHCPPayload(xid))

	m, err := dhcpv4.FromBytes(dhcpPayloadOf(frame))
	if err != nil {
		t.Fatalf("reply parse: %v", err)
	}
	if m.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("want OFFER, got %s", m.MessageType())
	}
	if got := m.YourIPAddr.String(); got != guestIPv4 {
		t.Fatalf("lease %s, want %s", got, guestIPv4)
	}
}

// TestDirectTCPNATHTTP: the full chain the uml-nt kernel will run —
// guest TCP to the gateway address, NAT44 out to host loopback, a real
// HTTP round-trip.
func TestDirectTCPNATHTTP(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	directHelper(t, dir, "nat", port)

	srv := newHTTPServer(t, "uml-nt-net-ok")
	defer srv.Close()
	srvURL, err := net.ResolveTCPAddr("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	mac := [6]byte{0x02, 0xaa, 0x00, 0x00, 0x00, 0x3b}
	g := startFakeGuest(t, port, mac)

	body := g.httpGet(t, uint16(srvURL.Port), "/netok")
	if !bytes.Contains([]byte(body), []byte("uml-nt-net-ok")) {
		t.Fatalf("HTTP through the NAT got: %q", body)
	}
}
