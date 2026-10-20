package dhcp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// macFor mints distinct client MACs so pool tests never collide.
func macFor(n byte) net.HardwareAddr {
	return net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, n}
}

// A pool whose run of addresses crosses the last-octet ceiling must keep
// counting into the next octet instead of wrapping back to x.x.x.0 — the
// wrap hands out addresses that belong to other leases or to the subnet
// itself.
func TestPoolCountsAcrossOctetBoundary(t *testing.T) {
	p := NewPool(net.ParseIP("10.0.2.250"), 10)
	got := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		ip, err := p.GetOrAssign(macFor(byte(i)))
		if err != nil {
			t.Fatalf("lease %d: %v", i, err)
		}
		got = append(got, ip.String())
	}
	want := []string{
		"10.0.2.250", "10.0.2.251", "10.0.2.252", "10.0.2.253",
		"10.0.2.254", "10.0.2.255", "10.0.3.0", "10.0.3.1",
		"10.0.3.2", "10.0.3.3",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("lease %d = %s, want %s (full run %v)", i, got[i], want[i], got)
		}
	}
}

// A pool seeded from a gossiped lease table must still recognize leases
// that live beyond the first octet — the restore walk computes candidate
// addresses the same way assignment does.
func TestRestoreFindsLeasesBeyondFirstOctet(t *testing.T) {
	p := NewPool(net.ParseIP("10.0.2.0"), 300)
	p.Restore(map[[6]byte][4]byte{
		{0x52, 0x54, 0x00, 0x00, 0x00, 0x01}: {10, 0, 2, 5},
		{0x52, 0x54, 0x00, 0x00, 0x00, 0x02}: {10, 0, 3, 0},
	})
	leases := p.Leases()
	if len(leases) != 2 {
		t.Fatalf("restored %d leases, want 2: %v", len(leases), leases)
	}
	if first := p.First(); first == nil || first.String() != "10.0.2.5" {
		t.Fatalf("First() = %v, want 10.0.2.5 (lowest restored)", first)
	}
	// The next fresh lease continues after the two restored ones (the
	// pool counts restored entries, then keeps handing out from there).
	ip, err := p.GetOrAssign(macFor(9))
	if err != nil {
		t.Fatalf("lease after restore: %v", err)
	}
	if ip.String() != "10.0.2.2" {
		t.Fatalf("lease after restore = %s, want 10.0.2.2", ip)
	}
}

func TestPoolExhaustsAtConfiguredSize(t *testing.T) {
	p := NewPool(net.ParseIP("10.0.2.100"), 3)
	for i := 0; i < 3; i++ {
		if _, err := p.GetOrAssign(macFor(byte(i))); err != nil {
			t.Fatalf("lease %d: %v", i, err)
		}
	}
	if _, err := p.GetOrAssign(macFor(99)); err == nil {
		t.Fatal("pool accepted a lease past its size")
	}
}

func TestUsableLeases(t *testing.T) {
	cases := []struct {
		network string
		start   net.IP
		max     int
		want    int
	}{
		// Ordinary /24 seeded mid-range: everything up to .254.
		{"10.0.2.0/24", net.ParseIP("10.0.2.15"), 256, 240},
		// A smaller cap wins over the subnet bound.
		{"10.0.2.0/24", net.ParseIP("10.0.2.100"), 8, 8},
		// The broadcast address itself is never leasable.
		{"10.0.2.0/24", net.ParseIP("10.0.2.255"), 256, 0},
		// One step below it leaves exactly one address.
		{"10.0.2.0/24", net.ParseIP("10.0.2.254"), 256, 1},
		// Outside the subnet: no pool at all.
		{"10.0.2.0/24", net.ParseIP("10.0.3.1"), 256, 0},
		// Tiny subnet: only .2 is usable, .3 is broadcast.
		{"10.0.0.0/30", net.ParseIP("10.0.0.2"), 256, 1},
		// No start, or no parseable network: disable.
		{"10.0.2.0/24", nil, 256, 0},
		{"", net.ParseIP("10.0.2.15"), 256, 0},
		{"nonsense/99", net.ParseIP("10.0.2.15"), 256, 0},
	}
	for _, c := range cases {
		got := UsableLeases(c.network, c.start, c.max)
		if got != c.want {
			t.Errorf("UsableLeases(%q, %v, %d) = %d, want %d", c.network, c.start, c.max, got, c.want)
		}
	}
}

// testServer wires a small server against the classic 10.0.2.0/24 setup.
func testServer(t *testing.T) *Server {
	t.Helper()
	pool := NewPool(net.ParseIP("10.0.2.15"), 20)
	srvMAC, _ := net.ParseMAC("52:54:00:00:00:01")
	return New(Options{
		Network:    "10.0.2.0/24",
		GatewayIP:  "10.0.2.2",
		Nameserver: "10.0.2.3",
	}, pool, tcpip.LinkAddress(srvMAC))
}

func discover(t *testing.T, clientMAC [6]byte, broadcast bool) []byte {
	t.Helper()
	req, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}
	req.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeDiscover))
	req.ClientHWAddr = net.HardwareAddr(clientMAC[:])
	if broadcast {
		req.SetBroadcast()
	} else {
		req.SetUnicast()
	}
	return req.ToBytes()
}

// RFC 2131 §4.1: a client that did not set the BROADCAST flag gets its
// reply unicast to its hardware address at the offered address — the
// reply must not go out as an all-ones broadcast.
func TestReplyUnicastWhenClientOmitsBroadcastFlag(t *testing.T) {
	srv := testServer(t)
	clientMAC := [6]byte{0x52, 0x54, 0x00, 0xaa, 0x00, 0x07}

	frame := srv.HandlePacket(discover(t, clientMAC, false), clientMAC)
	if frame == nil {
		t.Fatal("no reply to DISCOVER")
	}
	eth := header.Ethernet(frame)
	if got := eth.DestinationAddress().String(); got != "52:54:00:aa:00:07" {
		t.Fatalf("reply L2 destination = %s, want the client MAC", got)
	}
	ipH := header.IPv4(frame[header.EthernetMinimumSize:])
	if got := ipH.DestinationAddress().String(); got != "10.0.2.15" {
		t.Fatalf("reply IP destination = %s, want the offered 10.0.2.15", got)
	}
	udp := header.UDP(ipH.Payload())
	if got := udp.DestinationPort(); got != 68 {
		t.Fatalf("reply UDP destination port = %d, want 68", got)
	}
	payload, err := dhcpv4.FromBytes(udp.Payload())
	if err != nil {
		t.Fatalf("reply payload does not parse: %v", err)
	}
	if payload.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("reply type = %s, want OFFER", payload.MessageType())
	}
	if got := payload.YourIPAddr.String(); got != "10.0.2.15" {
		t.Fatalf("reply yiaddr = %s, want 10.0.2.15", got)
	}
}

// The mirror case: a client that set the BROADCAST flag keeps getting
// the broadcast reply.
func TestReplyBroadcastWhenClientSetsBroadcastFlag(t *testing.T) {
	srv := testServer(t)
	clientMAC := [6]byte{0x52, 0x54, 0x00, 0xaa, 0x00, 0x08}

	frame := srv.HandlePacket(discover(t, clientMAC, true), clientMAC)
	if frame == nil {
		t.Fatal("no reply to DISCOVER")
	}
	eth := header.Ethernet(frame)
	if got := eth.DestinationAddress().String(); got != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("reply L2 destination = %s, want broadcast", got)
	}
	ipH := header.IPv4(frame[header.EthernetMinimumSize:])
	if got := ipH.DestinationAddress().String(); got != "255.255.255.255" {
		t.Fatalf("reply IP destination = %s, want 255.255.255.255", got)
	}
}
