package dhcp

import (
	"net"
	"testing"
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
