package portfwd

import (
	"fmt"
	"net"
	"testing"

	"uml-kernel-build/vdeplug-go/internal/config"
)

// freePort returns a loopback port that is currently unused. The probe
// socket is closed before the port is handed out.
func freePort(t *testing.T, network string) int {
	t.Helper()
	var addr net.Addr
	switch network {
	case "udp":
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		addr = c.LocalAddr()
	default:
		ln, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		addr = ln.Addr()
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	}
	t.Fatalf("probe on %s yielded no port", network)
	return 0
}

// A rule that fails must not leave the rules before it listening: the
// caller believes Start failed entirely.
func TestStartClosesEarlierListenersWhenLaterRuleFails(t *testing.T) {
	port := freePort(t, "tcp")
	cfg := &config.Config{Ports: []string{
		fmt.Sprintf("127.0.0.1:%d:22", port), // opens fine
		fmt.Sprintf("127.0.0.1:%d:23", port), // same TCP port: fails
	}}
	if _, err := Start(nil, cfg, net.ParseIP("10.0.2.15")); err == nil {
		t.Fatal("conflicting second rule must fail Start")
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("first rule's listener still open after failed Start: %v", err)
	}
	ln.Close()
}

// A fallback rule with no usable fallback must fail Start outright —
// the old behavior spawned a relay that panicked on its first byte.
func TestStartRejectsMissingFallback(t *testing.T) {
	cfg := &config.Config{Ports: []string{"12345:22"}} // follows the fallback
	if _, err := Start(nil, cfg, nil); err == nil {
		t.Fatal("nil fallback must fail the rule, not start a forward")
	}
}

// UDP relays must bind inside Start: a taken port has to surface as an
// error, not as a silently dead goroutine.
func TestStartBindsUDPImmediately(t *testing.T) {
	taken, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", freePort(t, "udp")))
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	port := taken.LocalAddr().(*net.UDPAddr).Port
	cfg := &config.Config{Ports: []string{
		fmt.Sprintf("udp 127.0.0.1:%d:53", port),
	}}
	if _, err := Start(nil, cfg, net.ParseIP("10.0.2.15")); err == nil {
		t.Fatal("UDP port clash must surface from Start")
	}
}
