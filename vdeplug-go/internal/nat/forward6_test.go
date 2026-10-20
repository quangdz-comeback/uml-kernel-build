package nat

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"uml-kernel-build/vdeplug-go/internal/link"
)

func addr6(s string) tcpip.Address {
	return tcpip.AddrFrom16(as16(net.ParseIP(s)))
}

// forward6 harness helpers: build guest frames by hand and watch whether the
// netstack answers (any outbound v4/v6 TCP reply means the TCP forwarder saw
// the packet; silence means the network layer shed it before delivery).

const (
	guestMAC = tcpip.LinkAddress("\x02\x65\x22\x72\xf7\x7c")
	gwMAC    = tcpip.LinkAddress("\x7a\x72\x6d\x3c\xd7\x23")
)

func ethFrame(t *testing.T, proto tcpip.NetworkProtocolNumber, ip []byte) []byte {
	t.Helper()
	frame := make([]byte, header.EthernetMinimumSize+len(ip))
	h := header.Ethernet(frame)
	h.Encode(&header.EthernetFields{
		SrcAddr: guestMAC,
		DstAddr: gwMAC,
		Type:    proto,
	})
	copy(frame[header.EthernetMinimumSize:], ip)
	return frame
}

func ipv6Packet(t *testing.T, src, dst tcpip.Address, l4 []byte) []byte {
	t.Helper()
	ip := make([]byte, header.IPv6MinimumSize+len(l4))
	header.IPv6(ip).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(len(l4)),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	copy(ip[header.IPv6MinimumSize:], l4)
	return ip
}

func synSegment(t *testing.T, src, dst tcpip.Address, srcPort, dstPort uint16) []byte {
	t.Helper()
	seg := make([]byte, header.TCPMinimumSize+4)
	tcp := header.TCP(seg)
	tcp.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1,
		AckNum:     0,
		DataOffset: header.TCPMinimumSize + 4,
		Flags:      header.TCPFlagSyn,
		WindowSize: 0x2000,
	})
	// MSS option so the segment is a realistic 94-byte SYN.
	seg[header.TCPMinimumSize] = 2 // kind=MSS
	seg[header.TCPMinimumSize+1] = 4
	binary.BigEndian.PutUint16(seg[header.TCPMinimumSize+2:], 1440)
	tcp.SetChecksum(0)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(len(seg)))
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	return seg
}

func waitReply(t *testing.T, frames chan []byte, timeout time.Duration) (frame []byte, ok bool) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f := <-frames:
			return f, true
		case <-deadline:
			return nil, false
		}
	}
}

// dumpNonzeroStats prints every nonzero counter under a *tcpip.Stats tree.
func dumpNonzeroStats(t *testing.T, prefix string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			dumpNonzeroStats(t, prefix+"."+name, v.Field(i))
		}
	case reflect.Ptr:
		dumpNonzeroStats(t, prefix, v.Elem())
	default:
		switch v.Kind() {
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if n := v.Uint(); n != 0 {
				t.Logf("stats %s = %d", prefix, n)
			}
		}
	}
}

func TestForwarderSeesGuestV6SYN(t *testing.T) {
	ep := link.New(-1, 1500, gwMAC)
	frames := make(chan []byte, 64)
	ep.SetSink(func(f []byte) { frames <- f })
	go func() { _ = ep.Start() }()

	n, err := New(ep, Options{
		GatewayIP:  "10.0.2.2",
		Nameserver: "10.0.2.3",
		Network:    "10.0.2.0/24",
		IPv6:       true,
		MTU:        1500,
	})
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	defer n.Close()

	src := addr6("fec0::15")
	dst := addr6("2606:4700:4700::1111")
	frame := ethFrame(t, 0x86DD, ipv6Packet(t, src, dst, synSegment(t, src, dst, 40000, 443)))
	ep.Inject(frame)

	f, ok := waitReply(t, frames, 2*time.Second)
	if !ok {
		t.Log("no outbound TCP reply within 2s — forwarder never saw the SYN")
		dumpNonzeroStats(t, "stack", reflect.ValueOf(n.Stack.Stats()))
		t.Fatal("v6 SYN was shed before the TCP forwarder")
	}
	eth := header.Ethernet(f)
	t.Logf("got reply frame: type=%04x len=%d", binary.BigEndian.Uint16(eth[12:14]), len(f))
}
