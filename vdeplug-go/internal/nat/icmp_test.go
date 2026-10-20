package nat

import (
	"encoding/binary"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// echoFrame builds an Ethernet+IPv4+ICMP echo request the way a guest's
// kernel would put it on the wire.
func echoFrame(srcMAC [6]byte, srcIP, dstIP [4]byte, id, seq uint16, payload []byte) []byte {
	icmpLen := header.ICMPv4MinimumSize + len(payload)
	ipLen := header.IPv4MinimumSize + icmpLen
	frame := make([]byte, header.EthernetMinimumSize+ipLen)

	icmp := frame[header.EthernetMinimumSize+header.IPv4MinimumSize:]
	icmp[0] = uint8(header.ICMPv4Echo)
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[header.ICMPv4MinimumSize:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(icmp))

	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(srcIP),
		DstAddr:     tcpip.AddrFrom4(dstIP),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(srcMAC[:]),
		DstAddr: header.EthernetBroadcastAddress,
		Type:    0x0800,
	})
	return frame
}

func parseICMPFromFrame(t *testing.T, frame []byte) (dstMAC tcpip.LinkAddress, srcIP, dstIP [4]byte, id, seq uint16, payload []byte) {
	t.Helper()
	eth := header.Ethernet(frame)
	dstMAC = eth.DestinationAddress()
	ipH := header.IPv4(frame[header.EthernetMinimumSize:])
	src := ipH.SourceAddress()
	dst := ipH.DestinationAddress()
	copy(srcIP[:], src.AsSlice())
	copy(dstIP[:], dst.AsSlice())
	icmp := ipH.Payload()
	id = binary.BigEndian.Uint16(icmp[4:6])
	seq = binary.BigEndian.Uint16(icmp[6:8])
	payload = icmp[header.ICMPv4MinimumSize:]
	return dstMAC, srcIP, dstIP, id, seq, payload
}

func testRelay() (*ICMPRelay, *[][]byte, *[]([]byte)) {
	var sent [][]byte
	var delivered [][]byte
	r := &ICMPRelay{
		srcMAC:  "02:00:00:00:00:01",
		hostID:  4242,
		fd:      1, // any non-negative: tests replace send
		flows:   map[uint16]*icmpFlow{},
		deliver: func(f []byte) { delivered = append(delivered, f) },
	}
	r.send = func(b []byte, _ [4]byte) error { sent = append(sent, b); return nil }
	return r, &sent, &delivered
}

// A public ping is consumed, leaves the host socket with our id/seq and
// the guest's payload, and the flow table remembers the mapping.
func TestRelaySendsPublicEchoAndRecordsFlow(t *testing.T) {
	r, sent, _ := testRelay()
	guestMAC := [6]byte{0x52, 0x54, 0x00, 0x00, 0x00, 0x15}
	guestIP := [4]byte{10, 0, 2, 15}
	target := [4]byte{1, 1, 1, 1}
	own := map[[4]byte]bool{{10, 0, 2, 2}: true, {10, 0, 2, 3}: true}

	frame := echoFrame(guestMAC, guestIP, target, 0xBEEF, 7, []byte("ping-payload"))
	if !r.HandleFrame(frame, own) {
		t.Fatal("public echo request not taken by the relay")
	}
	if len(*sent) != 1 {
		t.Fatalf("host socket saw %d sends, want 1", len(*sent))
	}
	pkt := (*sent)[0]
	if pkt[0] != uint8(header.ICMPv4Echo) {
		t.Fatalf("host packet type %d, want echo request", pkt[0])
	}
	if got := binary.BigEndian.Uint16(pkt[4:6]); got != 4242 {
		t.Fatalf("host echo id %d, want the socket id 4242", got)
	}
	if got := binary.BigEndian.Uint16(pkt[6:8]); got == 7 {
		t.Fatal("host seq not remapped, would collide with guest seqs")
	}
	if got := string(pkt[header.ICMPv4MinimumSize:]); got != "ping-payload" {
		t.Fatalf("payload corrupted: %q", got)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.flows) != 1 {
		t.Fatalf("flow table has %d entries, want 1", len(r.flows))
	}
	for _, f := range r.flows {
		if f.id != 0xBEEF || f.seq != 7 {
			t.Fatalf("flow lost the guest's id/seq: %v", f)
		}
		if f.guestIP != guestIP || f.dst != target {
			t.Fatalf("flow lost addresses: %v", f)
		}
	}
}

// Pings to our own addresses stay with netstack, which answers directly.
func TestRelaySkipsOwnAddresses(t *testing.T) {
	r, sent, _ := testRelay()
	guestMAC := [6]byte{0x52, 0x54, 0x00, 0x00, 0x00, 0x15}
	frame := echoFrame(guestMAC, [4]byte{10, 0, 2, 15}, [4]byte{10, 0, 2, 2}, 1, 1, []byte("x"))
	own := map[[4]byte]bool{{10, 0, 2, 2}: true}
	if r.HandleFrame(frame, own) {
		t.Fatal("relay consumed an echo addressed to the gateway")
	}
	if len(*sent) != 0 {
		t.Fatal("host socket saw a send for a gateway ping")
	}
}

// The reply comes back with the guest's original id/seq and reversed
// addresses, wrapped as a frame addressed to the guest's MAC.
func TestRelayRewritesReplyIntoGuestFrame(t *testing.T) {
	r, _, delivered := testRelay()
	guestMAC := [6]byte{0x52, 0x54, 0x00, 0x00, 0x00, 0x15}
	guestIP := [4]byte{10, 0, 2, 15}
	target := [4]byte{1, 1, 1, 1}
	own := map[[4]byte]bool{{10, 0, 2, 2}: true}

	frame := echoFrame(guestMAC, guestIP, target, 0xBEEF, 9, []byte("roundtrip"))
	if !r.HandleFrame(frame, own) {
		t.Fatal("echo request not taken")
	}
	r.mu.Lock()
	var ourSeq uint16
	for seq := range r.flows {
		ourSeq = seq
	}
	r.mu.Unlock()

	// What the host kernel returns: echo reply, our id, our seq, the data.
	reply := make([]byte, header.ICMPv4MinimumSize+9)
	reply[0] = uint8(header.ICMPv4EchoReply)
	binary.BigEndian.PutUint16(reply[4:6], 4242)
	binary.BigEndian.PutUint16(reply[6:8], ourSeq)
	copy(reply[header.ICMPv4MinimumSize:], "roundtrip")
	r.handleReply(reply, &target)

	if len(*delivered) != 1 {
		t.Fatalf("relay produced %d frames, want 1", len(*delivered))
	}
	dstMAC, srcIP, dstIP, id, seq, payload := parseICMPFromFrame(t, (*delivered)[0])
	if dstMAC.String() != "52:54:00:00:00:15" {
		t.Fatalf("reply L2 destination %s, want the guest MAC", dstMAC)
	}
	if srcIP != target || dstIP != guestIP {
		t.Fatalf("reply addresses %v->%v, want %v->%v", srcIP, dstIP, target, guestIP)
	}
	if id != 0xBEEF || seq != 9 {
		t.Fatalf("reply id/seq %d/%d, want the guest's 0xBEEF/9", id, seq)
	}
	if string(payload) != "roundtrip" {
		t.Fatalf("reply payload %q", payload)
	}
	if len(r.flows) != 0 {
		t.Fatal("flow not retired after its reply")
	}
}

// A reply with no matching flow is dropped, not delivered as garbage.
func TestRelayDropsUnknownReply(t *testing.T) {
	r, _, delivered := testRelay()
	src := [4]byte{1, 1, 1, 1}
	reply := make([]byte, header.ICMPv4MinimumSize)
	reply[0] = uint8(header.ICMPv4EchoReply)
	binary.BigEndian.PutUint16(reply[4:6], 4242)
	r.handleReply(reply, &src)
	if len(*delivered) != 0 {
		t.Fatal("unmatched reply delivered to the guest")
	}
}
