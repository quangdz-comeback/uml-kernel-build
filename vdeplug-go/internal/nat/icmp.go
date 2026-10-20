package nat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ICMP echo to anywhere-but-us used to die on the floor: netstack answers
// echo for its own addresses only, and forwarding drops everything else.
// This relay gives public pings libslirp semantics: catch the guest's echo
// request at the frame layer, re-emit it from an unprivileged host ICMP
// datagram socket (SOCK_DGRAM IPPROTO_ICMP — needs no root, only
// ping_group_range covering our gid), and rewrite each reply back into a
// guest frame.
type ICMPRelay struct {
	srcMAC  tcpip.LinkAddress // our (gateway) MAC on the segment
	deliver func(frame []byte)
	logf    func(string, ...any)

	hostID uint16                              // kernel-assigned echo id of the host socket
	fd     int                                 // host ICMP socket, -1 when the relay is unavailable
	send   func(pkt []byte, dst [4]byte) error // the socket send (injected in tests)

	mu    sync.Mutex
	flows map[uint16]*icmpFlow // our seq -> flow
	seq   uint16
}

// icmpFlow remembers whose echo we rewrote, so the reply can be put back
// together with the guest's original id and addresses.
type icmpFlow struct {
	guestMAC [6]byte
	guestIP  [4]byte // echo source
	dst      [4]byte // echo destination: the reply's source
	id       uint16  // guest's original echo id
	seq      uint16  // guest's original echo seq
	deadline time.Time
	srcMAC   tcpip.LinkAddress // our MAC, for the reply's Ethernet header
}

const icmpFlowTTL = 30 * time.Second

// NewICMPRelay opens the host socket and starts the reply reader. Failure
// (closed ping_group_range, seccomp) leaves the relay nil-safe but inert:
// guest pings fall through to netstack, which sheds them as before.
func NewICMPRelay(srcMAC tcpip.LinkAddress, deliver func(frame []byte), logf func(string, ...any)) *ICMPRelay {
	r := &ICMPRelay{
		srcMAC:  srcMAC,
		deliver: deliver,
		logf:    logf,
		fd:      -1,
		flows:   map[uint16]*icmpFlow{},
	}
	fd, id, err := openEchoSocket()
	if err != nil {
		logf("icmp echo relay disabled: %v", err)
		return r
	}
	r.fd, r.hostID = fd, id
	r.send = func(pkt []byte, dst [4]byte) error {
		return unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: dst})
	}
	logf("icmp echo relay on host socket id %d", id)
	go r.readLoop()
	return r
}

// HandleFrame relays one guest ICMPv4 echo request frame. It reports
// whether the frame was consumed (a relayed request or a request destined
// to an address we own — netstack answers those itself and must not see
// duplicates). Frames that are not public echo requests return false and
// continue to netstack untouched.
func (r *ICMPRelay) HandleFrame(frame []byte, own map[[4]byte]bool) bool {
	if r == nil || r.fd < 0 {
		return false
	}
	dst, id, seq, payload, ok := parseEchoRequest(frame)
	if !ok {
		return false
	}
	dst4 := dst
	if own[dst4] {
		return false // ours: netstack answers directly
	}
	flow := &icmpFlow{
		guestIP:  [4]byte{frame[26], frame[27], frame[28], frame[29]},
		dst:      dst4,
		id:       id,
		seq:      seq,
		deadline: time.Now().Add(icmpFlowTTL),
		srcMAC:   r.srcMAC,
	}
	copy(flow.guestMAC[:], frame[6:12])

	r.mu.Lock()
	r.seq++
	ourSeq := r.seq
	r.sweepLocked()
	r.flows[ourSeq] = flow
	r.mu.Unlock()

	if err := r.sendEchoRequest(dst4, ourSeq, payload); err != nil {
		r.mu.Lock()
		delete(r.flows, ourSeq)
		r.mu.Unlock()
		r.logf("icmp relay: send to %s: %v", net.IP(dst4[:]), err)
		return false
	}
	return true
}

// sendEchoRequest emits one echo request on the host socket with our id
// and seq; the payload carries the guest's data verbatim.
func (r *ICMPRelay) sendEchoRequest(dst [4]byte, seq uint16, payload []byte) error {
	pkt := make([]byte, header.ICMPv4MinimumSize+len(payload))
	pkt[0] = uint8(header.ICMPv4Echo)
	binary.BigEndian.PutUint16(pkt[4:6], r.hostID)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[header.ICMPv4MinimumSize:], payload)
	binary.BigEndian.PutUint16(pkt[2:4], icmpChecksum(pkt))
	return r.send(pkt, dst)
}

// readLoop turns host echo replies back into guest frames.
func (r *ICMPRelay) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, from, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			return // socket closed: relay is done
		}
		from4, ok := from.(*unix.SockaddrInet4)
		if !ok {
			continue
		}
		r.handleReply(buf[:n], &from4.Addr)
	}
}

// handleReply matches one host echo reply to its flow and injects the
// rewritten guest frame.
func (r *ICMPRelay) handleReply(pkt []byte, replySrc *[4]byte) {
	if len(pkt) < header.ICMPv4MinimumSize || pkt[0] != uint8(header.ICMPv4EchoReply) {
		return
	}
	seq := binary.BigEndian.Uint16(pkt[6:8])
	r.mu.Lock()
	flow, ok := r.flows[seq]
	if ok {
		delete(r.flows, seq)
	}
	r.mu.Unlock()
	if !ok {
		return // late reply for a swept flow
	}
	payload := pkt[header.ICMPv4MinimumSize:]
	r.deliver(buildEchoReply(flow, *replySrc, payload))
}

// buildEchoReply assembles the Ethernet+IPv4+ICMP frame: source is the
// host the guest pinged, destination is the guest, id/seq are the
// guest's originals.
func buildEchoReply(flow *icmpFlow, replySrc [4]byte, payload []byte) []byte {
	icmpLen := header.ICMPv4MinimumSize + len(payload)
	ipLen := header.IPv4MinimumSize + icmpLen
	frame := make([]byte, header.EthernetMinimumSize+ipLen)

	icmp := frame[header.EthernetMinimumSize+header.IPv4MinimumSize:]
	icmp[0] = uint8(header.ICMPv4EchoReply)
	binary.BigEndian.PutUint16(icmp[4:6], flow.id)
	binary.BigEndian.PutUint16(icmp[6:8], flow.seq)
	copy(icmp[header.ICMPv4MinimumSize:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(icmp))

	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(ipLen),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(replySrc),
		DstAddr:     tcpip.AddrFrom4(flow.guestIP),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: flow.srcMAC,
		DstAddr: tcpip.LinkAddress(flow.guestMAC[:]),
		Type:    0x0800,
	})
	return frame
}

// parseEchoRequest pulls the echo fields out of an Ethernet+IPv4+ICMP
// frame. ok=false for anything that is not a well-formed echo request.
func parseEchoRequest(frame []byte) (dst [4]byte, id, seq uint16, payload []byte, ok bool) {
	if len(frame) < header.EthernetMinimumSize+header.IPv4MinimumSize+header.ICMPv4MinimumSize {
		return dst, 0, 0, nil, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return dst, 0, 0, nil, false
	}
	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	if ip.Protocol() != uint8(header.ICMPv4ProtocolNumber) {
		return dst, 0, 0, nil, false
	}
	ihl := int(ip.HeaderLength())
	if len(frame) < header.EthernetMinimumSize+ihl+header.ICMPv4MinimumSize {
		return dst, 0, 0, nil, false
	}
	icmp := frame[header.EthernetMinimumSize+ihl:]
	if icmp[0] != uint8(header.ICMPv4Echo) {
		return dst, 0, 0, nil, false
	}
	total := int(ip.TotalLength())
	if total < ihl+header.ICMPv4MinimumSize || header.EthernetMinimumSize+total > len(frame) {
		// Trust the frame length when the IP total length is off.
		total = len(frame) - header.EthernetMinimumSize
	}
	dstIP := ip.DestinationAddress()
	copy(dst[:], dstIP.AsSlice())
	id = binary.BigEndian.Uint16(icmp[4:6])
	seq = binary.BigEndian.Uint16(icmp[6:8])
	payload = icmp[header.ICMPv4MinimumSize : total-ihl]
	return dst, id, seq, payload, true
}

// sweepLocked drops flows whose replies never came back. Caller holds mu.
func (r *ICMPRelay) sweepLocked() {
	now := time.Now()
	for seq, f := range r.flows {
		if now.After(f.deadline) {
			delete(r.flows, seq)
		}
	}
}

// openEchoSocket binds an unprivileged ICMP datagram socket; the kernel
// assigns its echo id (the bound port).
func openEchoSocket() (fd int, id uint16, err error) {
	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return -1, 0, fmt.Errorf("socket icmp: %w (unprivileged ICMP may be disabled)", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		unix.Close(fd)
		return -1, 0, fmt.Errorf("bind icmp: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return -1, 0, fmt.Errorf("getsockname icmp: %w", err)
	}
	port, ok := sa.(*unix.SockaddrInet4)
	if !ok || port.Port == 0 {
		unix.Close(fd)
		return -1, 0, errors.New("icmp socket without an echo id")
	}
	return fd, uint16(port.Port), nil
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
