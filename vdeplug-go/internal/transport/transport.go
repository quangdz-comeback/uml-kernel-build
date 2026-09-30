// Package transport abstracts the switch socket AND the guest wire: a
// unix SOCK_SEQPACKET socket on one machine, or a length-prefixed TCP
// socket across machines / to the uml-nt kernel (D8: TCP localhost —
// the kernel dials, the helper listens). The address grammar (shared
// with config socket_file_location):
//
//	/tmp/vde.socket     unix socket file
//	203.0.113.7:9100    TCP host:port (remote raw socket)
package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FrameMax mirrors link.FrameMax (kept local: transport must not depend
// on the link layer).
const FrameMax = 9216 + 14 + 4

// Conn is one peer wire (or the guest-side view of a hub wire).
type Conn interface {
	SendFrame([]byte) error
	RecvFrame([]byte) (int, error)
	Close()
}

// Listener accepts peer wires; the unix variant removes its socket file
// on Close.
type Listener interface {
	Accept() (Conn, error)
	Close()
}

// IsTCP reports whether addr names a TCP socket rather than a file path.
func IsTCP(addr string) bool {
	if strings.Contains(addr, "/") {
		return false
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	_, err = strconv.Atoi(port)
	return err == nil
}

// NewConnFromNet wraps a connected TCP stream as a framed Conn — the
// guest wire the uml-nt kernel dials (2-byte big-endian length prefix
// per frame, same as the remote-peer protocol).
func NewConnFromNet(c net.Conn) Conn { return newTCPConn(c) }

// TryConnect joins an existing switch at addr without binding anything.
func TryConnect(addr string) (Conn, error) {
	if IsTCP(addr) {
		return tryConnectTCP(addr)
	}
	return tryConnectUnix(addr)
}

// BindOrConnect joins an existing switch at addr, or binds it (becoming
// the hub) when nobody answers. Returns either ln != nil (hub side) or
// conn != nil (peer side).
func BindOrConnect(addr string, mode uint32) (Listener, Conn, error) {
	if IsTCP(addr) {
		return bindOrConnectTCP(addr)
	}
	return bindOrConnectUnix(addr, mode)
}

func tryConnectTCP(addr string) (Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	return newTCPConn(c.(*net.TCPConn)), nil
}

func bindOrConnectTCP(addr string) (Listener, Conn, error) {
	if c, err := tryConnectTCP(addr); err == nil {
		return nil, c, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return tcpListener{l: l.(*net.TCPListener)}, nil, nil
}

// --- TCP: 2-byte big-endian length prefix per frame ---
//
// Writes take a mutex: the switch forwards to the guest wire from more
// than one goroutine (the netstack TX pump and the frame-layer DHCP
// replies), and interleaved stream writes would corrupt the framing.
// The seqpacket wire never needed this (one message = one write).

type tcpConn struct {
	c   net.Conn
	wmu sync.Mutex
}

func newTCPConn(c net.Conn) *tcpConn { return &tcpConn{c: c} }

func (t *tcpConn) SendFrame(b []byte) error {
	if len(b) > FrameMax {
		return fmt.Errorf("frame %d exceeds %d", len(b), FrameMax)
	}
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(b)))
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if _, err := t.c.Write(head[:]); err != nil {
		return err
	}
	_, err := t.c.Write(b)
	return err
}

func (t *tcpConn) RecvFrame(buf []byte) (int, error) {
	var head [2]byte
	if _, err := io.ReadFull(t.c, head[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 {
		return 0, io.EOF
	}
	if n > FrameMax || n > len(buf) {
		return 0, fmt.Errorf("peer frame %d exceeds buffer", n)
	}
	if _, err := io.ReadFull(t.c, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}

func (t *tcpConn) Close() { t.c.Close() }

type tcpListener struct{ l *net.TCPListener }

func (t tcpListener) Accept() (Conn, error) {
	c, err := t.l.Accept()
	if err != nil {
		return nil, err
	}
	return newTCPConn(c.(*net.TCPConn)), nil
}

func (t tcpListener) Close() { t.l.Close() }
