//go:build unix

// link_unix.go — the seqpacket fd guest wire (the production shape on
// Linux: UML's vector vde transport execs the helper with one end of a
// SOCK_SEQPACKET socketpair; one Ethernet frame per socket message).
package link

import (
	"io"

	"golang.org/x/sys/unix"
)

// fdWire adapts a connected SOCK_SEQPACKET fd to the Wire interface.
type fdWire struct{ fd int }

// NewFD wraps fd (inherited from UML, `seqpacket://FD`) as a Wire.
func NewFD(fd int) Wire { return fdWire{fd: fd} }

func (w fdWire) SendFrame(b []byte) error {
	for {
		err := unix.Sendmsg(w.fd, b, nil, nil, 0)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

func (w fdWire) RecvFrame(buf []byte) (int, error) {
	for {
		n, _, _, _, err := unix.Recvmsg(w.fd, buf, nil, 0)
		if err == unix.EINTR {
			continue
		}
		if n == 0 && err == nil {
			return 0, io.EOF // SEQPACKET peer close: (0, nil)
		}
		return n, err
	}
}

func (w fdWire) Close() {
	// Process-exit closes the fd anyway (upstream never closed it
	// either); a failed close here has nothing to report to.
	_ = unix.Close(w.fd)
}
