//go:build unix

// transport_unix.go — the unix SOCK_SEQPACKET switch socket (the
// production guest wire on Linux, and the fleet hub socket everywhere).
package transport

import "uml-kernel-build/vdeplug-go/internal/unixseq"

type unixConn struct{ *unixseq.Conn }

type unixListener struct{ l *unixseq.Listener }

func (w unixListener) Accept() (Conn, error) {
	c, err := w.l.Accept()
	if err != nil {
		return nil, err
	}
	return unixConn{c}, nil
}

func (w unixListener) Close() { w.l.Close() }

func tryConnectUnix(addr string) (Conn, error) {
	c, err := unixseq.TryConnect(addr)
	if err != nil {
		return nil, err
	}
	return unixConn{c}, nil
}

func bindOrConnectUnix(addr string, mode uint32) (Listener, Conn, error) {
	ln, conn, err := unixseq.BindOrConnect(addr, mode)
	if err != nil {
		return nil, nil, err
	}
	if conn != nil {
		return nil, unixConn{conn}, nil
	}
	return unixListener{ln}, nil, nil
}
