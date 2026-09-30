//go:build !unix

// transport_windows.go — no AF_UNIX on Windows (D8: the uml-nt kernel
// speaks TCP localhost only). The fleet switch socket is a Linux
// feature; the direct TCP guest wire lives in transport.go proper.
package transport

import "fmt"

func tryConnectUnix(addr string) (Conn, error) {
	return nil, fmt.Errorf("unix socket %s: unavailable on windows (D8)", addr)
}

func bindOrConnectUnix(addr string, mode uint32) (Listener, Conn, error) {
	return nil, nil, fmt.Errorf("unix socket %s: unavailable on windows (D8)", addr)
}
