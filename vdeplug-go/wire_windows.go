//go:build !unix

// wire_windows.go — the guest wire on Windows: the framed TCP wire only
// (D8 — the uml-nt kernel dials tcplisten://HOST:PORT; there is no
// AF_UNIX seqpacket to inherit).
package main

import (
	"errors"

	"uml-kernel-build/vdeplug-go/internal/link"
	"uml-kernel-build/vdeplug-go/internal/transport"
)

func makeGuestWire(fd int, tcpListen string) (link.Wire, error) {
	if tcpListen != "" {
		return transport.NewConnFromNet(listenOne(tcpListen)), nil
	}
	return nil, errors.New("no seqpacket fd on windows — pass tcplisten://host:port (D8)")
}
