//go:build unix

// wire_unix.go — the guest wire on Linux: the seqpacket fd UML execs
// the helper with (upstream contract), or the framed TCP wire (D8) for
// the uml-nt kernel and TCP-loopback tests.
package main

import (
	"uml-kernel-build/vdeplug-go/internal/link"
	"uml-kernel-build/vdeplug-go/internal/transport"
)

func makeGuestWire(fd int, tcpListen string) (link.Wire, error) {
	if tcpListen != "" {
		return transport.NewConnFromNet(listenOne(tcpListen)), nil
	}
	return link.NewFD(fd), nil
}
