//go:build !unix

// shutdown_windows.go — wait for a shutdown reason (INT/TERM only; the
// SIGUSR1 stats dump is the unix ops interface).
package main

import (
	"os"
	"os/signal"
	"syscall"

	"uml-kernel-build/vdeplug-go/internal/dhcp"
	"uml-kernel-build/vdeplug-go/internal/nat"
	"uml-kernel-build/vdeplug-go/internal/vswitch"
)

func waitShutdown(theNAT *nat.NAT, sw *vswitch.Switch, leasePool *dhcp.Pool, rxErr <-chan error, txErr <-chan error) {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
loop:
	for {
		select {
		case err := <-rxErr:
			logf("guest link gone: %v", err)
			break loop
		case err := <-txErr:
			logf("netstack pump gone: %v", err)
			break loop
		case s := <-sigs:
			logf("received %v, exiting", s)
			break loop
		}
	}
	if theNAT != nil {
		theNAT.Close()
	}
}
