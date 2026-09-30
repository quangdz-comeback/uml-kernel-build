//go:build unix

// shutdown_unix.go — wait for a shutdown reason; SIGUSR1 dumps the
// link/switch/netstack counters (the ops interface).
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
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
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
			if s == syscall.SIGUSR1 {
				dumpStats(theNAT, sw, leasePool)
				continue
			}
			logf("received %v, exiting", s)
			break loop
		}
	}
	if theNAT != nil {
		theNAT.Close()
	}
}
