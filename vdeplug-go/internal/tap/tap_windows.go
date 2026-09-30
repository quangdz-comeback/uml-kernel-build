//go:build !unix

// tap_windows.go — no tun/tap on Windows: the uml-nt helper uses the
// slirp uplink only (D8). The symbol exists so main.go compiles; the
// tap uplink branch never runs.
package tap

import "errors"

// Device is a placeholder; Open never returns one on Windows.
type Device struct{}

// Open always fails: there is no tun/tap on Windows.
func Open(name string) (*Device, error) {
	return nil, errors.New("tap: no tun/tap on windows (uplink slirp only, D8)")
}

// Name is the placeholder name.
func (d *Device) Name() string { return "none" }

// SendFrame drops the frame (unreachable).
func (d *Device) SendFrame(frame []byte) error { return nil }

// RecvFrame blocks forever (unreachable).
func (d *Device) RecvFrame(buf []byte) (int, error) {
	select {} // unreachable: Open fails first
}

// Close is a no-op.
func (d *Device) Close() error { return nil }
