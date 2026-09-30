//go:build !unix

// elect_windows.go — no fleet on Windows: the uml-nt helper runs direct
// (one guest wire per process), so the hub seat never applies. The
// symbol exists so the fleet code compiles; it always refuses.
package elect

import "errors"

// TryLock always fails: there is no fleet seat on Windows.
func TryLock(socketPath string) (release func(), err error) {
	return nil, errors.New("hub seat: no fleet on windows (direct mode)")
}
