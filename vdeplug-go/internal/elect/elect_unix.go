//go:build unix

// elect_unix.go — the hub seat as an exclusive flock on <socket>.lock:
// the kernel releases it when the holder dies (even SIGKILL), so a seat
// fight needs no election protocol.
package elect

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// TryLock takes the hub seat for the switch at socketPath, or fails with
// ErrSeatHeld. The returned release func drops the lock; the kernel
// drops it anyway when the process dies. The lock file itself is never
// removed.
func TryLock(socketPath string) (release func(), err error) {
	lockPath := socketPath + ".lock"
	fd, err := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", lockPath, err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, ErrSeatHeld
	}
	return func() { unix.Close(fd) }, nil
}
