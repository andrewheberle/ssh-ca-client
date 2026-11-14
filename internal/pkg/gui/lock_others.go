//go:build !windows

package gui

import (
	"errors"
	"syscall"
)

// lockHeld reports whether err is from taking a lock that another process
// holds, which flock reports as EWOULDBLOCK
func lockHeld(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK)
}
