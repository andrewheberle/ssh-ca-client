//go:build !windows

package auth

import (
	"errors"
	"syscall"
)

// addressUnavailable reports whether err is from listening on an address
// that can't be used on this machine: one that isn't assigned to it, or of
// an address family it doesn't support.
func addressUnavailable(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)
}
