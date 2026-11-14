// Package pageant proxies PuTTY Agent (Pageant) requests to the native
// OpenSSH SSH agent on Windows.
package pageant

import "errors"

var (
	// ErrNotSupported is returned by [Run] on platforms other than Windows
	ErrNotSupported = errors.New("pageant proxy is only supported on Windows")

	// ErrPageantRunning is returned by [Run] when another program, such as
	// PuTTY's own Pageant, already answers PuTTY's agent requests
	ErrPageantRunning = errors.New("another Pageant is already running")

	// ErrStopped is returned by [Run] when the proxy fails to start or stops
	// before ctx is done
	ErrStopped = errors.New("pageant proxy stopped")
)
