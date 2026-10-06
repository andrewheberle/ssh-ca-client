// Package pageant proxies PuTTY Agent (Pageant) requests to the native
// OpenSSH SSH agent on Windows.
package pageant

import "errors"

// ErrNotSupported is returned by [Run] on platforms other than Windows
var ErrNotSupported = errors.New("pageant proxy is only supported on Windows")
