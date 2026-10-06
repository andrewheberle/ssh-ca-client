//go:build !windows

package pageant

import "context"

// Run returns [ErrNotSupported] as the pageant proxy is only supported on
// Windows.
func Run(ctx context.Context) error {
	return ErrNotSupported
}
