//go:build !windows

package pageant

import (
	"context"
	"errors"
	"testing"
)

func TestRun(t *testing.T) {
	if err := Run(context.Background()); !errors.Is(err, ErrNotSupported) {
		t.Errorf("Run() error = %v, want %v", err, ErrNotSupported)
	}
}
