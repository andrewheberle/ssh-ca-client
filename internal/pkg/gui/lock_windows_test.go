package gui

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestLockSingleInstance checks that a second GUI is reported as already
// running on Windows, where the lock file can't be deleted while it is open
func TestLockSingleInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tray.lock")

	release, err := lockSingleInstance(path)
	if err != nil {
		t.Fatalf("first lockSingleInstance() error = %v", err)
	}

	if _, err := lockSingleInstance(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("lockSingleInstance() while locked error = %v, want %v", err, ErrAlreadyRunning)
	}

	if err := release(); err != nil {
		t.Fatalf("release() error = %v", err)
	}

	releaseNext, err := lockSingleInstance(path)
	if err != nil {
		t.Fatalf("lockSingleInstance() after release error = %v", err)
	}
	_ = releaseNext()
}
