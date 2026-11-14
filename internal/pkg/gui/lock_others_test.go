//go:build !windows

package gui

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLockSingleInstance checks the GUI's single-instance lock on Linux, where
// it is an flock on the lock file (#229).
func TestLockSingleInstance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tray.lock")

	releaseA, err := lockSingleInstance(path)
	if err != nil {
		t.Fatalf("first lockSingleInstance() error = %v", err)
	}

	if _, err := lockSingleInstance(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("lockSingleInstance() while locked error = %v, want %v", err, ErrAlreadyRunning)
	}

	if err := releaseA(); err != nil {
		t.Fatalf("release() error = %v", err)
	}

	// the file is left in place, as deleting it after the release lets a
	// start that locked it in between run alongside a later one
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file after release: %v, want it kept", err)
	}

	releaseB, err := lockSingleInstance(path)
	if err != nil {
		t.Fatalf("lockSingleInstance() after release error = %v", err)
	}
	defer func() {
		_ = releaseB()
	}()

	if _, err := lockSingleInstance(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("lockSingleInstance() while the next instance holds the lock error = %v, want %v", err, ErrAlreadyRunning)
	}

	// a lock that can't be taken for another reason isn't reported as running
	if _, err := lockSingleInstance(filepath.Join(t.TempDir(), "missing", "tray.lock")); err == nil || errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("lockSingleInstance() in a missing directory error = %v, want an error other than %v", err, ErrAlreadyRunning)
	}
}
