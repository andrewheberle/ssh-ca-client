//go:build !windows

package gui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

// TestExecute_AlreadyRunning starts the GUI while another holds the lock,
// which is reported as information before the configuration is loaded
func TestExecute_AlreadyRunning(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SNAP_USER_COMMON", "")
	t.Setenv("XDG_STATE_HOME", state)

	dir := filepath.Join(state, names.AppName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	release, err := lockSingleInstance(filepath.Join(dir, "tray.lock"))
	if err != nil {
		t.Fatalf("lockSingleInstance() error = %v", err)
	}
	defer func() {
		_ = release()
	}()

	// a deprecated flag's warning is written to stderr once the logger is
	// set up
	stderr := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(stderr)
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = f
	t.Cleanup(func() {
		os.Stderr = origStderr
		_ = f.Close()
	})

	err = Execute(context.Background(), []string{"--renew", "30m", "--config", filepath.Join(state, "missing.yml")})

	var exit *Exit
	if !errors.As(err, &exit) {
		t.Fatalf("Execute() error = %v, want an Exit", err)
	}
	if exit.Code != 0 || !strings.Contains(exit.Message, "already running") {
		t.Errorf("Execute() = %+v, want code 0 and a message that it is already running", exit)
	}

	warnings, err := os.ReadFile(stderr)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(warnings), "--renew has been deprecated") {
		t.Errorf("stderr = %q, want the deprecation warning for --renew", warnings)
	}
}
