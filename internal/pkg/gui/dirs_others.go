//go:build !windows

package gui

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

// stateDir returns the directory for logs and the lock file. When running as a
// snap this is $SNAP_USER_COMMON, otherwise it follows the XDG Base Directory
// Specification and is $XDG_STATE_HOME or ~/.local/state.
func stateDir() (string, error) {
	// are we running as a snap?
	if dir := os.Getenv("SNAP_USER_COMMON"); dir != "" {
		return dir, nil
	}

	// relative paths are invalid and must be ignored
	if dir := os.Getenv("XDG_STATE_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Join(dir, names.AppName), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not find home directory: %w", err)
	}

	return filepath.Join(home, ".local", "state", names.AppName), nil
}
