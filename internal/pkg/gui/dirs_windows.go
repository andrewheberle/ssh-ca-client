package gui

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

// stateDir returns the directory for logs and the lock file, which is in
// %LOCALAPPDATA% so it is specific to this machine and not part of a roaming
// profile.
func stateDir() (string, error) {
	// on Windows this is %LOCALAPPDATA%
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("could not find local application data directory: %w", err)
	}

	return filepath.Join(dir, names.AppName), nil
}
