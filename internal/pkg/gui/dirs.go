package gui

import (
	"fmt"
	"path/filepath"
)

// validatedStatePath ensures the state directory is absolute, cleaned and not
// the root of a filesystem, as it is derived from environment variables.
func validatedStatePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("state path is empty")
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("state path must be absolute: %q", path)
	}

	clean := filepath.Clean(path)

	// the parent of a root ("/", `C:\` or `\\server\share\`) is itself
	if filepath.Dir(clean) == clean {
		return "", fmt.Errorf("state path must not be a root directory: %q", path)
	}

	return clean, nil
}
