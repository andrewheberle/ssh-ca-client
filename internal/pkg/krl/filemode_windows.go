package krl

import (
	"io/fs"
	"os"
)

const (
	// FileMode is the mode of an installed KRL. Windows maps a mode without
	// write permission to the read-only attribute, which prevents another
	// file being renamed over it, so the KRL is left writable; access is
	// governed by the file's ACL instead.
	FileMode fs.FileMode = 0644

	// installedPerm is the permission reported for an installed KRL, as
	// Windows reports any writable file as 0666
	installedPerm fs.FileMode = 0666
)

// makeReplaceable clears the read-only attribute on the KRL at path, which
// earlier versions set, so another file can be renamed over it
func makeReplaceable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.Mode().Perm() == installedPerm {
		return nil
	}

	return os.Chmod(path, FileMode)
}
