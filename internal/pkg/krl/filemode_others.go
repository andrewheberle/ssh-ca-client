//go:build !windows

package krl

import "io/fs"

const (
	// FileMode is the mode of an installed KRL, which is read-only as
	// nothing but [Verified.Install] should change it
	FileMode fs.FileMode = 0440

	// installedPerm is the permission reported for an installed KRL
	installedPerm = FileMode
)

// makeReplaceable does nothing, as a read-only file can be replaced by
// renaming another file over it
func makeReplaceable(path string) error {
	return nil
}
