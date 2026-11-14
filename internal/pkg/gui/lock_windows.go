package gui

import (
	"errors"

	"golang.org/x/sys/windows"
)

// lockHeld reports whether err is from taking a lock that another process
// holds. On Windows the lock file is deleted and created again, which fails
// with a sharing violation while another process has it open.
func lockHeld(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
