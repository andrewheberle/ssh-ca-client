package gui

import (
	"errors"
	"fmt"

	"github.com/allan-simon/go-singleinstance"
)

// ErrAlreadyRunning is returned by lockSingleInstance when another GUI holds
// the lock
var ErrAlreadyRunning = errors.New("already running")

// lockSingleInstance takes the lock at path that stops a second GUI running,
// and returns the function that releases it. It returns [ErrAlreadyRunning]
// if another GUI holds the lock.
//
// Releasing the lock closes the file but leaves it in place. On Linux the lock
// is an flock on the file, so deleting it after the close would let a start
// that locked the file in between hold a lock on a deleted file, and a later
// start create a new file and run alongside it. On Windows the file can't be
// deleted while it is open, and the next start deletes a file left behind.
func lockSingleInstance(path string) (release func() error, err error) {
	f, err := singleinstance.CreateLockFile(path)
	if lockHeld(err) {
		return nil, fmt.Errorf("%w: %w", ErrAlreadyRunning, err)
	}
	if err != nil {
		return nil, err
	}

	return f.Close, nil
}
