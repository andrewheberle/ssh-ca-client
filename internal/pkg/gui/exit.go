package gui

import "fmt"

// Exit is returned by [Execute] when the GUI exits without running and has
// something to tell the user: the usage or version, a problem with the
// command line, or that the GUI is already running. Code is the exit code,
// which is 0 when Message is only information.
type Exit struct {
	Message string
	Code    int
}

func (e *Exit) Error() string {
	return fmt.Sprintf("exit %d: %s", e.Code, e.Message)
}
