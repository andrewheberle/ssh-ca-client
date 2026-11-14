package gui

import (
	"log"
	"log/slog"
	"os"

	"golang.org/x/sys/windows"
)

// redirectOutput sends stdout and stderr to logger when the process has no
// usable handle for them. The GUI is linked without a console, so unless its
// output was redirected when it was started, such as to a file, whatever is
// written there would otherwise be lost. That includes the standard log
// package, which the Pageant proxy's library reports its errors with, after
// pointing it at os.Stdout.
func redirectOutput(logger *slog.Logger) {
	if w := redirectStream(windows.STD_OUTPUT_HANDLE, logger, "stdout"); w != nil {
		os.Stdout = w
	}
	if w := redirectStream(windows.STD_ERROR_HANDLE, logger, "stderr"); w != nil {
		os.Stderr = w
		log.SetOutput(w)
	}
}

// redirectStream returns a pipe whose lines are logged with source, if the
// standard handle std isn't usable, or nil otherwise
func redirectStream(std uint32, logger *slog.Logger, source string) *os.File {
	if h, err := windows.GetStdHandle(std); err == nil && h != 0 && h != windows.InvalidHandle {
		return nil
	}

	r, w, err := os.Pipe()
	if err != nil {
		logger.Warn("could not redirect output to the log", "source", source, "error", err)
		return nil
	}
	go forwardLines(r, logger, source)

	return w
}
