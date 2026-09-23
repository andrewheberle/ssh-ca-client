//go:build !windows

package gui

import (
	"io"
	"log/slog"
	"os"
)

// Sets up a new [slog.Handler] using either [slog.NewTextHandler] or
// [slog.NewJSONHandler]
func newLogHandler(w io.Writer, level slog.Leveler, json bool) slog.Handler {
	if w == nil {
		w = os.Stderr
	}

	if json {
		return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	}
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
}
