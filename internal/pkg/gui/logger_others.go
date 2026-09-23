//go:build !windows

package gui

import (
	"io"
	"log/slog"
	"os"
)

func newLogHandler(w io.Writer, level slog.Leveler) slog.Handler {
	if w == nil {
		w = os.Stderr
	}

	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
}
