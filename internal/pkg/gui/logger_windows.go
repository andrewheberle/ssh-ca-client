package gui

import (
	"io"
	"log/slog"

	"github.com/andrewheberle/ssh-ca-client/pkg/winevent"
)

func newLogHandler(w io.Writer, level slog.Leveler, json bool) slog.Handler {
	if w == nil {
		h, err := winevent.NewHandler(EventLogSource, &winevent.Options{Level: level, EventID: 1000})
		if err != nil {
			panic(err)
		}

		return h
	}

	if json {
		return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	}
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
}
