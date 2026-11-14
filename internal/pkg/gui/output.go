package gui

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"strings"
)

// forwardLines logs each line read from r at warning level, with source as
// an attribute, until r returns an error. It reads lines of any length, so
// whatever writes to r is never left blocked.
func forwardLines(r io.Reader, logger *slog.Logger, source string) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line = strings.TrimRight(line, "\r\n"); line != "" {
			logger.Warn(line, "source", source)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				logger.Debug("stopped forwarding output", "source", source, "error", err)
			}
			return
		}
	}
}
