//go:build windows

// Package winevent provides an slog.Handler that writes log records to the
// Windows Event Log via golang.org/x/sys/windows/svc/eventlog.
//
// The named event source must already be registered on the target machine
// (for example by an MSI/WiX installer, via New-EventLog in PowerShell, or
// via eventlog.InstallAsEventCreate at install time) before NewHandler is
// called. This handler only opens and writes to an existing source; it
// does not register or deregister one.
package winevent

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

// Handler is an slog.Handler that writes records to the Windows Event Log.
//
// Record level is mapped to Windows event type as follows:
//
//	level < slog.LevelWarn  -> eventlog.Info
//	level < slog.LevelError -> eventlog.Warning
//	level >= slog.LevelError -> eventlog.Error
//
// Structured attributes and groups are rendered as an indented "key: value"
// list appended below the log message, one per line, which is more
// readable in Event Viewer than a single logfmt/JSON line.
type Handler struct {
	log     *eventlog.Log
	level   slog.Leveler
	eventID uint32
	addSrc  bool
	prefix  string   // dot-joined group prefix applied to subsequent keys
	attrs   []string // pre-rendered "key: value" lines from WithAttrs, in call order
}

// Options configures a Handler.
type Options struct {
	// Level is the minimum record level that will be logged.
	// If nil, the handler defaults to slog.LevelInfo.
	Level slog.Leveler

	// EventID is the Windows event ID reported with every record.
	// If zero, it defaults to 1.
	EventID uint32

	// AddSource causes the handler to append the source file and line
	// of the log call as a "source: file:line" line.
	AddSource bool
}

// NewHandler returns a Handler that writes to the already-registered
// Windows Event Log source named by source. The caller is responsible for
// calling Close on the returned Handler when done.
func NewHandler(source string, opts *Options) (*Handler, error) {
	l, err := eventlog.Open(source)
	if err != nil {
		return nil, fmt.Errorf("winevent: open event source %q: %w", source, err)
	}

	h := &Handler{log: l, eventID: 1}
	if opts != nil {
		h.level = opts.Level
		h.addSrc = opts.AddSource
		if opts.EventID != 0 {
			h.eventID = opts.EventID
		}
	}
	return h, nil
}

// Close deregisters the handler's underlying event source handle.
func (h *Handler) Close() error {
	return h.log.Close()
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.level != nil {
		minLevel = h.level.Level()
	}
	return level >= minLevel
}

// Handle implements slog.Handler.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)

	if h.addSrc && r.PC != 0 {
		frames := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := frames.Next()
		if f.File != "" {
			fmt.Fprintf(&b, "\nsource: %s:%d", f.File, f.Line)
		}
	}

	for _, line := range h.attrs {
		b.WriteString("\n")
		b.WriteString(line)
	}

	r.Attrs(func(a slog.Attr) bool {
		for _, line := range formatAttr(h.prefix, a) {
			b.WriteString("\n")
			b.WriteString(line)
		}
		return true
	})

	msg := b.String()

	switch {
	case r.Level >= slog.LevelError:
		return h.log.Error(h.eventID, msg)
	case r.Level >= slog.LevelWarn:
		return h.log.Warning(h.eventID, msg)
	default:
		return h.log.Info(h.eventID, msg)
	}
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := h.clone()
	for _, a := range attrs {
		h2.attrs = append(h2.attrs, formatAttr(h.prefix, a)...)
	}
	return h2
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	h2 := h.clone()
	if h2.prefix == "" {
		h2.prefix = name
	} else {
		h2.prefix += "." + name
	}
	return h2
}

func (h *Handler) clone() *Handler {
	h2 := *h
	h2.attrs = append([]string(nil), h.attrs...)
	return &h2
}

// formatAttr renders a, in the context of the given key prefix, as zero or
// more "key: value" lines, recursing into groups.
func formatAttr(prefix string, a slog.Attr) []string {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return nil
	}

	key := a.Key
	if prefix != "" {
		if key == "" {
			key = prefix
		} else {
			key = prefix + "." + key
		}
	}

	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		if len(group) == 0 {
			return nil
		}
		lines := make([]string, 0, len(group))
		for _, ga := range group {
			lines = append(lines, formatAttr(key, ga)...)
		}
		return lines
	}

	return []string{fmt.Sprintf("%s: %s", key, a.Value.String())}
}
