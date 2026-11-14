//go:build !windows

package gui

import "log/slog"

// redirectOutput does nothing, as the GUI only lacks a console on Windows
func redirectOutput(logger *slog.Logger) {}
