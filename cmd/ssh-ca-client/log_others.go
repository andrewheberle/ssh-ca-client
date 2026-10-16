//go:build !windows

package main

import (
	"fmt"
	"os"
	"strings"
)

func logFatal(format string, a ...any) {
	sanitized := make([]any, len(a))
	for i, v := range a {
		switch t := v.(type) {
		case string:
			s := strings.ReplaceAll(t, "\n", "")
			s = strings.ReplaceAll(s, "\r", "")
			sanitized[i] = s
		case error:
			s := strings.ReplaceAll(t.Error(), "\n", "")
			s = strings.ReplaceAll(s, "\r", "")
			sanitized[i] = s
		default:
			sanitized[i] = v
		}
	}

	fmt.Printf(format, sanitized...)
	os.Exit(1)
}
