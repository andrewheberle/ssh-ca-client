package gui

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestForwardLines(t *testing.T) {
	long := strings.Repeat("x", 100_000)

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"lines", "first\nsecond\n", []string{"first", "second"}},
		{"windows line endings", "first\r\nsecond\r\n", []string{"first", "second"}},
		{"no final newline", "first\nsecond", []string{"first", "second"}},
		{"empty lines skipped", "\nfirst\n\n\r\n", []string{"first"}},
		{"long line", long + "\nafter\n", []string{long, "after"}},
		{"nothing", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, nil))

			forwardLines(strings.NewReader(tt.input), logger, "stdout")

			var got []string
			for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				if l == "" {
					continue
				}
				var rec map[string]any
				if err := json.Unmarshal([]byte(l), &rec); err != nil {
					t.Fatalf("parsing log record %q: %v", l, err)
				}
				if rec["level"] != "WARN" || rec["source"] != "stdout" {
					t.Errorf("record level = %v, source = %v, want WARN and stdout", rec["level"], rec["source"])
				}
				got = append(got, rec["msg"].(string))
			}
			if strings.Join(got, "|") != strings.Join(tt.want, "|") {
				t.Errorf("logged %q, want %q", got, tt.want)
			}
		})
	}
}
