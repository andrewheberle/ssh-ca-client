package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// errReader is an io.Reader that always fails
type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		name    string
		input   io.Reader
		want    bool
		wantErr bool
	}{
		{"yes", strings.NewReader("yes\n"), true, false},
		{"yes without newline", strings.NewReader("yes"), true, false},
		{"yes with spaces and case", strings.NewReader("  YES \r\n"), true, false},
		{"y", strings.NewReader("y\n"), false, false},
		{"no", strings.NewReader("no\n"), false, false},
		{"empty", strings.NewReader("\n"), false, false},
		{"no input", strings.NewReader(""), false, false},
		{"only first line", strings.NewReader("no\nyes\n"), false, false},
		{"read error", errReader{}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer

			got, err := confirm(tt.input, &out)
			if (err != nil) != tt.wantErr {
				t.Fatalf("confirm() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("confirm() = %v, want %v", got, tt.want)
			}
			if !strings.Contains(out.String(), `"yes"`) {
				t.Errorf("confirm() prompt = %q, want it to ask for \"yes\"", out.String())
			}
		})
	}
}
