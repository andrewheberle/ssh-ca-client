package gui

import (
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

func TestStateDir(t *testing.T) {
	t.Run("local app data", func(t *testing.T) {
		t.Setenv("LocalAppData", `C:\Users\test\AppData\Local`)

		got, err := stateDir()
		if err != nil {
			t.Fatalf("stateDir() error = %v", err)
		}
		if want := filepath.Join(`C:\Users\test\AppData\Local`, names.AppName); got != want {
			t.Errorf("stateDir() = %q, want %q", got, want)
		}
	})

	t.Run("not roaming app data", func(t *testing.T) {
		t.Setenv("LocalAppData", `C:\Users\test\AppData\Local`)
		t.Setenv("AppData", `C:\Users\test\AppData\Roaming`)

		got, err := stateDir()
		if err != nil {
			t.Fatalf("stateDir() error = %v", err)
		}
		if filepath.Dir(got) != `C:\Users\test\AppData\Local` {
			t.Errorf("stateDir() = %q, want a directory in %%LOCALAPPDATA%%", got)
		}
	})

	t.Run("relative local app data", func(t *testing.T) {
		t.Setenv("LocalAppData", `AppData\Local`)

		if _, err := stateDir(); err == nil {
			t.Errorf("stateDir() error = nil, want error")
		}
	})

	t.Run("no local app data", func(t *testing.T) {
		t.Setenv("LocalAppData", "")

		if _, err := stateDir(); err == nil {
			t.Errorf("stateDir() error = nil, want error")
		}
	})
}

func TestValidatedStatePath(t *testing.T) {
	tests := []struct {
		path    string
		want    string
		wantErr bool
	}{
		{`C:\Users\test\AppData\Local\app`, `C:\Users\test\AppData\Local\app`, false},
		{`C:\Users\test\AppData\Local\app\`, `C:\Users\test\AppData\Local\app`, false},
		{`C:\Users\test\..\other\.\app`, `C:\Users\other\app`, false},
		{`\\server\share\app`, `\\server\share\app`, false},
		{"", "", true},
		{`relative\app`, "", true},
		{`\no-drive\app`, "", true},
		{`C:relative\app`, "", true},
		{`C:\`, "", true},
		{`C:\Users\..`, "", true},
		{`\\server\share\`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := validatedStatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatedStatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("validatedStatePath() = %q, want %q", got, tt.want)
			}
		})
	}
}
