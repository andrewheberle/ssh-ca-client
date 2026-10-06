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

	t.Run("no local app data", func(t *testing.T) {
		t.Setenv("LocalAppData", "")

		if _, err := stateDir(); err == nil {
			t.Errorf("stateDir() error = nil, want error")
		}
	})
}
