package krl_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
)

func TestInstall_Windows(t *testing.T) {
	ca := newSigner(t)

	const date = 1_800_000_000

	// install installs v at path and checks the outcome
	install := func(t *testing.T, v *krl.Verified, path string, want krl.Outcome) {
		t.Helper()

		got, err := v.Install(path)
		if err != nil {
			t.Fatalf("Install() failed: %v", err)
		}
		if got != want {
			t.Errorf("Install() = %v, want %v", got, want)
		}
	}

	t.Run("installed krl can be replaced", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "revocation_list")
		first := fetch(t, ca, generated(t, ca, 1, date))
		later := fetch(t, ca, generated(t, ca, 1, date+1))

		install(t, first, path, krl.Written)
		install(t, first, path, krl.Unchanged)
		install(t, later, path, krl.Written)
		install(t, later, path, krl.Unchanged)
	})

	// earlier versions installed the krl with the read-only attribute set
	t.Run("read-only krl can be replaced", func(t *testing.T) {
		tests := []struct {
			name     string
			existing func(v *krl.Verified) []byte
		}{
			{"same krl", func(v *krl.Verified) []byte { return v.Bytes() }},
			{"older krl", func(*krl.Verified) []byte { return generated(t, ca, 1, date-1) }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "revocation_list")
				v := fetch(t, ca, generated(t, ca, 1, date))

				if err := os.WriteFile(path, tt.existing(v), 0600); err != nil {
					t.Fatalf("writing existing krl: %v", err)
				}
				if err := os.Chmod(path, 0440); err != nil {
					t.Fatalf("making existing krl read-only: %v", err)
				}

				install(t, v, path, krl.Written)
				install(t, v, path, krl.Unchanged)
			})
		}
	})
}
