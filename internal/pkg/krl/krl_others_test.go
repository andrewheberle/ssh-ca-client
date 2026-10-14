//go:build !windows

package krl_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
	sshkrl "github.com/forfuncsake/krl"
)

func TestInstall(t *testing.T) {
	ca := newSigner(t)

	const date = 1_800_000_000
	malformed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	// sameDateNoSections is a different KRL with the same version and
	// generated date
	sameDateNoSections, err := (&sshkrl.KRL{Version: 1, GeneratedDate: date}).Marshal(rand.Reader)
	if err != nil {
		t.Fatalf("marshalling krl: %v", err)
	}

	tests := []struct {
		name         string
		krl          []byte
		existing     []byte
		existingMode os.FileMode
		wantOutcome  krl.Outcome
		wantErr      error
	}{
		{"no existing krl", generated(t, ca, 1, date), nil, 0, krl.Written, nil},
		{"generated later", generated(t, ca, 1, date+1), generated(t, ca, 1, date), 0600, krl.Written, nil},
		{"same version and date", generated(t, ca, 1, date), sameDateNoSections, 0440, krl.Written, nil},
		{"higher version generated earlier", generated(t, ca, 2, date-1), generated(t, ca, 1, date), 0440, krl.Written, nil},
		{"existing malformed", generated(t, ca, 1, date), malformed, 0440, krl.ReplacedUnparseable, nil},
		{"existing empty", generated(t, ca, 1, date), []byte{}, 0440, krl.ReplacedUnparseable, nil},

		{"generated earlier", generated(t, ca, 1, date-1), generated(t, ca, 1, date), 0440, krl.Written, krl.ErrOlderKRL},
		{"lower version generated later", generated(t, ca, 1, date+1), generated(t, ca, 2, date), 0440, krl.Written, krl.ErrOlderKRL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := fetch(t, ca, tt.krl)
			path := filepath.Join(t.TempDir(), "revocation_list")
			if tt.existing != nil {
				writeExisting(t, path, tt.existing, tt.existingMode)
			}

			got, err := v.Install(path)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Install() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				assertFile(t, path, tt.existing, tt.existingMode)
				return
			}

			if got != tt.wantOutcome {
				t.Errorf("Install() = %v, want %v", got, tt.wantOutcome)
			}
			assertFile(t, path, tt.krl, krl.FileMode)
		})
	}

	t.Run("unchanged", func(t *testing.T) {
		tests := []struct {
			name        string
			mode        os.FileMode
			wantOutcome krl.Outcome
		}{
			{"same krl is not rewritten", 0440, krl.Unchanged},
			{"same krl with another mode is rewritten", 0600, krl.Written},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				v := fetch(t, ca, generated(t, ca, 1, date))
				path := filepath.Join(t.TempDir(), "revocation_list")
				writeExisting(t, path, v.Bytes(), tt.mode)
				before, err := os.Stat(path)
				if err != nil {
					t.Fatalf("checking existing krl: %v", err)
				}

				got, err := v.Install(path)
				if err != nil {
					t.Fatalf("Install() failed: %v", err)
				}
				if got != tt.wantOutcome {
					t.Errorf("Install() = %v, want %v", got, tt.wantOutcome)
				}

				after, err := os.Stat(path)
				if err != nil {
					t.Fatalf("checking krl: %v", err)
				}
				// the krl is written by renaming a new file over it
				if rewritten := !os.SameFile(before, after); rewritten != (tt.wantOutcome == krl.Written) {
					t.Errorf("rewritten = %v, want %v", rewritten, tt.wantOutcome == krl.Written)
				}
				assertFile(t, path, v.Bytes(), krl.FileMode)
			})
		}
	})

	t.Run("existing cannot be read", func(t *testing.T) {
		v := fetch(t, ca, generated(t, ca, 1, date))

		// a directory cannot be read as a file
		path := t.TempDir()

		if _, err := v.Install(path); err == nil || errors.Is(err, krl.ErrOlderKRL) {
			t.Errorf("Install() error = %v, want read error", err)
		}
	})

	t.Run("cannot be written", func(t *testing.T) {
		v := fetch(t, ca, generated(t, ca, 1, date))
		path := filepath.Join(t.TempDir(), "missing", "revocation_list")

		if _, err := v.Install(path); err == nil {
			t.Error("Install() succeeded unexpectedly")
		}
	})
}

// writeExisting writes b to path with mode
func writeExisting(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()

	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatalf("writing existing krl: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("setting existing krl mode: %v", err)
	}
}

// assertFile checks path holds want with mode
func assertFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading krl: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("krl file = %x, want %x", got, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("checking krl: %v", err)
	}
	if got := info.Mode().Perm(); got != mode {
		t.Errorf("krl mode = %o, want %o", got, mode)
	}
}
