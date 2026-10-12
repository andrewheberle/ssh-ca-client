package tokenstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func newKeyringStore(t *testing.T) *KeyringStore {
	t.Helper()

	keyring.MockInit()

	s, err := NewKeyringStore()
	if err != nil {
		t.Fatalf("NewKeyringStore() error = %v", err)
	}

	return s
}

func TestKeyringStore(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"small token", "refresh-token"},
		// some IdPs issue refresh tokens larger than a single Windows
		// Credential Manager entry
		{"large token", strings.Repeat("0123456789", 600)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newKeyringStore(t)

			if got := s.Get(); got != "" {
				t.Errorf("Get() = %q before Set(), want empty", got)
			}

			if err := s.Set(tt.token); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			if got := s.Get(); got != tt.token {
				t.Errorf("Get() returned %d bytes, want the %d bytes stored", len(got), len(tt.token))
			}

			if err := s.Delete(); err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
			if got := s.Get(); got != "" {
				t.Errorf("Get() after Delete() returned %d bytes, want empty", len(got))
			}
		})
	}

	t.Run("delete when empty", func(t *testing.T) {
		s := newKeyringStore(t)

		if err := s.Delete(); err != nil {
			t.Errorf("Delete() error = %v, want nil", err)
		}
	})
}

func TestFileStore(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"small token", "refresh-token"},
		{"large token", strings.Repeat("0123456789", 600)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the directory is created by Set
			path := filepath.Join(t.TempDir(), "dir", "token")
			s, err := NewFileStore(path)
			if err != nil {
				t.Fatalf("NewFileStore() error = %v", err)
			}

			if got := s.Get(); got != "" {
				t.Errorf("Get() = %q before Set(), want empty", got)
			}

			if err := s.Set(tt.token); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			if got := s.Get(); got != tt.token {
				t.Errorf("Get() returned %d bytes, want the %d bytes stored", len(got), len(tt.token))
			}

			// a second Set replaces the token
			if err := s.Set("replaced"); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
			if got := s.Get(); got != "replaced" {
				t.Errorf("Get() after second Set() = %q, want %q", got, "replaced")
			}

			if err := s.Delete(); err != nil {
				t.Fatalf("Delete() error = %v", err)
			}
			if got := s.Get(); got != "" {
				t.Errorf("Get() after Delete() returned %d bytes, want empty", len(got))
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("token file exists after Delete(): %v", err)
			}
		})
	}

	t.Run("delete when empty", func(t *testing.T) {
		s, err := NewFileStore(filepath.Join(t.TempDir(), "token"))
		if err != nil {
			t.Fatalf("NewFileStore() error = %v", err)
		}

		if err := s.Delete(); err != nil {
			t.Errorf("Delete() error = %v, want nil", err)
		}
	})

	t.Run("whitespace is trimmed", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(path, []byte("refresh-token\n"), 0600); err != nil {
			t.Fatal(err)
		}
		s, err := NewFileStore(path)
		if err != nil {
			t.Fatalf("NewFileStore() error = %v", err)
		}

		if got := s.Get(); got != "refresh-token" {
			t.Errorf("Get() = %q, want %q", got, "refresh-token")
		}
	})

	t.Run("empty path", func(t *testing.T) {
		if _, err := NewFileStore(""); !errors.Is(err, ErrEmptyPath) {
			t.Errorf("NewFileStore() error = %v, want %v", err, ErrEmptyPath)
		}
	})
}

func TestDiscardStore(t *testing.T) {
	var s DiscardStore

	if err := s.Set("refresh-token"); err != nil {
		t.Errorf("Set() error = %v, want nil", err)
	}
	if got := s.Get(); got != "" {
		t.Errorf("Get() = %q, want empty", got)
	}
	if err := s.Delete(); err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}
