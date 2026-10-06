package tokenstore

import (
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
