//go:build !windows

package keyringutil

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestGoKeyring checks the default backend uses go-keyring, using its mock.
//
// This does not run on Windows because keyring.MockInit permanently replaces
// the go-keyring provider for the rest of the test binary, which would make
// TestCredentialManager use the mock instead of the real Credential Manager.
// On Windows the default backend is tested by TestCredentialManager.
func TestGoKeyring(t *testing.T) {
	// the default backend uses go-keyring, which is mocked here
	keyring.MockInit()

	want := value(10 * 1024)
	if err := Set(service, user, want); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	got, err := Get(service, user)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got != want {
		t.Errorf("Get() did not return the stored value")
	}

	if err := Delete(service, user); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := keyring.Get(partService(service, 1), user); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("part still in keyring after Delete(), err = %v", err)
	}
}
