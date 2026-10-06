package keyringutil

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestCredentialManager stores values in the real Windows Credential Manager,
// which limits each entry to 2560 bytes. This runs on CI so changes to the
// real limits are noticed.
func TestCredentialManager(t *testing.T) {
	// a unique service so runs cannot interfere with each other or real data
	svc := "ssh-ca-client-keyringutil-test-" + rand.Text()

	// skip if no keyring is available, such as in some sandboxed sessions
	if err := keyring.Set(svc, user, "probe"); err != nil {
		t.Skipf("Windows Credential Manager not available: %v", err)
	}
	_ = keyring.Delete(svc, user)
	t.Cleanup(func() { _ = Delete(svc, user) })

	large := value(10 * 1024)

	t.Run("single entry limit", func(t *testing.T) {
		// confirms values over the limit cannot be stored in one entry
		err := keyring.Set(svc, user, value(windowsLimit+1))
		if !errors.Is(err, keyring.ErrSetDataTooBig) {
			_ = keyring.Delete(svc, user)
			t.Errorf("keyring.Set() over limit error = %v, want %v", err, keyring.ErrSetDataTooBig)
		}
	})

	t.Run("large value", func(t *testing.T) {
		if err := Set(svc, user, large); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		got, err := Get(svc, user)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != large {
			t.Errorf("Get() did not return the stored value")
		}
	})

	t.Run("replace with small value", func(t *testing.T) {
		if err := Set(svc, user, "small"); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		got, err := Get(svc, user)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != "small" {
			t.Errorf("Get() = %q, want %q", got, "small")
		}
		if _, err := keyring.Get(partService(svc, 1), user); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("part left in Credential Manager, err = %v", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		if err := Set(svc, user, large); err != nil {
			t.Fatalf("Set() error = %v", err)
		}
		if err := Delete(svc, user); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}

		if _, err := Get(svc, user); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get() error = %v, want %v", err, ErrNotFound)
		}
		for i := 1; i <= len(split(large)); i++ {
			if _, err := keyring.Get(partService(svc, i), user); !errors.Is(err, keyring.ErrNotFound) {
				t.Errorf("part %d left in Credential Manager, err = %v", i, err)
			}
		}
	})
}
