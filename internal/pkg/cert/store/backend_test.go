package store

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/keyringutil"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/zalando/go-keyring"
)

// backends returns a fresh instance of each [Backend] for contract tests
func backends(t *testing.T) map[string]func(t *testing.T) Backend {
	t.Helper()

	return map[string]func(t *testing.T) Backend{
		"file": func(t *testing.T) Backend {
			return NewFileBackend(filepath.Join(t.TempDir(), "id_ecdsa"))
		},
		"keyring": func(t *testing.T) Backend {
			keyring.MockInit()

			return NewKeyringBackend("test")
		},
		"memory": func(t *testing.T) Backend {
			return NewMemoryBackend()
		},
	}
}

func TestBackend_Contract(t *testing.T) {
	for name, newBackend := range backends(t) {
		t.Run(name, func(t *testing.T) {
			for _, slot := range []Slot{Key, Cert} {
				t.Run(slot.String(), func(t *testing.T) {
					t.Run("empty slot is not found", func(t *testing.T) {
						b := newBackend(t)

						if _, err := b.Get(slot); !errors.Is(err, ErrNotFound) {
							t.Errorf("Get() error = %v, want %v", err, ErrNotFound)
						}
					})

					t.Run("round trip", func(t *testing.T) {
						b := newBackend(t)
						want := []byte("value\n")

						if err := b.Put(slot, want); err != nil {
							t.Fatalf("Put() error = %v", err)
						}
						got, err := b.Get(slot)
						if err != nil {
							t.Fatalf("Get() error = %v", err)
						}
						if !bytes.Equal(got, want) {
							t.Errorf("Get() = %q, want %q", got, want)
						}
					})

					t.Run("put replaces", func(t *testing.T) {
						b := newBackend(t)

						if err := b.Put(slot, []byte("first")); err != nil {
							t.Fatalf("Put() error = %v", err)
						}
						if err := b.Put(slot, []byte("second")); err != nil {
							t.Fatalf("Put() error = %v", err)
						}
						got, err := b.Get(slot)
						if err != nil {
							t.Fatalf("Get() error = %v", err)
						}
						if string(got) != "second" {
							t.Errorf("Get() = %q, want %q", got, "second")
						}
					})

					t.Run("delete", func(t *testing.T) {
						b := newBackend(t)

						if err := b.Put(slot, []byte("value")); err != nil {
							t.Fatalf("Put() error = %v", err)
						}
						if err := b.Delete(slot); err != nil {
							t.Fatalf("Delete() error = %v", err)
						}
						if _, err := b.Get(slot); !errors.Is(err, ErrNotFound) {
							t.Errorf("Get() after Delete() error = %v, want %v", err, ErrNotFound)
						}
					})

					t.Run("delete empty slot", func(t *testing.T) {
						b := newBackend(t)

						if err := b.Delete(slot); err != nil {
							t.Errorf("Delete() error = %v, want nil", err)
						}
					})
				})
			}

			t.Run("slots are independent", func(t *testing.T) {
				b := newBackend(t)

				if err := b.Put(Key, []byte("key")); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
				if _, err := b.Get(Cert); !errors.Is(err, ErrNotFound) {
					t.Errorf("Get(Cert) error = %v, want %v", err, ErrNotFound)
				}
				if err := b.Delete(Cert); err != nil {
					t.Fatalf("Delete(Cert) error = %v", err)
				}
				if got, err := b.Get(Key); err != nil || string(got) != "key" {
					t.Errorf("Get(Key) = %q, %v, want %q", got, err, "key")
				}
			})
		})
	}
}

func TestFileBackend(t *testing.T) {
	t.Run("paths", func(t *testing.T) {
		keypath := filepath.Join(t.TempDir(), "id_ecdsa")
		b := NewFileBackend(keypath)

		if err := b.Put(Key, []byte("key")); err != nil {
			t.Fatalf("Put(Key) error = %v", err)
		}
		if err := b.Put(Cert, []byte("cert")); err != nil {
			t.Fatalf("Put(Cert) error = %v", err)
		}

		for path, want := range map[string]string{keypath: "key", keypath + "-cert.pub": "cert"} {
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", path, err)
			}
			if string(got) != want {
				t.Errorf("%s = %q, want %q", path, got, want)
			}
		}
	})

	t.Run("directory does not exist", func(t *testing.T) {
		b := NewFileBackend(filepath.Join(t.TempDir(), "missing", "id_ecdsa"))

		if err := b.Put(Key, []byte("key")); err == nil {
			t.Errorf("Put() error = nil, want error")
		}
	})

	t.Run("path cannot be replaced or removed", func(t *testing.T) {
		keypath := filepath.Join(t.TempDir(), "id_ecdsa")
		b := NewFileBackend(keypath)

		// a non-empty directory at the certificate path cannot be replaced
		// or removed
		if err := os.MkdirAll(filepath.Join(keypath+"-cert.pub", "child"), 0700); err != nil {
			t.Fatalf("could not create directory: %v", err)
		}

		if err := b.Put(Cert, []byte("cert")); err == nil {
			t.Errorf("Put() error = nil, want error")
		}
		if err := b.Delete(Cert); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Delete() error = %v, want error other than %v", err, ErrNotFound)
		}
	})
}

func TestKeyringBackend(t *testing.T) {
	t.Run("service names", func(t *testing.T) {
		// existing installs keep their key and certificate under these
		// names, so they must not change
		keyring.MockInit()
		b := NewKeyringBackend("someone")

		if err := b.Put(Key, []byte("key")); err != nil {
			t.Fatalf("Put(Key) error = %v", err)
		}
		if err := b.Put(Cert, []byte("cert")); err != nil {
			t.Fatalf("Put(Cert) error = %v", err)
		}

		for service, want := range map[string]string{
			names.AppName + " Key Store Key":  "key",
			names.AppName + " Key Store Cert": "cert",
		} {
			got, err := keyringutil.Get(service, "someone")
			if err != nil {
				t.Fatalf("keyringutil.Get(%q) error = %v", service, err)
			}
			if got != want {
				t.Errorf("%q = %q, want %q", service, got, want)
			}
		}
	})

	t.Run("large value is stored in parts", func(t *testing.T) {
		// a value larger than a single Windows Credential Manager entry, such
		// as an RSA-3072 key, is stored in parts
		keyring.MockInit()
		b := NewKeyringBackend("someone")
		want := []byte(strings.Repeat("k", keyringutil.ChunkSize*2+1))

		if err := b.Put(Key, want); err != nil {
			t.Fatalf("Put() error = %v", err)
		}
		if _, err := keyring.Get(names.AppName+" Key Store Key #1", "someone"); err != nil {
			t.Fatalf("value was not stored in parts: %v", err)
		}

		got, err := b.Get(Key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Get() returned %d bytes, want %d", len(got), len(want))
		}
	})

	t.Run("keyring error", func(t *testing.T) {
		keyringErr := errors.New("keyring unavailable")
		keyring.MockInitWithError(keyringErr)
		b := NewKeyringBackend("someone")

		if err := b.Put(Key, []byte("key")); !errors.Is(err, keyringErr) {
			t.Errorf("Put() error = %v, want %v", err, keyringErr)
		}
		if _, err := b.Get(Key); !errors.Is(err, keyringErr) || errors.Is(err, ErrNotFound) {
			t.Errorf("Get() error = %v, want %v and not %v", err, keyringErr, ErrNotFound)
		}
		if err := b.Delete(Key); !errors.Is(err, keyringErr) {
			t.Errorf("Delete() error = %v, want %v", err, keyringErr)
		}
	})
}

func TestNewKeyring(t *testing.T) {
	keyring.MockInit()

	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() error = %v", err)
	}

	s, err := NewKeyring(newCA(t).PublicKey(), WithAgent(newAgent()))
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	if err := s.GeneratePrivateKey(); err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}

	// the key is kept for the current user
	if _, err := keyringutil.Get(names.AppName+" Key Store Key", u.Username); err != nil {
		t.Errorf("key not stored for current user: %v", err)
	}

	// the keyring store replaces an existing key
	if err := s.GeneratePrivateKey(); err != nil {
		t.Errorf("second GeneratePrivateKey() error = %v, want nil", err)
	}
}

func TestNewFile(t *testing.T) {
	keypath := filepath.Join(t.TempDir(), "id_ecdsa")

	s, err := NewFile(newCA(t).PublicKey(), keypath, WithAgent(newAgent()))
	if err != nil {
		t.Fatalf("NewFile() error = %v", err)
	}
	if _, err := os.Stat(keypath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key file exists after NewFile(), err = %v", err)
	}

	if err := s.GeneratePrivateKey(); err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}
	if _, err := os.Stat(keypath); err != nil {
		t.Errorf("key file not written: %v", err)
	}

	// the file store never replaces an existing key, such as a host key
	if err := s.GeneratePrivateKey(); !errors.Is(err, ErrPrivateKeyExists) {
		t.Errorf("second GeneratePrivateKey() error = %v, want %v", err, ErrPrivateKeyExists)
	}
}
