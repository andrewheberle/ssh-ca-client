// Package tokenstore persists the OIDC refresh token between runs so a new
// certificate can be requested without an interactive login.
package tokenstore

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/keyringutil"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

// ErrEmptyPath is returned by [NewFileStore] when no path is given
var ErrEmptyPath = errors.New("token store path was empty")

// Store persists a single refresh token
type Store interface {
	// Delete removes the stored token. Deleting when no token is stored is
	// not an error.
	Delete() error
	// Get returns the stored token, or an empty string if no token is
	// stored or it could not be read.
	Get() string
	// Set stores v, replacing any existing token.
	Set(v string) error
}

// KeyringStore is a [Store] that keeps the token in the system keyring (such
// as Windows Credential Manager, macOS Keychain or the Secret Service on
// Linux) under an entry for the current user.
type KeyringStore struct {
	service string
	user    string
}

var _ Store = &KeyringStore{}

// NewKeyringStore creates a [KeyringStore] for the current user
func NewKeyringStore() (*KeyringStore, error) {
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	return &KeyringStore{
		user:    user.Username,
		service: names.AppName + " Refresh Token",
	}, nil
}

// Delete removes the token from the keyring. Nothing is done if the keyring
// holds no token.
func (s *KeyringStore) Delete() error {
	if err := keyringutil.Delete(s.service, s.user); err != nil {
		if !errors.Is(err, keyringutil.ErrNotFound) {
			return err
		}
	}

	return nil
}

// Get returns the token from the keyring, or an empty string if there is none
// or the keyring could not be read
func (s *KeyringStore) Get() string {
	v, _ := keyringutil.Get(s.service, s.user)
	return v
}

// Set stores v in the keyring, replacing any existing token
func (s *KeyringStore) Set(v string) error {
	return keyringutil.Set(s.service, s.user, v)
}

// FileStore is a [Store] that keeps the token in a plain file, for systems
// without a keyring such as servers. The token is not encrypted, so it is only
// protected by the permissions on the file, which is created readable and
// writable only by its owner. On Windows those permissions are not applied, so
// the file is protected only by the access control list it inherits.
type FileStore struct {
	path string

	mu sync.RWMutex
}

var _ Store = &FileStore{}

// NewFileStore creates a [FileStore] that keeps the token in the file at path.
// The file does not need to exist until [FileStore.Set] is called.
func NewFileStore(path string) (*FileStore, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}

	return &FileStore{path: path}, nil
}

// Delete removes the token file. Nothing is done if the file does not exist.
func (s *FileStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("could not delete token file: %w", err)
	}

	return nil
}

// Get returns the token from the file, or an empty string if the file does
// not exist or could not be read. Surrounding whitespace, such as a trailing
// newline added when the file was edited by hand, is removed.
func (s *FileStore) Get() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, err := os.ReadFile(s.path)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}

// Set writes v to the file, replacing any existing token. The file is
// replaced atomically, so a failed write does not leave a partial token, and
// the directory holding it is created, readable only by its owner, if it does
// not exist.
func (s *FileStore) Set(v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("could not create token directory: %w", err)
	}

	if err := atomic.WriteFile(s.path, strings.NewReader(v), atomic.FileMode(0600)); err != nil {
		return fmt.Errorf("could not write token file: %w", err)
	}

	return nil
}

// DiscardStore is a [Store] that does not persist the token, so a login is
// needed on each run
type DiscardStore struct{}

var _ Store = &DiscardStore{}

// NewDiscardStore creates a new [DiscardStore] however, new([DiscardStore])
// (or just declaring a [DiscardStore] variable) is sufficient to initialize a [DiscardStore].
func NewDiscardStore() (*DiscardStore, error) {
	return &DiscardStore{}, nil
}

// Delete does nothing and always succeeds
func (s *DiscardStore) Delete() error {
	return nil
}

// Get always returns an empty string
func (s *DiscardStore) Get() string {
	return ""
}

// Set discards v and always succeeds
func (s *DiscardStore) Set(v string) error {
	return nil
}
