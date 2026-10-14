package store

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/keyringutil"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

// ErrNotFound is returned, possibly wrapped, by [Backend.Get] when nothing is
// stored in a slot
var ErrNotFound = errors.New("not found in store backend")

// Slot identifies one of the two values a [Store] keeps in its [Backend]
type Slot int

const (
	// Key is the slot holding the PEM encoded private key
	Key Slot = iota
	// Cert is the slot holding the certificate in authorized_keys format
	Cert
)

func (s Slot) String() string {
	switch s {
	case Key:
		return "key"
	case Cert:
		return "cert"
	}

	return fmt.Sprintf("Slot(%d)", int(s))
}

// Backend is where a [Store] keeps its private key and certificate. A
// Backend only stores bytes; validation, parsing, locking and policy are
// the job of the [Store].
type Backend interface {
	// Get returns the value in slot. An error wrapping [ErrNotFound] is
	// returned when the slot is empty.
	Get(slot Slot) ([]byte, error)
	// Put stores value in slot, replacing any existing value.
	Put(slot Slot, value []byte) error
	// Delete empties slot. Deleting an empty slot is not an error.
	Delete(slot Slot) error
}

// FileBackend is a [Backend] that keeps the private key in a file and the
// certificate alongside it with a "-cert.pub" suffix, as OpenSSH expects.
// The private key file is only readable by its owner.
type FileBackend struct {
	keypath string
}

var _ Backend = &FileBackend{}

// NewFileBackend returns a [FileBackend] for the private key at keypath
func NewFileBackend(keypath string) *FileBackend {
	return &FileBackend{keypath: keypath}
}

func (b *FileBackend) path(slot Slot) string {
	if slot == Cert {
		return b.keypath + "-cert.pub"
	}

	return b.keypath
}

func (b *FileBackend) mode(slot Slot) fs.FileMode {
	if slot == Cert {
		return 0644
	}

	return 0600
}

func (b *FileBackend) Get(slot Slot) ([]byte, error) {
	v, err := os.ReadFile(b.path(slot))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	return v, err
}

func (b *FileBackend) Put(slot Slot, value []byte) error {
	return atomic.WriteFile(b.path(slot), bytes.NewReader(value), atomic.FileMode(b.mode(slot)))
}

func (b *FileBackend) Delete(slot Slot) error {
	if err := os.Remove(b.path(slot)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

const (
	keyringService     = names.AppName + " Key Store"
	keyringKeyService  = keyringService + " Key"
	keyringCertService = keyringService + " Cert"
)

// KeyringBackend is a [Backend] that keeps the private key and certificate
// in the system keyring (such as Windows Credential Manager, macOS Keychain
// or the Secret Service on Linux) under entries for a user. Values too large
// for a single entry are split into parts.
type KeyringBackend struct {
	user string
}

var _ Backend = &KeyringBackend{}

// NewKeyringBackend returns a [KeyringBackend] for user
func NewKeyringBackend(user string) *KeyringBackend {
	return &KeyringBackend{user: user}
}

func (b *KeyringBackend) service(slot Slot) string {
	if slot == Cert {
		return keyringCertService
	}

	return keyringKeyService
}

func (b *KeyringBackend) Get(slot Slot) ([]byte, error) {
	v, err := keyringutil.Get(b.service(slot), b.user)
	if errors.Is(err, keyringutil.ErrNotFound) {
		return nil, fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	if err != nil {
		return nil, err
	}

	return []byte(v), nil
}

func (b *KeyringBackend) Put(slot Slot, value []byte) error {
	return keyringutil.Set(b.service(slot), b.user, string(value))
}

func (b *KeyringBackend) Delete(slot Slot) error {
	if err := keyringutil.Delete(b.service(slot), b.user); err != nil && !errors.Is(err, keyringutil.ErrNotFound) {
		return err
	}

	return nil
}

// MemoryBackend is a [Backend] that keeps values in memory, for tests
type MemoryBackend struct {
	mu     sync.RWMutex
	values map[Slot][]byte
}

var _ Backend = &MemoryBackend{}

// NewMemoryBackend returns an empty [MemoryBackend]
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{values: make(map[Slot][]byte)}
}

func (b *MemoryBackend) Get(slot Slot) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	v, ok := b.values[slot]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, slot)
	}

	return bytes.Clone(v), nil
}

func (b *MemoryBackend) Put(slot Slot, value []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.values[slot] = bytes.Clone(value)

	return nil
}

func (b *MemoryBackend) Delete(slot Slot) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.values, slot)

	return nil
}
