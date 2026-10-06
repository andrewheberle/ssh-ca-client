package tokenstore

import (
	"errors"
	"os/user"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/zalando/go-keyring"
)

type Store interface {
	Delete() error
	Get() string
	Set(v string) error
}

type KeyringStore struct {
	service string
	user    string
}

var _ Store = &KeyringStore{}

func NewKeyringStore() (*KeyringStore, error) {
	user, err := user.Current()
	if err != nil {
		return nil, err
	}

	return &KeyringStore{
		user:   user.Username,
		service: names.AppName + " Refresh Token",
	}, nil
}

func (s *KeyringStore) Delete() error {
	if err := keyring.Delete(s.service, s.user); err != nil {
		if !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
	}

	return nil
}

func (s *KeyringStore) Get() string {
	v, _ := keyring.Get(s.service, s.user)
	return v
}

func (s *KeyringStore) Set(v string) error {
	return keyring.Set(s.service, s.user, v)
}

type DiscardStore struct{}

var _ Store = &DiscardStore{}

// NewDiscardStore creates a new [DiscardStore] however, new([DiscardStore])
// (or just declaring a [DiscardStore] variable) is sufficient to initialize a [DiscardStore].
func NewDiscardStore() (*DiscardStore, error) {
	return &DiscardStore{}, nil
}

func (s *DiscardStore) Delete() error {
	return nil
}

func (s *DiscardStore) Get() string {
	return ""
}

// Set discards v and always succeeds
func (s *DiscardStore) Set(v string) error {
	return nil
}
