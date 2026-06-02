package persistence

import (
	"encoding/json"
	"fmt"
	"os/user"
	"sync"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"
	"github.com/zalando/go-keyring"
)

var _ Persistence = &KeyringPersistence{}

const keyringService = names.AppName + " User Config"

// KeyringPersistence handles persisting user config to the system keyring
type KeyringPersistence struct {
	mu     sync.RWMutex
	user   string
	config *userconfig.UserConfig
}

// This saves the user part of the config
func (p *KeyringPersistence) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.save()
}

func (p *KeyringPersistence) save() error {
	b, err := json.Marshal(p.config)
	if err != nil {
		return err
	}

	return keyring.Set(keyringService, p.user, string(b))
}

func (p *KeyringPersistence) Get() *userconfig.UserConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config
}

// Set updates and saves the config
func (p *KeyringPersistence) Set(config *userconfig.UserConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	return p.save()
}

func NewKeyring() (Persistence, error) {
	// get user details
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("error looking up user %w", err)
	}

	v, err := keyring.Get(keyringService, u.Username)
	if err != nil {
		return nil, fmt.Errorf("problem loading user config: %w", err)
	}

	var config userconfig.UserConfig
	if err := json.Unmarshal(fmt.Append(nil, v), &config); err != nil {
		return nil, fmt.Errorf("problem parsing user config: %w", err)
	}

	return &KeyringPersistence{user: u.Username, config: &config}, nil
}
