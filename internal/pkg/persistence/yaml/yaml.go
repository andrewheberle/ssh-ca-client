package yamlpersistence

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/persistence"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"
	"sigs.k8s.io/yaml"
)

var _ persistence.Persistence = &YamlPersistence{}

// YamlPersistence handles persisting user config to disk as a YAML file
type YamlPersistence struct {
	mu     sync.RWMutex
	name   string
	config *userconfig.UserConfig
}

// This saves the user part of the config
func (p *YamlPersistence) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.save()
}

func (p *YamlPersistence) save() error {
	y, err := yaml.Marshal(p.config)
	if err != nil {
		return err
	}

	return atomic.WriteFile(p.name, bytes.NewReader(y), atomic.FileMode(0600))
}

func (p *YamlPersistence) Get() *userconfig.UserConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.config
}

// Set updates and saves the config
func (p *YamlPersistence) Set(config *userconfig.UserConfig) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	return p.save()
}

func New(name string) (*YamlPersistence, error) {
	config, err := loadUserConfig(name)
	if err != nil {
		return nil, fmt.Errorf("problem loading user config: %w", err)
	}

	return &YamlPersistence{name: name, config: config}, nil
}

func loadUserConfig(name string) (*userconfig.UserConfig, error) {
	y, err := os.ReadFile(name)
	if err != nil {
		// the user config missing is not fatal
		if errors.Is(err, os.ErrNotExist) {
			return &userconfig.UserConfig{}, nil
		}

		// otherwise return the error
		return nil, err
	}

	var c userconfig.UserConfig
	if err := yaml.UnmarshalStrict(y, &c); err != nil {
		return nil, fmt.Errorf("problem parsing user config: %w", err)
	}

	return &c, nil
}
