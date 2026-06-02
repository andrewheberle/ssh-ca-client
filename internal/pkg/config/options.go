package config

import (
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/persistence"
	"github.com/andrewheberle/ssh-ca-client/pkg/protect"
)

// Options for [*Config]
type ConfigOption func(*Config)

func WithPersistence(p persistence.Persistence) ConfigOption {
	return func(c *Config) {
		c.persistence = p
	}
}

func WithProtector(p protect.Protector) ConfigOption {
	return func(c *Config) {
		c.protector = p
	}
}
