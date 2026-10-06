//go:build !windows

package config

import (
	"fmt"
	"path/filepath"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

func loadClientConfig(configpath string) (*koanf.Koanf, error) {
	k := koanf.New(".")
	if err := k.Load(file.Provider(configpath), yaml.Parser()); err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}

	return k, nil
}

func ConfigPath() string {
	return filepath.Join("/etc", names.AppName, "config.yml")
}
