//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

func LogDir() (string, error) {
	// are we running as a snap?
	if os.Getenv("SNAP_USER_COMMON") != "" && os.Getenv("IGNORE_SNAP_DURING_TEST") == "" {
		return os.Getenv("SNAP_USER_COMMON"), nil
	}

	user, _, err := ConfigDirs()

	return user, err
}

func ConfigDirs() (user, system string, err error) {
	// are we running as a snap?
	if os.Getenv("SNAP_USER_DATA") != "" && os.Getenv("IGNORE_SNAP_DURING_TEST") == "" {
		return os.Getenv("SNAP_USER_DATA"), filepath.Join("/etc", names.AppName), nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "/dev/null/nonexistent", filepath.Join("/etc", names.AppName), nil
	}

	return filepath.Join(dir, names.AppName), filepath.Join("/etc", names.AppName), nil
}

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
