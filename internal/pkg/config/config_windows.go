package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/v2"
	"github.com/pda0/koanf-winreg/v2/winreg"
	"golang.org/x/sys/windows/registry"
)

// Registry hives accepted as the config location on Windows
const (
	configHiveMachine = "HKLM"
	configHiveUser    = "HKCU"
)

// configRegistryKey returns the registry hive for configpath, which must be
// either HKLM or HKCU (case insensitive).
func configRegistryKey(configpath string) (registry.Key, error) {
	switch strings.ToUpper(configpath) {
	case configHiveMachine:
		return winreg.LOCAL_MACHINE, nil
	case configHiveUser:
		return winreg.CURRENT_USER, nil
	default:
		return 0, fmt.Errorf("only %s or %s is accepted: %s", configHiveMachine, configHiveUser, configpath)
	}
}

// Loading config on Windows is from the registry so configpath denotes
// must be either HKLM or HKCU.
func loadClientConfig(configpath string) (*koanf.Koanf, error) {
	key, err := configRegistryKey(configpath)
	if err != nil {
		return nil, err
	}

	k := koanf.New(".")
	if err := k.Load(winreg.Provider(winreg.Config{Key: key, Path: "SOFTWARE\\Andrew Heberle\\Serverless SSH CA Client", MaxDepth: 2}), nil); err != nil {
		return nil, fmt.Errorf("could not load %s config: %w", strings.ToUpper(configpath), err)
	}

	// Load policy second
	if err := k.Load(winreg.Provider(winreg.Config{Key: winreg.LOCAL_MACHINE, Path: "SOFTWARE\\Policies\\Serverless SSH CA Client", MaxDepth: 2}), nil); err != nil {
		return nil, fmt.Errorf("could not load policy: %w", err)
	}

	return k, nil
}

// ConfigPath returns the default config location, which on Windows is the
// HKLM registry hive.
func ConfigPath() string {
	return configHiveMachine
}
