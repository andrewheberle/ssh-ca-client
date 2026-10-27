package config

import (
	"errors"
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

// Registry paths of the config and the policy applied over it
const (
	configRegistryPath = `SOFTWARE\Andrew Heberle\Serverless SSH CA Client`
	policyRegistryPath = `SOFTWARE\Policies\Serverless SSH CA Client`
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

	return loadRegistryConfig(key, configRegistryPath, winreg.LOCAL_MACHINE, policyRegistryPath)
}

// loadRegistryConfig loads the config from path under key, then the policy
// from policyPath under policyKey over it. Either key may be absent, which
// leaves any required settings to be reported missing by validation.
func loadRegistryConfig(key registry.Key, path string, policyKey registry.Key, policyPath string) (*koanf.Koanf, error) {
	k := koanf.New(".")
	if err := loadRegistryKey(k, key, path); err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}

	// Load policy second
	if err := loadRegistryKey(k, policyKey, policyPath); err != nil {
		return nil, fmt.Errorf("could not load policy: %w", err)
	}

	return k, nil
}

// loadRegistryKey loads the values under path into k, skipping it if the key
// does not exist. The provider does not wrap the error from opening the key,
// so it is opened here first to tell a missing key apart from other errors.
func loadRegistryKey(k *koanf.Koanf, key registry.Key, path string) error {
	rk, err := registry.OpenKey(key, path, registry.READ)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	_ = rk.Close()

	return k.Load(winreg.Provider(winreg.Config{Key: key, Path: path, MaxDepth: 2}), nil)
}

// ConfigPath returns the default config location, which on Windows is the
// HKLM registry hive.
func ConfigPath() string {
	return configHiveMachine
}
