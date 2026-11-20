package config

import (
	"errors"
	"fmt"
	"log/slog"
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
func loadClientConfig(configpath string, logger *slog.Logger) (*koanf.Koanf, error) {
	key, err := configRegistryKey(configpath)
	if err != nil {
		return nil, err
	}

	return loadRegistryConfig(key, configRegistryPath, winreg.LOCAL_MACHINE, policyRegistryPath, logger)
}

// loadRegistryConfig loads the config from path under key, then the policy
// from policyPath under policyKey over it. Either key may be absent, which
// leaves any required settings to be reported missing by validation. Values
// left in the policy by old Group Policy templates are ignored, with a
// warning to logger.
func loadRegistryConfig(key registry.Key, path string, policyKey registry.Key, policyPath string, logger *slog.Logger) (*koanf.Koanf, error) {
	k := koanf.New(".")
	if _, err := loadRegistryKey(k, key, path, false); err != nil {
		return nil, fmt.Errorf("could not load config: %w", err)
	}

	// Load policy second
	ignored, err := loadRegistryKey(k, policyKey, policyPath, true)
	if err != nil {
		return nil, fmt.Errorf("could not load policy: %w", err)
	}
	if len(ignored) > 0 {
		logger.Warn("ignoring values left by old Group Policy templates, which no release reads; remove them from the GPO or Intune profile that sets them",
			"key", registryKeyPath(policyKey, policyPath),
			"values", ignored,
		)
	}

	return k, nil
}

// loadRegistryKey loads the values under path into k, skipping it if the key
// does not exist, and returns the names of any values ignored as being left
// by old Group Policy templates when policy is set. The provider does not
// wrap the error from opening the key, so it is opened here first to tell a
// missing key apart from other errors.
func loadRegistryKey(k *koanf.Koanf, key registry.Key, path string, policy bool) ([]string, error) {
	rk, err := registry.OpenKey(key, path, registry.READ)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", registryKeyPath(key, path), err)
	}
	_ = rk.Close()

	raw := koanf.New(".")
	if err := raw.Load(winreg.Provider(winreg.Config{Key: key, Path: path, MaxDepth: 2}), nil); err != nil {
		return nil, err
	}

	// checked per key, so an unknown value is reported with the key it is
	// in
	values, ignored, err := registryValues(raw.All(), policy)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", registryKeyPath(key, path), err)
	}

	// a policy value replaces the config value however either is written,
	// as the names are lower-cased
	for name, value := range values {
		if err := k.Set(name, value); err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
	}

	return ignored, nil
}

// registryKeyPath returns path under key as an admin would find it in the
// Registry Editor, such as HKLM\SOFTWARE\Policies\Serverless SSH CA Client
func registryKeyPath(key registry.Key, path string) string {
	switch key {
	case winreg.LOCAL_MACHINE:
		return configHiveMachine + `\` + path
	case winreg.CURRENT_USER:
		return configHiveUser + `\` + path
	default:
		return path
	}
}

// ConfigPath returns the default config location, which on Windows is the
// HKLM registry hive.
func ConfigPath() string {
	return configHiveMachine
}
