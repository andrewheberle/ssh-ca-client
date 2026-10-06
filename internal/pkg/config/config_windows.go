package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/knadh/koanf/v2"
	"github.com/pda0/koanf-winreg/v2/winreg"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows/registry"
	"sigs.k8s.io/yaml"
)

var (
	ErrConfigIncomplete = errors.New("config was incomplete")
)

func LogDir() (string, error) {
	user, _, err := ConfigDirs()

	return user, err
}

func ConfigDirs() (user, system string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}

	return filepath.Join(dir, names.AppName), filepath.Join(os.Getenv("ProgramData"), names.AppName), nil
}

func loadPolicy() SystemConfig {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "Software\\Policies\\Serverless SSH CA Client", registry.QUERY_VALUE)
	if err != nil {
		return SystemConfig{}
	}
	defer func() {
		_ = k.Close()
	}()

	var config SystemConfig
	clientId, _, err := k.GetStringValue("ClientID")
	if err == nil {
		config.ClientID = clientId
	}

	issuer, _, err := k.GetStringValue("Issuer")
	if err == nil {
		config.Issuer = issuer
	}

	scopes, _, err := k.GetStringsValue("Scopes")
	if err == nil {
		config.Scopes = scopes
	}

	redirectURL, _, err := k.GetStringValue("RedirectURL")
	if err == nil {
		config.RedirectURL = redirectURL
	}

	trustedCA, _, err := k.GetStringValue("TrustedCertificateAuthority")
	if err == nil {
		config.TrustedCertificateAuthority = trustedCA
	}

	certificateAuthorityURL, _, err := k.GetStringValue("CertificateAuthorityURL")
	if err == nil {
		config.CertificateAuthorityURL = certificateAuthorityURL
	}

	return config
}

func loadConfig(name string) SystemConfig {
	y, err := os.ReadFile(name)
	if err != nil {
		return SystemConfig{}
	}

	var config SystemConfig
	if err := yaml.UnmarshalStrict(y, &config); err != nil {
		return SystemConfig{}
	}

	return config
}

// Function merges policy -> base with values set via policy overridding values
// in base.
//
// An error is returned if values are not set after merge
func mergeConfig(policy, base SystemConfig) (SystemConfig, error) {
	if policy.ClientID != "" {
		base.ClientID = policy.ClientID
	}

	if policy.Issuer != "" {
		base.Issuer = policy.Issuer
	}

	if len(policy.Scopes) > 0 {
		base.Scopes = policy.Scopes
	}

	if policy.RedirectURL != "" {
		base.RedirectURL = policy.RedirectURL
	}

	if policy.CertificateAuthorityURL != "" {
		base.CertificateAuthorityURL = policy.CertificateAuthorityURL
	}

	if base.ClientID == "" || base.Issuer == "" || len(base.Scopes) == 0 || base.RedirectURL == "" || base.CertificateAuthorityURL == "" {
		return SystemConfig{}, ErrConfigIncomplete
	}

	if policy.TrustedCertificateAuthority != "" {
		base.TrustedCertificateAuthority = policy.TrustedCertificateAuthority
	}

	if base.TrustedCertificateAuthority != "" {
		ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(base.TrustedCertificateAuthority))
		if err != nil {
			return SystemConfig{}, fmt.Errorf("problem parsing trusted_ca: %w", err)
		}

		base.ca = ca
	}

	return base, nil
}

func loadSystemConfig(name string) (SystemConfig, error) {
	local := loadConfig(name)
	policy := loadPolicy()

	return mergeConfig(policy, local)
}

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
