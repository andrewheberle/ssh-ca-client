//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
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

func loadSystemConfig(name string) (SystemConfig, error) {
	y, err := os.ReadFile(name)
	if err != nil {
		return SystemConfig{}, err
	}

	var config SystemConfig
	if err := yaml.UnmarshalStrict(y, &config); err != nil {
		return SystemConfig{}, fmt.Errorf("problem parsing system config: %w", err)
	}

	if config.TrustedCertificateAuthority != "" {
		ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.TrustedCertificateAuthority))
		if err != nil {
			return SystemConfig{}, fmt.Errorf("problem parsing trusted_ca: %w", err)
		}

		config.ca = ca
	}

	return config, nil
}
