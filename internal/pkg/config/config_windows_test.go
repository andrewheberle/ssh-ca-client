package config

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// errAny is used in tests where an error is expected but its specific value
// is not checked
var errAny = errors.New("any error")

func TestConfigPath(t *testing.T) {
	if got := ConfigPath(); got != "HKLM" {
		t.Errorf("ConfigPath() = %q, want %q", got, "HKLM")
	}

	// the default must be accepted when loading the config, otherwise the CLI
	// fails when --config is not set
	key, err := configRegistryKey(ConfigPath())
	if err != nil {
		t.Fatalf("configRegistryKey(ConfigPath()) error = %v", err)
	}
	if key != registry.LOCAL_MACHINE {
		t.Errorf("configRegistryKey(ConfigPath()) = %v, want HKEY_LOCAL_MACHINE", key)
	}
}

func Test_configRegistryKey(t *testing.T) {
	tests := []struct {
		configpath string
		want       registry.Key
		wantErr    bool
	}{
		{"HKLM", registry.LOCAL_MACHINE, false},
		{"hklm", registry.LOCAL_MACHINE, false},
		{"HKCU", registry.CURRENT_USER, false},
		{"Hkcu", registry.CURRENT_USER, false},
		{"HLKM", 0, true},
		{"HKEY_LOCAL_MACHINE", 0, true},
		{`C:\ProgramData\Serverless SSH CA Client\config.yml`, 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.configpath, func(t *testing.T) {
			got, err := configRegistryKey(tt.configpath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("configRegistryKey() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("configRegistryKey() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("invalid location is rejected before loading", func(t *testing.T) {
		if _, err := loadClientConfig("HLKM"); err == nil {
			t.Errorf("loadClientConfig() error = nil, want error")
		}
	})
}
