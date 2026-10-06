package config

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"golang.org/x/sys/windows/registry"
)

func TestConfigDirs(t *testing.T) {
	// set variables so we can test result
	t.Setenv("AppData", "C:\\Users\\testuser\\AppData")
	t.Setenv("ProgramData", "C:\\ProgramData")

	tests := []struct {
		name    string // description of this test case
		want    string
		want2   string
		wantErr bool
	}{
		{"test results", filepath.Join("C:\\Users\\testuser\\AppData", names.AppName), filepath.Join("C:\\ProgramData", names.AppName), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2, gotErr := ConfigDirs()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ConfigDirs() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ConfigDirs() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("ConfigDirs() = %v, want %v", got, tt.want)
			}
			if got2 != tt.want2 {
				t.Errorf("ConfigDirs() = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func TestLogDir(t *testing.T) {
	// set variable so we can test result
	t.Setenv("AppData", "C:\\Users\\testuser\\AppData")

	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"test results", filepath.Join("C:\\Users\\testuser\\AppData", names.AppName), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LogDir()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LogDir() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LogDir() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("LogDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
