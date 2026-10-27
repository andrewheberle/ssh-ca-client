package config

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// errAny is used in tests where an error is expected but its specific value
// is not checked

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

// createTestKey creates path under HKCU with values, which may be a string
// or []string, and removes it when the test ends
func createTestKey(t *testing.T, path string, values map[string]any) {
	t.Helper()

	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
	if err != nil {
		t.Fatalf("registry.CreateKey(%q) error = %v", path, err)
	}
	t.Cleanup(func() {
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Errorf("registry.DeleteKey(%q) error = %v", path, err)
		}
	})
	defer func() { _ = k.Close() }()

	for name, value := range values {
		switch v := value.(type) {
		case string:
			err = k.SetStringValue(name, v)
		case []string:
			err = k.SetStringsValue(name, v)
		default:
			t.Fatalf("unsupported value type %T for %q", value, name)
		}
		if err != nil {
			t.Fatalf("setting %q error = %v", name, err)
		}
	}
}

func Test_loadRegistryConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     map[string]any
		policy     map[string]any
		wantClient string
		wantIssuer string
		wantScopes []string
	}{
		{
			name: "neither key exists",
		},
		{
			name:       "config only",
			config:     map[string]any{"client_id": "config", "scopes": []string{"openid", "email"}},
			wantClient: "config",
			wantScopes: []string{"openid", "email"},
		},
		{
			name:       "policy only",
			policy:     map[string]any{"client_id": "policy", "issuer": "https://idp.example.com/"},
			wantClient: "policy",
			wantIssuer: "https://idp.example.com/",
		},
		{
			name:       "policy applied over config",
			config:     map[string]any{"client_id": "config", "issuer": "https://config.example.com/"},
			policy:     map[string]any{"client_id": "policy"},
			wantClient: "policy",
			wantIssuer: "https://config.example.com/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := fmt.Sprintf(`SOFTWARE\ssh-ca-client-test-%d`, time.Now().UnixNano())
			configPath := base + `-config`
			policyPath := base + `-policy`
			if tt.config != nil {
				createTestKey(t, configPath, tt.config)
			}
			if tt.policy != nil {
				createTestKey(t, policyPath, tt.policy)
			}

			k, err := loadRegistryConfig(registry.CURRENT_USER, configPath, registry.CURRENT_USER, policyPath)
			if err != nil {
				t.Fatalf("loadRegistryConfig() error = %v", err)
			}
			if got := k.String("client_id"); got != tt.wantClient {
				t.Errorf("client_id = %q, want %q", got, tt.wantClient)
			}
			if got := k.String("issuer"); got != tt.wantIssuer {
				t.Errorf("issuer = %q, want %q", got, tt.wantIssuer)
			}
			if got := k.Strings("scopes"); !slices.Equal(got, tt.wantScopes) {
				t.Errorf("scopes = %q, want %q", got, tt.wantScopes)
			}
		})
	}
}
