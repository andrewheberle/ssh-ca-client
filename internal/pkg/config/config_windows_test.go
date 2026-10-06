package config

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"golang.org/x/crypto/ssh"
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

func Test_mergeConfig(t *testing.T) {
	const (
		testCA    = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgJTsYW+tHl0lz/rnO8djbwq0B3uZ5sGugXU6Ha5S2rTdzMDgit2DO+hoivdT4I07rMrRtmFI179wUY06gIf00="
		altTestCA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVtQh5Agnm9nknP29cudULJc2Fdp0ok65tui/+GJ8x/"
		badCA     = "not a valid public key"
	)

	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testCA))
	if err != nil {
		panic(err)
	}

	altCA, _, _, _, err := ssh.ParseAuthorizedKey([]byte(altTestCA))
	if err != nil {
		panic(err)
	}

	// complete returns a config with all required values set, with any
	// modifications applied by fn
	complete := func(fn func(*SystemConfig)) SystemConfig {
		c := SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}
		if fn != nil {
			fn(&c)
		}
		return c
	}

	tests := []struct {
		name    string
		policy  SystemConfig
		config  SystemConfig
		want    SystemConfig
		wantErr error
	}{
		{"incomplete", SystemConfig{}, SystemConfig{}, SystemConfig{}, ErrConfigIncomplete},
		{"empty policy", SystemConfig{}, complete(nil), complete(nil), nil},
		{"empty config", complete(nil), SystemConfig{}, complete(nil), nil},
		{"override all from policy", SystemConfig{Issuer: "overridden", ClientID: "overridden", Scopes: []string{"overridden"}, RedirectURL: "overridden", CertificateAuthorityURL: "overridden"}, complete(nil), SystemConfig{Issuer: "overridden", ClientID: "overridden", Scopes: []string{"overridden"}, RedirectURL: "overridden", CertificateAuthorityURL: "overridden"}, nil},
		{"override just issuer from policy", SystemConfig{Issuer: "overridden"}, complete(nil), SystemConfig{Issuer: "overridden", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, nil},

		// each individual field can be overridden by policy without affecting others
		{"override just client id from policy", SystemConfig{ClientID: "overridden"}, complete(nil), complete(func(c *SystemConfig) { c.ClientID = "overridden" }), nil},
		{"override just scopes from policy", SystemConfig{Scopes: []string{"openid", "email"}}, complete(nil), complete(func(c *SystemConfig) { c.Scopes = []string{"openid", "email"} }), nil},
		{"override just redirect url from policy", SystemConfig{RedirectURL: "overridden"}, complete(nil), complete(func(c *SystemConfig) { c.RedirectURL = "overridden" }), nil},
		{"override just ca url from policy", SystemConfig{CertificateAuthorityURL: "overridden"}, complete(nil), complete(func(c *SystemConfig) { c.CertificateAuthorityURL = "overridden" }), nil},

		// scopes from policy replace rather than append to config
		{"policy scopes replace config scopes", SystemConfig{Scopes: []string{"email"}}, complete(func(c *SystemConfig) { c.Scopes = []string{"openid", "profile"} }), complete(func(c *SystemConfig) { c.Scopes = []string{"email"} }), nil},
		// an empty (but non-nil) scopes slice in policy does not clear config scopes
		{"empty policy scopes do not override", SystemConfig{Scopes: []string{}}, complete(nil), complete(nil), nil},

		// each required value missing after merge results in an error
		{"missing issuer", SystemConfig{}, complete(func(c *SystemConfig) { c.Issuer = "" }), SystemConfig{}, ErrConfigIncomplete},
		{"missing client id", SystemConfig{}, complete(func(c *SystemConfig) { c.ClientID = "" }), SystemConfig{}, ErrConfigIncomplete},
		{"missing scopes", SystemConfig{}, complete(func(c *SystemConfig) { c.Scopes = nil }), SystemConfig{}, ErrConfigIncomplete},
		{"empty scopes", SystemConfig{}, complete(func(c *SystemConfig) { c.Scopes = []string{} }), SystemConfig{}, ErrConfigIncomplete},
		{"missing redirect url", SystemConfig{}, complete(func(c *SystemConfig) { c.RedirectURL = "" }), SystemConfig{}, ErrConfigIncomplete},
		{"missing ca url", SystemConfig{}, complete(func(c *SystemConfig) { c.CertificateAuthorityURL = "" }), SystemConfig{}, ErrConfigIncomplete},

		// required values split across policy and config are merged
		{"missing issuer supplied by policy", SystemConfig{Issuer: "iss"}, complete(func(c *SystemConfig) { c.Issuer = "" }), complete(nil), nil},
		{"missing client id supplied by policy", SystemConfig{ClientID: "id"}, complete(func(c *SystemConfig) { c.ClientID = "" }), complete(nil), nil},
		{"missing scopes supplied by policy", SystemConfig{Scopes: []string{"openid"}}, complete(func(c *SystemConfig) { c.Scopes = nil }), complete(nil), nil},
		{"missing redirect url supplied by policy", SystemConfig{RedirectURL: "redirect"}, complete(func(c *SystemConfig) { c.RedirectURL = "" }), complete(nil), nil},
		{"missing ca url supplied by policy", SystemConfig{CertificateAuthorityURL: "ca"}, complete(func(c *SystemConfig) { c.CertificateAuthorityURL = "" }), complete(nil), nil},
		{"split across policy and config", SystemConfig{Issuer: "iss", Scopes: []string{"openid"}, CertificateAuthorityURL: "ca"}, SystemConfig{ClientID: "id", RedirectURL: "redirect"}, complete(nil), nil},

		// trusted ca handling
		{"trusted ca from config", SystemConfig{}, complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA }), complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA; c.ca = ca }), nil},
		{"trusted ca from policy", SystemConfig{TrustedCertificateAuthority: testCA}, complete(nil), complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA; c.ca = ca }), nil},
		{"trusted ca from policy with empty config", complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA }), SystemConfig{}, complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA; c.ca = ca }), nil},
		{"trusted ca from policy overrides config", SystemConfig{TrustedCertificateAuthority: altTestCA}, complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA }), complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = altTestCA; c.ca = altCA }), nil},
		{"trusted ca from policy with trailing newline", SystemConfig{TrustedCertificateAuthority: testCA + "\n"}, complete(nil), complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA + "\n"; c.ca = ca }), nil},
		{"trusted ca from policy with comment", SystemConfig{TrustedCertificateAuthority: testCA + " ca@example.com"}, complete(nil), complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA + " ca@example.com"; c.ca = ca }), nil},
		{"valid trusted ca from policy overrides invalid config", SystemConfig{TrustedCertificateAuthority: testCA}, complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = badCA }), complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA; c.ca = ca }), nil},
		{"invalid trusted ca from config", SystemConfig{}, complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = badCA }), SystemConfig{}, errAny},
		{"invalid trusted ca from policy", SystemConfig{TrustedCertificateAuthority: badCA}, complete(nil), SystemConfig{}, errAny},
		{"invalid trusted ca from policy overrides valid config", SystemConfig{TrustedCertificateAuthority: badCA}, complete(func(c *SystemConfig) { c.TrustedCertificateAuthority = testCA }), SystemConfig{}, errAny},
		{"trusted ca only in policy is still incomplete", SystemConfig{TrustedCertificateAuthority: testCA}, SystemConfig{}, SystemConfig{}, ErrConfigIncomplete},
		// completeness is checked before the trusted ca is parsed
		{"incomplete with invalid trusted ca", SystemConfig{TrustedCertificateAuthority: badCA}, SystemConfig{}, SystemConfig{}, ErrConfigIncomplete},
		// a parsed ca is never taken from policy, only from parsing the trusted ca string
		{"policy ca key without trusted ca string is ignored", SystemConfig{ca: ca}, complete(nil), complete(nil), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := mergeConfig(tt.policy, tt.config)
			if gotErr != nil {
				if tt.wantErr == nil {
					t.Errorf("mergeConfig() failed: %v", gotErr)
				} else if tt.wantErr != errAny && !errors.Is(gotErr, tt.wantErr) {
					t.Errorf("mergeConfig() error = %v, want %v", gotErr, tt.wantErr)
				}
				if !reflect.DeepEqual(got, SystemConfig{}) {
					t.Errorf("mergeConfig() = %v on error, want empty SystemConfig", got)
				}
				return
			}
			if tt.wantErr != nil {
				t.Fatal("mergeConfig() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeConfig() = %v, want %v", got, tt.want)
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
