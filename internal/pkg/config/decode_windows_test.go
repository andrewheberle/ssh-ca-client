package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/windows/registry"
)

// TestDecodeConfig_Registry loads configuration written to the registry and
// decodes and validates it as [LoadClientConfig] does, so the values the
// registry provider returns (REG_SZ, REG_MULTI_SZ and REG_DWORD) are checked
// against the strict decoding. Only the fixed registry paths differ, as tests
// must not write to the real configuration or Policy keys.
func TestDecodeConfig_Registry(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ca, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating public key: %v", err)
	}
	trusted := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca)))

	// required returns the required values, with extra added
	required := func(extra map[string]any) map[string]any {
		values := map[string]any{
			"issuer":     "https://idp.example.com/",
			"client_id":  "client",
			"ca_url":     "https://ca.example.com/",
			"trusted_ca": trusted,
		}
		for name, value := range extra {
			values[name] = value
		}
		return values
	}

	// want returns the config loaded from the required values, with mutate
	// applied
	want := func(mutate func(c *ClientConfig)) ClientConfig {
		c := ClientConfig{
			CertificateAuthorityURL:     "https://ca.example.com/",
			ClientID:                    "client",
			Issuer:                      "https://idp.example.com/",
			RedirectURL:                 "http://localhost:3000/auth/callback",
			Scopes:                      []string{"openid", "email", "profile"},
			TrustedCertificateAuthority: trusted,
		}
		if mutate != nil {
			mutate(&c)
		}
		return c
	}

	tests := []struct {
		name    string
		config  map[string]any
		policy  map[string]any
		want    ClientConfig
		wantErr error // checked with errors.Is; errAny for any error
	}{
		{
			name:   "required values",
			config: required(nil),
			want:   want(nil),
		},
		{
			name: "all values",
			config: required(map[string]any{
				"scopes":       []string{"openid", "offline_access"},
				"redirect_url": "http://127.0.0.1:8250/callback",
			}),
			want: want(func(c *ClientConfig) {
				c.Scopes = []string{"openid", "offline_access"}
				c.RedirectURL = "http://127.0.0.1:8250/callback"
			}),
		},
		{
			name:   "policy only",
			policy: required(map[string]any{"scopes": []string{"openid"}}),
			want:   want(func(c *ClientConfig) { c.Scopes = []string{"openid"} }),
		},
		{
			name:   "policy applied over config",
			config: required(nil),
			policy: map[string]any{"client_id": "policy", "scopes": []string{"openid"}},
			want: want(func(c *ClientConfig) {
				c.ClientID = "policy"
				c.Scopes = []string{"openid"}
			}),
		},
		{
			// registry names are case insensitive
			name: "names in any case",
			config: map[string]any{
				"Issuer":     "https://idp.example.com/",
				"CLIENT_ID":  "client",
				"Ca_Url":     "https://ca.example.com/",
				"TRUSTED_CA": trusted,
			},
			policy: map[string]any{"Client_Id": "policy"},
			want:   want(func(c *ClientConfig) { c.ClientID = "policy" }),
		},
		{
			// the MSI writes installed0 under the HKCU config key
			name:   "installer value",
			config: required(map[string]any{"installed0": uint32(1)}),
			want:   want(nil),
		},
		{
			name:    "unknown value",
			config:  required(map[string]any{"foo_bar": "1"}),
			wantErr: ErrUnknownKey,
		},
		{
			// a misspelt optional value must not leave the default in place
			name:    "misspelt scopes",
			config:  required(map[string]any{"scope": []string{"openid", "offline_access"}}),
			wantErr: ErrUnknownKey,
		},
		{
			name:    "unknown policy value",
			config:  required(nil),
			policy:  map[string]any{"redirect-url": "http://localhost:8250/cb"},
			wantErr: ErrUnknownKey,
		},
		{
			// scopes must be REG_MULTI_SZ, not one string
			name:    "scopes as REG_SZ",
			config:  required(map[string]any{"scopes": "openid,offline_access"}),
			wantErr: errAny,
		},
		{
			name:    "client id as REG_DWORD",
			config:  required(map[string]any{"client_id": uint32(12345)}),
			wantErr: errAny,
		},
		{
			name:    "http certificate authority url",
			config:  required(map[string]any{"ca_url": "http://ca.example.com/"}),
			wantErr: ErrInvalidCertificateAuthorityURL,
		},
		{
			name:    "missing required value",
			config:  map[string]any{"issuer": "https://idp.example.com/"},
			wantErr: ErrMissingClientID,
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

			got, err := decodeConfig(k)
			switch {
			case tt.wantErr == errAny:
				if err == nil {
					t.Fatalf("decodeConfig() = %+v, want error", got)
				}
				return
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("decodeConfig() error = %v, want %v", err, tt.wantErr)
				}
				return
			case err != nil:
				t.Fatalf("decodeConfig() error = %v", err)
			}

			if !bytes.Equal(got.CertificateAuthorityPublicKey().Marshal(), ca.Marshal()) {
				t.Errorf("CertificateAuthorityPublicKey() = %s, want %s", ssh.MarshalAuthorizedKey(got.CertificateAuthorityPublicKey()), trusted)
			}
			got.ca = nil
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("decodeConfig() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}
