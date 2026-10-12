//go:build !windows

package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadClientConfig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ca, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating public key: %v", err)
	}
	trusted := bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca))

	// required is the minimum valid configuration
	required := fmt.Sprintf(`issuer: https://idp.example.com/
client_id: client
ca_url: https://ca.example.com/
trusted_ca: %s
`, trusted)

	tests := []struct {
		name    string
		content string
		want    ClientConfig
		wantErr error
		wantAny bool
	}{
		{
			name:    "defaults",
			content: required,
			want: ClientConfig{
				CertificateAuthorityURL:     "https://ca.example.com/",
				ClientID:                    "client",
				Issuer:                      "https://idp.example.com/",
				RedirectURL:                 "http://localhost:3000/auth/callback",
				Scopes:                      []string{"openid", "email", "profile"},
				TrustedCertificateAuthority: string(trusted),
			},
		},
		{
			name: "defaults replaced",
			content: required + `redirect_url: http://127.0.0.1:8080/callback
scopes: ["openid", "offline_access"]
`,
			want: ClientConfig{
				CertificateAuthorityURL:     "https://ca.example.com/",
				ClientID:                    "client",
				Issuer:                      "https://idp.example.com/",
				RedirectURL:                 "http://127.0.0.1:8080/callback",
				Scopes:                      []string{"openid", "offline_access"},
				TrustedCertificateAuthority: string(trusted),
			},
		},
		{
			// fewer scopes than the defaults must not leave any defaults behind
			name:    "single scope",
			content: required + "scopes: [openid]\n",
			want: ClientConfig{
				CertificateAuthorityURL:     "https://ca.example.com/",
				ClientID:                    "client",
				Issuer:                      "https://idp.example.com/",
				RedirectURL:                 "http://localhost:3000/auth/callback",
				Scopes:                      []string{"openid"},
				TrustedCertificateAuthority: string(trusted),
			},
		},
		{
			name:    "invalid",
			content: "issuer: https://idp.example.com/\n",
			wantErr: ErrMissingClientID,
		},
		{
			name:    "not yaml",
			content: "issuer: [https://idp.example.com/\n",
			wantAny: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatalf("writing config: %v", err)
			}

			got, err := LoadClientConfig(path)
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("LoadClientConfig() error = %v, want %v", err, tt.wantErr)
				}
				return
			case tt.wantAny:
				if err == nil {
					t.Error("LoadClientConfig() error = nil, want error")
				}
				return
			case err != nil:
				t.Fatalf("LoadClientConfig() error = %v", err)
			}

			if !bytes.Equal(got.CertificateAuthorityPublicKey().Marshal(), ca.Marshal()) {
				t.Errorf("CertificateAuthorityPublicKey() = %s, want %s", ssh.MarshalAuthorizedKey(got.CertificateAuthorityPublicKey()), trusted)
			}
			got.ca = nil
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("LoadClientConfig() = %+v, want %+v", *got, tt.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadClientConfig(filepath.Join(t.TempDir(), "missing.yml")); err == nil {
			t.Error("LoadClientConfig() error = nil, want error")
		}
	})

	// the example in the repository must stay a valid configuration
	t.Run("example", func(t *testing.T) {
		got, err := LoadClientConfig(filepath.Join("..", "..", "..", "config-example.yml"))
		if err != nil {
			t.Fatalf("LoadClientConfig() error = %v", err)
		}

		want := []string{"openid", "email", "profile", "offline_access"}
		if !reflect.DeepEqual(got.Scopes, want) {
			t.Errorf("Scopes = %q, want %q", got.Scopes, want)
		}
	})
}
