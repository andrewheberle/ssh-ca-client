package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"reflect"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/persistence"
	yamlpersistence "github.com/andrewheberle/ssh-ca-client/internal/pkg/persistence/yaml"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"
	"github.com/andrewheberle/ssh-ca-client/pkg/protect"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

var _ protect.Protector = &mockProtector{}

type mockProtector struct {
}

func (p *mockProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return bytes.Clone(data), nil
}

func (p *mockProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return bytes.Clone(data), nil
}

var _ persistence.Persistence = &mockPersistence{}

type mockPersistence struct {
	data *userconfig.UserConfig
}

func (p *mockPersistence) Get() *userconfig.UserConfig {
	return p.data
}

func (p *mockPersistence) Save() error {
	return nil
}

func (p *mockPersistence) Set(config *userconfig.UserConfig) error {
	p.data = config
	return nil
}

func TestLoadConfig(t *testing.T) {
	ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgJTsYW+tHl0lz/rnO8djbwq0B3uZ5sGugXU6Ha5S2rTdzMDgit2DO+hoivdT4I07rMrRtmFI179wUY06gIf00="))
	if err != nil {
		panic(err)
	}

	missing, err := yamlpersistence.New("testdata/missing.yml")
	if err != nil {
		panic(err)
	}

	validuser, err := yamlpersistence.New("testdata/validuser.yml")
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name    string
		system  string
		user    string
		want    *Config
		wantErr bool
	}{
		{"missing", "missing.yml", "missing.yml", nil, true},
		{"system missing", "missing.yml", "testdata/validuser.yml", nil, true},
		{"user missing", "testdata/validsystem.yml", "testdata/missing.yml",
			&Config{
				system: &SystemConfig{
					Issuer:                  "OIDC Issuer",
					ClientID:                "OIDC Client ID",
					Scopes:                  []string{"openid", "email", "profile"},
					RedirectURL:             "http://localhost:3000/auth/callback",
					CertificateAuthorityURL: "https://ssh-ca.example.com/",
				},
				user:        &userconfig.UserConfig{},
				persistence: missing,
				protector:   protect.NewDefaultProtector(),
			}, false},
		{"system only with ca", "testdata/validsystem_withca.yml", "testdata/missing.yml",
			&Config{
				system: &SystemConfig{
					Issuer:                      "OIDC Issuer",
					ClientID:                    "OIDC Client ID",
					Scopes:                      []string{"openid", "email", "profile"},
					RedirectURL:                 "http://localhost:3000/auth/callback",
					CertificateAuthorityURL:     "https://ssh-ca.example.com/",
					TrustedCertificateAuthority: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMgJTsYW+tHl0lz/rnO8djbwq0B3uZ5sGugXU6Ha5S2rTdzMDgit2DO+hoivdT4I07rMrRtmFI179wUY06gIf00=",
					ca:                          ca,
				},
				user:        &userconfig.UserConfig{},
				persistence: missing,
				protector:   protect.NewDefaultProtector(),
			}, false},
		{"system only with invalid ca", "testdata/validsystem_withbadca.yml", "testdata/missing.yml", nil, true},
		{"invalid system", "testdata/invalidsystem.yml", "testdata/validuser.yml", nil, true},
		{"invalid user", "testdata/validsystem.yml", "testdata/invaliduser.yml", nil, true},
		{"both valid", "testdata/validsystem.yml", "testdata/validuser.yml",
			&Config{
				system: &SystemConfig{
					Issuer:                  "OIDC Issuer",
					ClientID:                "OIDC Client ID",
					Scopes:                  []string{"openid", "email", "profile"},
					RedirectURL:             "http://localhost:3000/auth/callback",
					CertificateAuthorityURL: "https://ssh-ca.example.com/",
				},
				user: &userconfig.UserConfig{
					PrivateKey: []byte("somedataencodedasbase64"),
				},
				persistence: validuser,
				protector:   protect.NewDefaultProtector(),
			}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LoadConfig(tt.system, tt.user)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LoadConfig() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LoadConfig() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got.system, tt.want.system) {
				t.Errorf("LoadConfig() (system) = %v, want %v", got.system, tt.want.system)
			}
			if !reflect.DeepEqual(got.user, tt.want.user) {
				t.Errorf("LoadConfig() (user) = %v, want %v", got.user, tt.want.user)
			}
		})
	}
}

func TestLoadUserConfigOnly(t *testing.T) {
	missing, err := yamlpersistence.New("testdata/missing.yml")
	if err != nil {
		panic(err)
	}

	validuser, err := yamlpersistence.New("testdata/validuser.yml")
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name    string
		config  string
		want    *Config
		wantErr bool
	}{
		{"missing", "missing.yml", &Config{
			user:        &userconfig.UserConfig{},
			persistence: missing,
			protector:   protect.NewDefaultProtector(),
		}, false},
		{"valid config", "testdata/validuser.yml",
			&Config{
				user: &userconfig.UserConfig{
					PrivateKey: []byte("somedataencodedasbase64"),
				},
				persistence: validuser,
				protector:   protect.NewDefaultProtector(),
			}, false},
		{"invalid config", "testdata/invaliduser.yml", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LoadUserConfigOnly(tt.config)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LoadUserConfigOnly() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LoadUserConfigOnly() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got.system, tt.want.system) {
				t.Errorf("LoadUserConfigOnly() (system)= %v, want %v", got.system, tt.want.system)
			}
			if !reflect.DeepEqual(got.user, tt.want.user) {
				t.Errorf("LoadUserConfigOnly() (user)= %v, want %v", got.user, tt.want.user)
			}
		})
	}
}

func TestConfig_Oidc(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		system: &SystemConfig{
			Issuer:      "OIDC Issuer",
			ClientID:    "OIDC Client ID",
			Scopes:      []string{"openid", "email", "profile"},
			RedirectURL: "http://localhost:3000/auth/callback",
		},
	}

	tests := []struct {
		name   string
		config *Config
		want   ClientOIDCConfig
	}{
		{"valid config", testconfig, ClientOIDCConfig{
			Issuer:      "OIDC Issuer",
			ClientID:    "OIDC Client ID",
			Scopes:      []string{"openid", "email", "profile"},
			RedirectURL: "http://localhost:3000/auth/callback",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.Oidc()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Oidc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_CertificateAuthorityURL(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		system: &SystemConfig{
			CertificateAuthorityURL: "https://ssh-ca.example.com/",
		},
	}

	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{"valid config", testconfig, "https://ssh-ca.example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.CertificateAuthorityURL()
			if got != tt.want {
				t.Errorf("CertificateAuthorityURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_getPrivateKeyBytes(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		user: &userconfig.UserConfig{
			PrivateKey: []byte("somedata"),
		},
		protector: &mockProtector{},
	}

	tests := []struct {
		name    string
		config  *Config
		want    []byte
		wantErr bool
	}{
		{"valid config", testconfig, []byte("somedata"), false},
		{"no key", &Config{
			user: &userconfig.UserConfig{
				PrivateKey: nil,
			},
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.config.getPrivateKeyBytes()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getPrivateKeyBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getPrivateKeyBytes() succeeded unexpectedly")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("getPrivateKeyBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetRefreshToken(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		user: &userconfig.UserConfig{
			RefreshToken: []byte("somedata"),
		},
		protector: &mockProtector{},
	}

	tests := []struct {
		name    string
		config  *Config
		want    string
		wantErr bool
	}{
		{"valid config", testconfig, "somedata", false},
		{"missing token", &Config{
			user: &userconfig.UserConfig{
				PrivateKey: nil,
			},
		}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.config.GetRefreshToken()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GetRefreshToken() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GetRefreshToken() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("GetRefreshToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_HasPrivateKey(t *testing.T) {
	// generate test key
	key, err := sshkey.GenerateKey("testkey")
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no key", &Config{}, false},
		{"invalid key", &Config{
			user: &userconfig.UserConfig{
				PrivateKey: []byte("somedatathatisntavalidprivatekey"),
			},
			protector: &mockProtector{},
		}, false},
		{"valid key", &Config{
			user: &userconfig.UserConfig{
				PrivateKey: key,
			},
			protector: &mockProtector{},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.HasPrivateKey()
			if got != tt.want {
				t.Errorf("HasPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_getPublicKeyBytes(t *testing.T) {
	// generate test key
	pemBytes, err := sshkey.GenerateKey("testkey")
	if err != nil {
		panic(err)
	}

	// parse into a private key
	key, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		panic(err)
	}

	// convert to public key (trim newline)
	publicBytes := bytes.TrimSuffix(ssh.MarshalAuthorizedKey(key.PublicKey()), []byte("\n"))

	tests := []struct {
		name    string
		config  *Config
		want    []byte
		wantErr bool
	}{
		{"no key", &Config{}, nil, true},
		{"invalid key", &Config{
			user: &userconfig.UserConfig{
				PrivateKey: []byte("somedatathatisntavalidprivatekey"),
			},
			protector: &mockProtector{},
		}, nil, true},
		{"valid key", &Config{
			user: &userconfig.UserConfig{
				PrivateKey: pemBytes,
			},
			protector: &mockProtector{},
		}, publicBytes, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.config.getPublicKeyBytes()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getPublicKeyBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getPublicKeyBytes() succeeded unexpectedly")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("getPublicKeyBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_SetAndGetPrivateKeyBytes(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		pemBytes []byte
		wantErr  bool
	}{
		{"mock save", &Config{
			persistence: &mockPersistence{},
			protector:   &mockProtector{},
		}, []byte("somebytes"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := tt.config.SetPrivateKeyBytes(tt.pemBytes)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("SetPrivateKeyBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("SetPrivateKeyBytes() succeeded unexpectedly")
			}

			saved := tt.config.persistence.(*mockPersistence).data.PrivateKey
			if !bytes.Equal(saved, tt.config.user.PrivateKey) {
				t.Fatalf("SetPrivateKeyBytes() did not save: %v, want %v", saved, tt.config.user.PrivateKey)
			}

			got, gotErr := tt.config.GetPrivateKeyBytes()
			if gotErr != nil {
				t.Fatal("GetPrivateKeyBytes() failed")
			}
			if !bytes.Equal(got, tt.config.user.PrivateKey) {
				t.Errorf("GetPrivateKeyBytes() = %v, want %v", got, tt.config.user.PrivateKey)
			}
		})
	}
}

func TestConfig_HasCertificate(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no certificate", &Config{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.HasCertificate()
			if got != tt.want {
				t.Errorf("HasCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_CertificateValid(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no certificate", &Config{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.CertificateValid()
			if got != tt.want {
				t.Errorf("CertificateValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientConfigDefaults(t *testing.T) {
	want := ClientConfig{
		RedirectURL: "http://localhost:3000/auth/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}

	got := clientConfigDefaults()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("clientConfigDefaults() = %+v, want %+v", got, want)
	}

	// changes to the returned config must not affect later defaults
	got.Scopes[0] = "changed"
	got.RedirectURL = "changed"
	if again := clientConfigDefaults(); !reflect.DeepEqual(again, want) {
		t.Errorf("clientConfigDefaults() after modification = %+v, want %+v", again, want)
	}
}

func TestValidateConfig(t *testing.T) {
	// missing and invalid errors must be distinguishable to the user
	if ErrMissingRedirectURL.Error() == ErrInvalidRedirectURL.Error() {
		t.Errorf("ErrMissingRedirectURL and ErrInvalidRedirectURL have the same message %q", ErrMissingRedirectURL)
	}

	_, ca, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate CA key: %v", err)
	}
	caPub, err := ssh.NewPublicKey(ca.Public())
	if err != nil {
		t.Fatalf("could not get CA public key: %v", err)
	}
	trustedCA := string(ssh.MarshalAuthorizedKey(caPub))

	// valid returns a fully populated valid config with mutate applied
	valid := func(mutate func(c *ClientConfig)) *ClientConfig {
		c := &ClientConfig{
			CertificateAuthorityURL:     "https://ca.example.com",
			ClientID:                    "client-id",
			Issuer:                      "https://issuer.example.com",
			RedirectURL:                 "http://localhost:3000/auth/callback",
			Scopes:                      []string{"openid"},
			TrustedCertificateAuthority: trustedCA,
		}
		if mutate != nil {
			mutate(c)
		}
		return c
	}

	// defaults returns the default config with the required fields set
	defaults := func() *ClientConfig {
		c := clientConfigDefaults()
		c.CertificateAuthorityURL = "https://ca.example.com"
		c.ClientID = "client-id"
		c.Issuer = "https://issuer.example.com"
		c.TrustedCertificateAuthority = trustedCA
		return &c
	}

	// every sentinel error validateConfig can return
	allErrs := []error{
		ErrInvalidCertificateAuthorityURL,
		ErrInvalidIssuer,
		ErrInvalidRedirectURL,
		ErrInvalidScopes,
		ErrInvalidTrustedCertificateAuthority,
		ErrMissingCertificateAuthorityURL,
		ErrMissingClientID,
		ErrMissingIssuer,
		ErrMissingRedirectURL,
		ErrMissingTrustedCertificateAuthority,
	}

	tests := []struct {
		name     string
		conf     *ClientConfig
		wantErrs []error
		wantURL  bool // the url.Parse error is also returned
	}{
		{
			name: "valid",
			conf: valid(nil),
		},
		{
			name: "valid trusted ca with comment",
			conf: valid(func(c *ClientConfig) {
				c.TrustedCertificateAuthority = "ssh-ed25519 " + base64Key(caPub) + " ca@example.com"
			}),
		},
		{
			name: "defaults with required fields",
			conf: defaults(),
		},
		{
			name:     "defaults only",
			conf:     func() *ClientConfig { c := clientConfigDefaults(); return &c }(),
			wantErrs: []error{
				ErrMissingCertificateAuthorityURL,
				ErrMissingClientID,
				ErrMissingIssuer,
				ErrMissingTrustedCertificateAuthority,
			},
		},
		{
			name: "empty config",
			conf: &ClientConfig{},
			wantErrs: []error{
				ErrMissingCertificateAuthorityURL,
				ErrMissingClientID,
				ErrMissingIssuer,
				ErrMissingRedirectURL,
				ErrInvalidScopes,
				ErrMissingTrustedCertificateAuthority,
			},
		},
		{
			name:     "missing certificate authority url",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "" }),
			wantErrs: []error{ErrMissingCertificateAuthorityURL},
		},
		{
			name:     "invalid certificate authority url",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "http://[::1" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
			wantURL:  true,
		},
		{
			name:     "certificate authority url missing scheme",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "://ca.example.com" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
			wantURL:  true,
		},
		{
			name: "valid uppercase scheme",
			conf: valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "HTTPS://ca.example.com" }),
		},
		{
			name: "valid ipv6 host with port and path",
			conf: valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "http://[::1]:8080/ca" }),
		},
		{
			name:     "certificate authority url without scheme",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "ca.example.com" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
		},
		{
			name:     "certificate authority url with unsupported scheme",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "ftp://ca.example.com" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
		},
		{
			name:     "certificate authority url without host",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "https://" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
		},
		{
			name:     "certificate authority url with port but no host",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "https://:8443" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
		},
		{
			name:     "certificate authority url is a path",
			conf:     valid(func(c *ClientConfig) { c.CertificateAuthorityURL = "/ca" }),
			wantErrs: []error{ErrInvalidCertificateAuthorityURL},
		},
		{
			name:     "missing client id",
			conf:     valid(func(c *ClientConfig) { c.ClientID = "" }),
			wantErrs: []error{ErrMissingClientID},
		},
		{
			name:     "missing issuer",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "" }),
			wantErrs: []error{ErrMissingIssuer},
		},
		{
			name: "valid issuer with path",
			conf: valid(func(c *ClientConfig) { c.Issuer = "https://issuer.example.com/realms/test/" }),
		},
		{
			name: "valid http issuer",
			conf: valid(func(c *ClientConfig) { c.Issuer = "http://localhost:8080" }),
		},
		{
			name:     "issuer without scheme",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "issuer.example.com" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "issuer with unsupported scheme",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "ftp://issuer.example.com" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "issuer without host",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "https:///realms/test" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "issuer does not parse",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "https://[::1" }),
			wantErrs: []error{ErrInvalidIssuer},
			wantURL:  true,
		},
		{
			name:     "issuer with query",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "https://issuer.example.com?tenant=1" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "issuer with empty query",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "https://issuer.example.com?" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "issuer with fragment",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "https://issuer.example.com#frag" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "issuer with empty fragment",
			conf:     valid(func(c *ClientConfig) { c.Issuer = "https://issuer.example.com#" }),
			wantErrs: []error{ErrInvalidIssuer},
		},
		{
			name:     "missing redirect url",
			conf:     valid(func(c *ClientConfig) { c.RedirectURL = "" }),
			wantErrs: []error{ErrMissingRedirectURL},
		},
		{
			name:     "invalid redirect url",
			conf:     valid(func(c *ClientConfig) { c.RedirectURL = "http://localhost:3000/%zz" }),
			wantErrs: []error{ErrInvalidRedirectURL},
			wantURL:  true,
		},
		{
			name:     "redirect url without scheme",
			conf:     valid(func(c *ClientConfig) { c.RedirectURL = "localhost:3000/auth/callback" }),
			wantErrs: []error{ErrInvalidRedirectURL},
		},
		{
			name:     "redirect url with unsupported scheme",
			conf:     valid(func(c *ClientConfig) { c.RedirectURL = "file:///auth/callback" }),
			wantErrs: []error{ErrInvalidRedirectURL},
		},
		{
			name:     "redirect url without host",
			conf:     valid(func(c *ClientConfig) { c.RedirectURL = "http:///auth/callback" }),
			wantErrs: []error{ErrInvalidRedirectURL},
		},
		{
			name:     "nil scopes",
			conf:     valid(func(c *ClientConfig) { c.Scopes = nil }),
			wantErrs: []error{ErrInvalidScopes},
		},
		{
			name:     "empty scopes",
			conf:     valid(func(c *ClientConfig) { c.Scopes = []string{} }),
			wantErrs: []error{ErrInvalidScopes},
		},
		{
			name:     "missing trusted ca",
			conf:     valid(func(c *ClientConfig) { c.TrustedCertificateAuthority = "" }),
			wantErrs: []error{ErrMissingTrustedCertificateAuthority},
		},
		{
			name:     "whitespace only trusted ca",
			conf:     valid(func(c *ClientConfig) { c.TrustedCertificateAuthority = " \n" }),
			wantErrs: []error{ErrInvalidTrustedCertificateAuthority},
		},
		{
			name:     "invalid trusted ca",
			conf:     valid(func(c *ClientConfig) { c.TrustedCertificateAuthority = "not a key" }),
			wantErrs: []error{ErrInvalidTrustedCertificateAuthority},
		},
		{
			name: "multiple invalid fields",
			conf: valid(func(c *ClientConfig) {
				c.CertificateAuthorityURL = "http://[::1"
				c.RedirectURL = "http://localhost:3000/%zz"
				c.TrustedCertificateAuthority = "not a key"
			}),
			wantErrs: []error{
				ErrInvalidCertificateAuthorityURL,
				ErrInvalidRedirectURL,
				ErrInvalidTrustedCertificateAuthority,
			},
			wantURL: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateConfig(tt.conf)

			if len(tt.wantErrs) == 0 {
				if err != nil {
					t.Fatalf("validateConfig() error = %v, want nil", err)
				}
				if got != tt.conf {
					t.Errorf("validateConfig() did not return the provided config")
				}
				return
			}

			if err == nil {
				t.Fatalf("validateConfig() error = nil, want %v", tt.wantErrs)
			}
			if got != nil {
				t.Errorf("validateConfig() config = %+v, want nil", got)
			}

			// check exactly the expected sentinel errors were returned
			for _, e := range allErrs {
				want := false
				for _, w := range tt.wantErrs {
					if w == e {
						want = true
						break
					}
				}
				if errors.Is(err, e) != want {
					t.Errorf("errors.Is(err, %q) = %v, want %v (err = %v)", e, !want, want, err)
				}
			}

			var urlErr *url.Error
			if errors.As(err, &urlErr) != tt.wantURL {
				t.Errorf("errors.As(err, *url.Error) = %v, want %v (err = %v)", !tt.wantURL, tt.wantURL, err)
			}
		})
	}
}

// base64Key returns the base64 encoded key portion of pub in authorized_keys
// format
func base64Key(pub ssh.PublicKey) string {
	b := ssh.MarshalAuthorizedKey(pub)
	return string(bytes.TrimSuffix(bytes.SplitN(b, []byte(" "), 2)[1], []byte("\n")))
}
