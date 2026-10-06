package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
			name: "defaults only",
			conf: func() *ClientConfig { c := clientConfigDefaults(); return &c }(),
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
