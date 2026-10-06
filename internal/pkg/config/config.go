package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/persistence"
	yamlpersistence "github.com/andrewheberle/ssh-ca-client/internal/pkg/persistence/yaml"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"
	"github.com/andrewheberle/ssh-ca-client/pkg/protect"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshcert"
	"github.com/knadh/koanf/v2"
	"golang.org/x/crypto/ssh"
)

const (
	keySecretName   = names.AppName
	tokenSecretName = names.AppName
)

type Config struct {
	mu     sync.RWMutex
	user   *userconfig.UserConfig
	system *SystemConfig

	protector   protect.Protector
	persistence persistence.Persistence
}

type ClientOIDCConfig struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURL string   `json:"redirect_url"`
}

type SystemConfig struct {
	Issuer                      string   `json:"issuer"`
	ClientID                    string   `json:"client_id"`
	Scopes                      []string `json:"scopes"`
	RedirectURL                 string   `json:"redirect_url"`
	CertificateAuthorityURL     string   `json:"ca_url"`
	TrustedCertificateAuthority string   `json:"trusted_ca"`
	ca                          ssh.PublicKey
}

var (
	ErrNoPrivateKey   = errors.New("no private key found")
	ErrNoCertificate  = errors.New("no certificate found")
	ErrNoRefreshToken = errors.New("no refresh token found")

	ErrInvalidCertificateAuthorityURL     = errors.New("invalid certificate authority URL")
	ErrInvalidIssuer                      = errors.New("invalid issuer")
	ErrInvalidRedirectURL                 = errors.New("invalid redirect URL")
	ErrInvalidScopes                      = errors.New("invalid scopes")
	ErrInvalidTrustedCertificateAuthority = errors.New("invalid trusted ca")

	ErrMissingCertificateAuthorityURL     = errors.New("missing certificate authority URL")
	ErrMissingClientID                    = errors.New("missing client ID")
	ErrMissingIssuer                      = errors.New("missing issuer")
	ErrMissingRedirectURL                 = errors.New("missing redirect URL")
	ErrMissingTrustedCertificateAuthority = errors.New("missing trusted ca")
)

func LoadConfig(system, user string, opts ...ConfigOption) (*Config, error) {
	s, err := loadSystemConfig(system)
	if err != nil {
		return nil, err
	}

	c := &Config{
		system:    &s,
		protector: protect.NewDefaultProtector(),
	}

	for _, opt := range opts {
		opt(c)
	}

	// if no persistence option was provided, default to yaml file persistence
	if c.persistence == nil {
		p, err := yamlpersistence.New(user)
		if err != nil {
			return nil, fmt.Errorf("problem initializing persistence: %w", err)
		}
		c.persistence = p
	}
	c.user = c.persistence.Get()

	return c, nil
}

func LoadUserConfigOnly(name string, opts ...ConfigOption) (*Config, error) {
	c := &Config{
		protector: protect.NewDefaultProtector(),
	}

	for _, opt := range opts {
		opt(c)
	}

	// if no persistence option was provided, default to yaml file persistence
	if c.persistence == nil {
		p, err := yamlpersistence.New(name)
		if err != nil {
			return nil, fmt.Errorf("problem initializing persistence: %w", err)
		}
		c.persistence = p
	}
	c.user = c.persistence.Get()

	return c, nil
}

func (c *Config) Save() error {
	return c.persistence.Set(c.user)
}

func (c *Config) Oidc() ClientOIDCConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return ClientOIDCConfig{
		Issuer:      c.system.Issuer,
		ClientID:    c.system.ClientID,
		Scopes:      c.system.Scopes,
		RedirectURL: c.system.RedirectURL,
	}
}

func (c *Config) CertificateAuthorityURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.system.CertificateAuthorityURL
}

func (c *Config) HasPrivateKey() bool {
	// parse key via Signer
	if _, err := c.Signer(); err != nil {
		return false
	}

	return true
}

// GetPrivateKeyBytes returns a []byte slice that contains the users
// unencrypted SSH private key. It is up to the caller to ensure this is
// handled securely.
func (c *Config) GetPrivateKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPrivateKeyBytes()
}

func (c *Config) getPrivateKeyBytes() ([]byte, error) {
	// error if no user config exists or no private key exists
	if c.user == nil || c.user.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	// unprotect key
	pemBytes, err := c.protector.Decrypt(c.user.PrivateKey, keySecretName)
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

// SetPrivateKeyBytes encrypts and persists the PEM private key []byte slice
// via [Persistence]
func (c *Config) SetPrivateKeyBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := c.protector.Encrypt(pemBytes, keySecretName)
	if err != nil {
		return err
	}

	// set key and also clear certificate
	if c.user == nil {
		c.user = &userconfig.UserConfig{
			PrivateKey: protected,
		}
	} else {
		c.user.PrivateKey = protected
	}
	c.user.Certificate = nil

	// save config
	if err := c.persistence.Set(c.user); err != nil {
		return err
	}

	return nil
}

func (c *Config) GetPublicKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPublicKeyBytes()
}

func (c *Config) getPublicKeyBytes() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// get and parse key
	key, err := c.signer()
	if err != nil {
		return nil, err
	}

	// get public key and marshal in authorized_keys format
	pub := ssh.MarshalAuthorizedKey(key.PublicKey())

	// return as public key without a newline
	return bytes.TrimSuffix(pub, []byte("\n")), nil
}

func (c *Config) GetCertificateBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.user == nil || c.user.Certificate == nil {
		return nil, ErrNoCertificate
	}

	return c.user.Certificate, nil
}

func (c *Config) HasCertificate() bool {
	_, err := c.GetCertificateBytes()
	return err == nil
}

func (c *Config) CertificateValid() bool {
	return c.CertificateExpiry().After(time.Now())
}

func (c *Config) CertificateExpiry() time.Time {
	certBytes, err := c.GetCertificateBytes()
	if err != nil {
		return time.Time{}
	}

	// parse the cert, errors mean invalid
	cert, err := sshcert.ParseCert(certBytes)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(int64(cert.ValidBefore), 0)
}

func (c *Config) SetCertificateBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.user == nil {
		panic("attempt to set certificate when user config was nil")
	}
	c.user.Certificate = pemBytes

	// save config
	if err := c.persistence.Set(c.user); err != nil {
		return err
	}

	return nil
}

func (c *Config) GetRefreshToken() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.user == nil || c.user.RefreshToken == nil {
		return "", ErrNoRefreshToken
	}

	// unprotect token
	token, err := c.protector.Decrypt(c.user.RefreshToken, tokenSecretName)
	if err != nil {
		return "", err
	}
	defer clearBytes(token)

	return string(token), nil
}

func (c *Config) SetRefreshToken(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := c.protector.Encrypt([]byte(token), tokenSecretName)
	if err != nil {
		return err
	}

	if c.user == nil {
		panic("attempt to set refresh_token when user config was nil")
	}

	c.user.RefreshToken = protected

	// save config
	if err := c.persistence.Set(c.user); err != nil {
		return err
	}

	return nil
}

// Signer returns a ssh.Signer
func (c *Config) Signer() (ssh.Signer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.signer()
}

// CertificateAuthority returns the Config's ssh.PublicKey
func (c *Config) CertificateAuthority() ssh.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.system.CertificateAuthority()
}

// System returns the current system config
func (c *Config) System() *SystemConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.system
}

func (c *Config) signer() (ssh.Signer, error) {
	// get key
	pemBytes, err := c.getPrivateKeyBytes()
	if err != nil {
		return nil, err
	}
	defer clearBytes(pemBytes)

	// parse key and return signer
	return ssh.ParsePrivateKey(pemBytes)
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *SystemConfig) CertificateAuthority() ssh.PublicKey {
	return c.ca
}

type ClientConfig struct {
	CertificateAuthorityURL     string   `json:"ca_url"`
	ClientID                    string   `json:"client_id"`
	Issuer                      string   `json:"issuer"`
	RedirectURL                 string   `json:"redirect_url"`
	Scopes                      []string `json:"scopes"`
	TrustedCertificateAuthority string   `json:"trusted_ca"`

	ca ssh.PublicKey
}

// Loads client config from the following sources on Windows:
//   - Registry (HKCU or HKLM - defaults to HKLM)
//   - Policy ("HKLM\Software\Policies\Serverless SSH CA Client")
//
// And the following on non-Windows platforms:
//   - YAML based configuration file
func LoadClientConfig(configpath string) (*ClientConfig, error) {
	k, err := loadClientConfig(configpath)
	if err != nil {
		return nil, err
	}

	conf := clientConfigDefaults()
	if err := k.UnmarshalWithConf("", &conf, koanf.UnmarshalConf{Tag: "json"}); err != nil {
		return nil, err
	}

	return validateConfig(&conf)
}

func (c *ClientConfig) CertificateAuthorityPublicKey() ssh.PublicKey {
	return c.ca
}

func clientConfigDefaults() ClientConfig {
	return ClientConfig{
		RedirectURL: "http://localhost:3000/auth/callback",
		Scopes: []string{
			"openid",
			"email",
			"profile",
		},
	}
}

func validateConfig(conf *ClientConfig) (*ClientConfig, error) {
	errs := make([]error, 0)
	if conf.CertificateAuthorityURL == "" {
		errs = append(errs, ErrMissingCertificateAuthorityURL)
	} else {
		// ensure the url is valid
		if err := validateURL(conf.CertificateAuthorityURL); err != nil {
			errs = append(errs, ErrInvalidCertificateAuthorityURL, err)
		}
	}

	if conf.ClientID == "" {
		errs = append(errs, ErrMissingClientID)
	}

	if conf.Issuer == "" {
		errs = append(errs, ErrMissingIssuer)
	} else {
		// ensure the issuer is a valid url that OIDC discovery can use
		if err := validateIssuer(conf.Issuer); err != nil {
			errs = append(errs, ErrInvalidIssuer, err)
		}
	}

	if conf.RedirectURL == "" {
		errs = append(errs, ErrMissingRedirectURL)
	} else {
		// ensure the url is valid
		if err := validateURL(conf.RedirectURL); err != nil {
			errs = append(errs, ErrInvalidRedirectURL, err)
		}
	}

	if len(conf.Scopes) == 0 {
		errs = append(errs, ErrInvalidScopes)
	}

	if conf.TrustedCertificateAuthority == "" {
		errs = append(errs, ErrMissingTrustedCertificateAuthority)
	} else {
		// ensure it parses
		ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(conf.TrustedCertificateAuthority))
		if err != nil {
			errs = append(errs, ErrInvalidTrustedCertificateAuthority, err)
		}
		conf.ca = ca
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return conf, nil
}

// validateURL ensures raw parses as an absolute http or https URL that
// includes a host
func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https, got %q", u.Scheme)
	}

	if u.Hostname() == "" {
		return fmt.Errorf("missing host")
	}

	return nil
}

// validateIssuer ensures raw is a valid URL for OIDC discovery. As the
// discovery document is found by appending a path to the issuer, it must
// not contain a query or fragment.
func validateIssuer(raw string) error {
	if err := validateURL(raw); err != nil {
		return err
	}

	// already parsed successfully by validateURL
	u, _ := url.Parse(raw)
	if u.RawQuery != "" || u.ForceQuery {
		return fmt.Errorf("issuer must not contain a query")
	}

	if u.Fragment != "" || strings.HasSuffix(raw, "#") {
		return fmt.Errorf("issuer must not contain a fragment")
	}

	return nil
}
