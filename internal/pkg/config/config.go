package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/v2"
	"golang.org/x/crypto/ssh"
)

var (
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

	ErrUnknownKey = errors.New("unknown configuration key")
)

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

	return decodeConfig(k)
}

// decodeConfig checks, decodes and validates the configuration loaded into k
// from any source, over the defaults.
func decodeConfig(k *koanf.Koanf) (*ClientConfig, error) {
	if err := checkKeys(k.Keys()); err != nil {
		return nil, err
	}

	// values must already have the type of their field, so a string is not
	// accepted for a list or a number for a string
	conf := clientConfigDefaults()
	if err := k.UnmarshalWithConf("", &conf, koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			TagName:     "json",
			ErrorUnused: true,
			Result:      &conf,
		},
	}); err != nil {
		return nil, err
	}

	return validateConfig(&conf)
}

// configKeys are the names of the configuration keys, from the json tags of
// [ClientConfig]
var configKeys = func() []string {
	keys := make([]string, 0)
	t := reflect.TypeFor[ClientConfig]()
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" {
			keys = append(keys, name)
		}
	}

	return keys
}()

// checkKeys reports every key in keys that is not exactly the name of a
// configuration key, so a misspelt or differently-cased key is not silently
// ignored, leaving its setting at the default.
func checkKeys(keys []string) error {
	errs := make([]error, 0)
	for _, key := range keys {
		if !slices.Contains(configKeys, key) {
			errs = append(errs, fmt.Errorf("%w: %q", ErrUnknownKey, key))
		}
	}

	return errors.Join(errs...)
}

// NewClientConfig validates conf and returns it ready to use, for callers
// that build the config in code rather than loading it with
// [LoadClientConfig]. No defaults are applied.
func NewClientConfig(conf ClientConfig) (*ClientConfig, error) {
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
		// ensure the url is valid and that tokens sent to the CA are
		// encrypted
		if err := validateSecureURL(conf.CertificateAuthorityURL); err != nil {
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
		// ensure it parses as exactly one key, so a second key is not
		// silently ignored
		ca, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(conf.TrustedCertificateAuthority))
		switch {
		case err != nil:
			errs = append(errs, ErrInvalidTrustedCertificateAuthority, err)
		case strings.TrimSpace(string(rest)) != "":
			errs = append(errs, ErrInvalidTrustedCertificateAuthority, fmt.Errorf("only one key is allowed"))
		default:
			conf.ca = ca
		}
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

// validateSecureURL ensures raw is a valid URL as for [validateURL] that uses
// https, unless its host is a loopback address, where http is also allowed.
func validateSecureURL(raw string) error {
	if err := validateURL(raw); err != nil {
		return err
	}

	// already parsed successfully by validateURL
	u, _ := url.Parse(raw)
	if u.Scheme != "https" && !isLoopback(u.Hostname()) {
		return fmt.Errorf("scheme must be https unless the host is a loopback address, got %q", u.Scheme)
	}

	return nil
}

// isLoopback reports whether host is localhost or a loopback IP address
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// validateIssuer ensures raw is a valid URL for OIDC discovery, which must
// use https unless its host is a loopback address. As the discovery document
// is found by appending a path to the issuer, it must not contain a query or
// fragment.
func validateIssuer(raw string) error {
	if err := validateSecureURL(raw); err != nil {
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
