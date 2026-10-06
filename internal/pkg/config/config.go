package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

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
