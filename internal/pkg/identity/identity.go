// Package identity provides the user identity: the user's SSH private key and
// certificate, and how a new certificate is obtained from the CA and added to
// the SSH agent.
package identity

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth/tokenstore"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"golang.org/x/crypto/ssh"
)

// User is the user identity. By default the private key and certificate are
// kept in the system keyring and certificates are obtained after an OIDC
// login, with the refresh token also kept in the system keyring.
type User struct {
	store cert.Storage
	cert  *cert.UserCertificate
}

type options struct {
	lifetime time.Duration
	logger   *slog.Logger
	store    cert.Storage
	auth     auth.Handler
}

// Option configures a [User]
type Option func(*options)

// WithLifetime sets the lifetime requested for new certificates. The default
// is [cert.DefaultUserCertificateLifetime].
func WithLifetime(d time.Duration) Option {
	return func(o *options) {
		o.lifetime = d
	}
}

// WithLogger sets the logger used for the OIDC login
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		o.logger = logger
	}
}

// WithStore uses s for the private key and certificate instead of the system
// keyring
func WithStore(s cert.Storage) Option {
	return func(o *options) {
		o.store = s
	}
}

// WithAuthHandler uses h to authenticate certificate requests instead of an
// OIDC login using conf
func WithAuthHandler(h auth.Handler) Option {
	return func(o *options) {
		o.auth = h
	}
}

// NewUser creates the [User] for conf. Neither the CA nor the identity
// provider is contacted until a certificate is obtained.
func NewUser(conf *config.ClientConfig, opts ...Option) (*User, error) {
	o := options{
		lifetime: cert.DefaultUserCertificateLifetime,
		logger:   slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(&o)
	}

	if o.store == nil {
		// the key and certificate are kept in the users keyring
		s, err := store.NewKeyring(conf.CertificateAuthorityPublicKey())
		if err != nil {
			return nil, fmt.Errorf("could not set up key store: %w", err)
		}
		o.store = s
	}

	if o.auth == nil {
		// the refresh token is persisted in the users keyring
		ts, err := tokenstore.NewKeyringStore()
		if err != nil {
			return nil, fmt.Errorf("could not set up token store: %w", err)
		}

		handler, err := auth.NewOidcHandler(auth.OidcConfig{
			ClientID:    conf.ClientID,
			Issuer:      conf.Issuer,
			RedirectURL: conf.RedirectURL,
			Scopes:      conf.Scopes,
		}, auth.WithTokenStore(ts), auth.WithLogger(o.logger))
		if err != nil {
			return nil, fmt.Errorf("could not set up OIDC authentication: %w", err)
		}
		o.auth = handler
	}

	c, err := cert.NewUserCertificate(conf.CertificateAuthorityURL, o.store)
	if err != nil {
		return nil, fmt.Errorf("could not set up certificate: %w", err)
	}
	c.AuthHandler = o.auth
	c.Lifetime = o.lifetime

	return &User{store: o.store, cert: c}, nil
}

// ObtainOption changes how [User.Obtain] obtains a certificate
type ObtainOption int

const (
	// WithoutAgent does not add the new certificate to the SSH agent
	WithoutAgent ObtainOption = iota + 1

	// WithoutInteractiveLogin only uses cached tokens or a refresh token, so
	// the request fails with [auth.ErrInteractiveLoginRequired] rather than
	// start an interactive login
	WithoutInteractiveLogin
)

// Obtain requests a new certificate from the CA, saves it and adds it to the
// SSH agent. This blocks until any interactive login completes, times out or
// ctx is cancelled. If the certificate is saved but cannot be added to the
// agent the returned error wraps [cert.ErrAddingToAgent].
func (u *User) Obtain(ctx context.Context, opts ...ObtainOption) error {
	if slices.Contains(opts, WithoutInteractiveLogin) {
		ctx = auth.NonInteractive(ctx)
	}

	if err := u.cert.RequestContext(ctx); err != nil {
		return err
	}

	if slices.Contains(opts, WithoutAgent) {
		return nil
	}

	if err := u.store.AddToAgent(); err != nil {
		return fmt.Errorf("certificate issued but %w", err)
	}

	return nil
}

// AddToAgent adds the current private key and certificate to the SSH agent.
// Failures are returned as [cert.ErrAddingToAgent].
func (u *User) AddToAgent() error {
	return u.store.AddToAgent()
}

// Certificate returns the current certificate, or an error wrapping
// [cert.ErrCertificateNotFound] if there is none
func (u *User) Certificate() (*ssh.Certificate, error) {
	return u.store.Certificate()
}

// HasPrivateKey reports whether there is a private key
func (u *User) HasPrivateKey() bool {
	return u.store.HasPrivateKey()
}

// GeneratePrivateKey generates a new private key, replacing any existing key
// and its certificate
func (u *User) GeneratePrivateKey() error {
	return u.store.GeneratePrivateKey()
}
