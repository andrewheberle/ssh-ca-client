package cert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/pkg/proof"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshcert"
	"golang.org/x/crypto/ssh"
)

type HostCertificate struct {
	*BaseCertificate

	AuthHandler auth.Handler
	Lifetime    time.Duration
	Principals  []string
}

var _ Renewable = &HostCertificate{}

const DefaultHostCertificateLifetime = (time.Hour * 24) * 30

var (
	ErrEmptyPrincipalsList = errors.New("principals list was empty")
)

func NewHostCertificate(server string, store Storage, opts ...Option) (*HostCertificate, error) {
	base, err := newBaseCertificate(server, store, opts...)
	if err != nil {
		return nil, err
	}

	// include hostname in list of principals by default
	principals := make([]string, 0)
	hostname, err := os.Hostname()
	if err == nil {
		principals = append(principals, strings.ToLower(hostname))
	}

	h := &HostCertificate{
		BaseCertificate: base,
		Lifetime:        DefaultHostCertificateLifetime,
		Principals:      principals,
	}

	return h, nil
}

// Renew renews the existing host certificate. See [HostCertificate.RenewContext].
func (h *HostCertificate) Renew() error {
	return h.RenewContext(context.Background())
}

// RenewContext renews the existing host certificate using proof of
// possession of the private key, saving the renewed certificate to the store.
// Cancelling ctx aborts the request to the CA.
func (h *HostCertificate) RenewContext(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	certBytes, err := h.store.CertificateBytes()
	if err != nil {
		return fmt.Errorf("host certificate renewal: could not get certificate: %w", err)
	}

	signer, err := h.store.Signer()
	if err != nil {
		return fmt.Errorf("host certificate renewal: could not get signer: %w", err)
	}
	publicKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	proof, err := proof.Generate(signer)
	if err != nil {
		return fmt.Errorf("host certificate renewal: could not generate proof: %w", err)
	}

	lifetime := int(h.Lifetime.Seconds())

	payload := api.HostCertificateRenew{
		Certificate: certBytes,
		Lifetime:    &lifetime,
		PublicKey:   publicKey,
		Proof:       proof.String(),
	}

	// do renewal
	res, err := h.client.PostHostRenewWithResponse(
		ctx,
		payload,
	)
	if err != nil {
		return fmt.Errorf("host certificate renewal: %w", err)
	}

	// ensure status code was 200 OK
	if res.StatusCode() != http.StatusOK {
		return fmt.Errorf("host certificate renewal: got bad status code: %d", res.StatusCode())
	}

	// JSON200 is only set when the response was JSON
	if res.JSON200 == nil {
		return fmt.Errorf("host certificate renewal: %w: content type %q", ErrUnexpectedResponse, res.HTTPResponse.Header.Get("Content-Type"))
	}

	// parse cert
	cert, err := sshcert.ParseCert(res.JSON200.Certificate)
	if err != nil {
		return fmt.Errorf("host certificate renewal: could not parse certificate: %w", err)
	}

	// save certificate
	if err := h.store.SaveCertificate(cert); err != nil {
		return fmt.Errorf("host certificate renewal: could not save certificate: %w", err)
	}

	return nil
}

// Request requests a new host certificate. See [HostCertificate.RequestContext].
func (h *HostCertificate) Request() error {
	return h.RequestContext(context.Background())
}

// RequestContext authenticates using the AuthHandler and requests a new host
// certificate for Principals from the CA, saving it to the store. Cancelling
// ctx stops waiting for authentication and aborts the request to the CA.
func (h *HostCertificate) RequestContext(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.AuthHandler == nil {
		return fmt.Errorf("host certificate request: %w", ErrNoAuthHandlerAvailable)
	}

	// check before authenticating so an interactive login is not wasted
	if len(h.Principals) == 0 {
		return fmt.Errorf("host certificate request: %w", ErrEmptyPrincipalsList)
	}

	tokens, err := h.AuthHandler.GetTokensContext(ctx)
	if err != nil {
		return fmt.Errorf("host certificate request: authentication error: %w", err)
	}

	signer, err := h.store.Signer()
	if err != nil {
		return fmt.Errorf("host certificate request: could not get signer: %w", err)
	}
	publicKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	proof, err := proof.Generate(signer)
	if err != nil {
		return fmt.Errorf("host certificate request: could not generate proof: %w", err)
	}

	lifetime := int(h.Lifetime.Seconds())

	payload := api.HostCertificateRequest{
		Principals: h.Principals,
		PublicKey:  publicKey,
		Lifetime:   &lifetime,
		Identity:   tokens.Identity,
		Proof:      proof.String(),
	}

	// do request
	res, err := h.client.PostHostCertificateWithResponse(
		ctx,
		&api.PostHostCertificateParams{
			Authorization: "Bearer " + tokens.Access,
		},
		payload,
	)
	if err != nil {
		return fmt.Errorf("host certificate request: %w", err)
	}

	// ensure status code was 200 OK
	if res.StatusCode() != http.StatusOK {
		return fmt.Errorf("host certificate request: got bad status code: %d", res.StatusCode())
	}

	// JSON200 is only set when the response was JSON
	if res.JSON200 == nil {
		return fmt.Errorf("host certificate request: %w: content type %q", ErrUnexpectedResponse, res.HTTPResponse.Header.Get("Content-Type"))
	}

	// parse cert
	cert, err := sshcert.ParseCert(res.JSON200.Certificate)
	if err != nil {
		return fmt.Errorf("host certificate request: could not parse certificate: %w", err)
	}

	// save certificate
	if err := h.store.SaveCertificate(cert); err != nil {
		return fmt.Errorf("host certificate request: could not save certificate: %w", err)
	}

	return nil
}
