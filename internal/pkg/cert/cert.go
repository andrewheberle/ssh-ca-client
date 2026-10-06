package cert

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/client"
	"golang.org/x/crypto/ssh"
)

var (
	ErrAddingToAgent                  = client.ErrAddingToAgent
	ErrCertificateMismatch            = errors.New("certificate did not match private key")
	ErrCertificateNotFound            = errors.New("no certificate found")
	ErrCertificateNotValid            = client.ErrCertificateNotValid
	ErrKeyNotFound                    = errors.New("no key private key found")
	ErrNoAuthHandlerAvailable         = errors.New("no auth handler was available")
	ErrNotImplemented                 = errors.New("method not implemented")
	ErrSignerNotFound                 = errors.New("no signer found")
	ErrUnexpectedCertificateAuthority = errors.New("certificate was not issued by the CA")
	ErrUnexpectedResponse             = errors.New("unexpected response from CA")
)

type Certificate interface {
	Store() Storage
}

type Waiter interface {
	Wait() error
	Stop()
}

type Requestable interface {
	Certificate
	Request() error
	RequestContext(ctx context.Context) error
}

type RequestableWaiter interface {
	Requestable
	Waiter
}

type Renewable interface {
	Requestable
	Renew() error
	RenewContext(ctx context.Context) error
}

type RenewableWaiter interface {
	Renewable
	Waiter
}

type Storage interface {
	AddToAgent() error
	Certificate() (*ssh.Certificate, error)
	CertificateBytes() ([]byte, error)
	GeneratePrivateKey() error
	HasCertificate() bool
	HasPrivateKey() bool
	PrivateKey() (crypto.PrivateKey, error)
	PrivateKeyBytes() ([]byte, error)
	PublicKey() (ssh.PublicKey, error)
	PublicKeyBytes() ([]byte, error)
	SaveCertificate(*ssh.Certificate) error
	Signer() (ssh.Signer, error)
}

// Helper function to validate a certificate. This checks that the certificate
// is not expired, was issued by the expected CA and that the certificate is for
// the public key of the private key it will be used with.
func CertificateValid(ca ssh.PublicKey, pub ssh.PublicKey, cert *ssh.Certificate) error {
	// Check its not expired (with 5-seconds grace time on ValidAfter as
	// certificate could be issued with +1 seconds from now ValidAfter).
	// Compare as uint64 so ssh.CertTimeInfinity is handled correctly.
	now := uint64(time.Now().Unix())
	if now > cert.ValidBefore || now+5 < cert.ValidAfter {
		return ErrCertificateNotValid
	}

	// Check the certificate is for the correct CA
	if !bytes.Equal(cert.SignatureKey.Marshal(), ca.Marshal()) {
		return ErrUnexpectedCertificateAuthority
	}

	// Check that certificate is for our private key
	if !bytes.Equal(cert.Key.Marshal(), pub.Marshal()) {
		return ErrCertificateMismatch
	}

	return nil
}

// RenewalDue reports whether the fraction at (between 0 and 1) of the
// certificate's validity period, from ValidAfter to ValidBefore, has passed
// at now. Expired certificates are always due and certificates that never
// expire are never due.
func RenewalDue(c *ssh.Certificate, at float64, now time.Time) bool {
	if c.ValidBefore == ssh.CertTimeInfinity {
		return false
	}

	validAfter := time.Unix(int64(c.ValidAfter), 0)
	validBefore := time.Unix(int64(c.ValidBefore), 0)

	if !now.Before(validBefore) || !validAfter.Before(validBefore) {
		return true
	}

	elapsed := now.Sub(validAfter)
	lifetime := validBefore.Sub(validAfter)

	return float64(elapsed) >= float64(lifetime)*at
}

type BaseCertificate struct {
	// options
	store Storage
	h     *http.Client

	// internal state
	mu     sync.RWMutex
	client *api.ClientWithResponses
}

var (
	_ Certificate = &BaseCertificate{}
)

func newBaseCertificate(server string, store Storage, opts ...Option) (*BaseCertificate, error) {
	// set up defaults
	base := &BaseCertificate{
		h:     client.NewHttpClient(),
		store: store,
	}

	// apply options
	for _, o := range opts {
		o(base)
	}

	// set up API client
	client, err := api.NewClientWithResponses(server, api.WithHTTPClient(base.h))
	if err != nil {
		return nil, fmt.Errorf("could not set up api client: %w", err)
	}
	base.client = client

	return base, nil
}

func (base *BaseCertificate) Store() Storage {
	return base.store
}

type Option func(*BaseCertificate)

func WithHTTPClient(h *http.Client) Option {
	return func(base *BaseCertificate) {
		base.h = h
	}
}

func WithStore(store Storage) Option {
	return func(base *BaseCertificate) {
		base.store = store
	}
}
