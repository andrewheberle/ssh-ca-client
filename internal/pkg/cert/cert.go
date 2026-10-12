package cert

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/httpclient"
	"github.com/andrewheberle/ssh-ca-client/pkg/proof"
	"golang.org/x/crypto/ssh"
)

var (
	ErrAddingToAgent                  = errors.New("could not add to agent")
	ErrAlreadyRevoked                 = errors.New("certificate was already revoked")
	ErrCertificateMismatch            = errors.New("certificate did not match private key")
	ErrCertificateNotFound            = errors.New("no certificate found")
	ErrCertificateNotValid            = errors.New("certificate validity not ok")
	ErrDeletingCertificate            = errors.New("could not delete certificate")
	ErrKeyNotFound                    = errors.New("no key private key found")
	ErrNoAuthHandlerAvailable         = errors.New("no auth handler was available")
	ErrNotImplemented                 = errors.New("method not implemented")
	ErrRemovingFromAgent              = errors.New("could not remove from agent")
	ErrSignerNotFound                 = errors.New("no signer found")
	ErrUnexpectedCertificateAuthority = errors.New("certificate was not issued by the CA")
	ErrUnexpectedResponse             = errors.New("unexpected response from CA")
	ErrUnknownCertificate             = errors.New("certificate not found at CA for this key")
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

// Revocable is a certificate that can be revoked at the CA using proof of
// possession of its private key
type Revocable interface {
	Certificate
	Revoke() (time.Time, error)
	RevokeContext(ctx context.Context) (time.Time, error)
	RevokeSerialContext(ctx context.Context, serial uint64) (time.Time, error)
}

type Storage interface {
	AddToAgent() error
	Certificate() (*ssh.Certificate, error)
	CertificateBytes() ([]byte, error)
	DeleteCertificate() error
	GeneratePrivateKey() error
	HasCertificate() bool
	HasPrivateKey() bool
	PrivateKey() (crypto.PrivateKey, error)
	PrivateKeyBytes() ([]byte, error)
	PublicKey() (ssh.PublicKey, error)
	PublicKeyBytes() ([]byte, error)
	RemoveFromAgent() error
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

// apiBasePath is the path the CA serves the v4 API under. A proof of
// possession is bound to the path of the request as the CA serves it, which is
// below this path regardless of any path in the server URL.
const apiBasePath = "/api/v4"

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
		h:     httpclient.New(),
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

// revokeResponse holds the parts of a response to a revocation request that
// are common to user and host certificates
type revokeResponse struct {
	statusCode  int
	body        []byte
	contentType string
	result      *api.RevocationResponse
}

// revokeRequest makes a request to revoke the certificate with serial, with
// proof as the proof of possession
type revokeRequest func(ctx context.Context, serial, proof string) (revokeResponse, error)

// revokeCurrent revokes the certificate in the store. See [BaseCertificate.revoke].
func (base *BaseCertificate) revokeCurrent(ctx context.Context, path string, do revokeRequest, fromAgent bool) (time.Time, error) {
	c, err := base.store.Certificate()
	if err != nil {
		return time.Time{}, err
	}

	return base.revoke(ctx, path, c.Serial, do, fromAgent)
}

// revoke revokes the certificate with serial at the CA using do, with a
// proof of possession of the private key in the store made for the request
// to path (below [apiBasePath]) and serial.
//
// The time of revocation is returned. If the CA reports the certificate was
// already revoked the error wraps [ErrAlreadyRevoked] and if the CA has no
// certificate with serial for this key the error wraps
// [ErrUnknownCertificate].
//
// Once the CA confirms the certificate is revoked, if it is the certificate
// in the store it is deleted from the store, and first removed from the SSH
// agent if fromAgent is set. If removing it from the agent fails the
// certificate is still deleted and the error wraps [ErrRemovingFromAgent]. If
// deleting it fails the error wraps [ErrDeletingCertificate].
func (base *BaseCertificate) revoke(ctx context.Context, path string, serial uint64, do revokeRequest, fromAgent bool) (time.Time, error) {
	signer, err := base.store.Signer()
	if err != nil {
		return time.Time{}, fmt.Errorf("could not get signer: %w", err)
	}

	id := strconv.FormatUint(serial, 10)
	p, err := proof.GenerateForRequest(signer, http.MethodDelete, apiBasePath+path+"/"+id)
	if err != nil {
		return time.Time{}, fmt.Errorf("could not generate proof: %w", err)
	}

	res, err := do(ctx, id, p.String())
	if err != nil {
		return time.Time{}, err
	}

	var (
		revokedAt time.Time
		revokeErr error
	)
	switch res.statusCode {
	case http.StatusOK:
		// result is only set when the response was JSON
		if res.result == nil {
			return time.Time{}, fmt.Errorf("%w: content type %q", ErrUnexpectedResponse, res.contentType)
		}
		revokedAt = res.result.RevokedAt
	case http.StatusConflict:
		revokeErr = ErrAlreadyRevoked
	case http.StatusNotFound:
		return time.Time{}, ErrUnknownCertificate
	default:
		return time.Time{}, api.StatusError(res.statusCode, res.body)
	}

	return revokedAt, errors.Join(revokeErr, base.removeRevoked(serial, fromAgent))
}

// removeRevoked deletes the certificate in the store if it has serial, as it
// has been revoked, removing it from the SSH agent first if fromAgent is set
func (base *BaseCertificate) removeRevoked(serial uint64, fromAgent bool) error {
	c, err := base.store.Certificate()
	if err != nil || c.Serial != serial {
		// the revoked certificate is not the one in the store
		return nil
	}

	var agentErr error
	if fromAgent {
		agentErr = base.store.RemoveFromAgent()
	}

	if err := base.store.DeleteCertificate(); err != nil {
		return errors.Join(fmt.Errorf("%w: %w", ErrDeletingCertificate, err), agentErr)
	}

	return agentErr
}
