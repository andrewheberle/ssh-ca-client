package cert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/pkg/proof"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshcert"
	"golang.org/x/crypto/ssh"
)

type UserCertificate struct {
	*BaseCertificate

	AuthHandler auth.Handler
	Lifetime    time.Duration
}

var (
	_ Requestable = &UserCertificate{}
	_ Revocable   = &UserCertificate{}
)

const DefaultUserCertificateLifetime = time.Hour * 24

var (
	ErrInitialRequestFailed = errors.New("initial certificate request failed")
	ErrNotRunning           = errors.New("renewal ticker not running")
)

func NewUserCertificate(server string, store Storage, opts ...Option) (*UserCertificate, error) {
	base, err := newBaseCertificate(server, store, opts...)
	if err != nil {
		return nil, err
	}

	u := &UserCertificate{
		BaseCertificate: base,
		Lifetime:        DefaultUserCertificateLifetime,
	}

	return u, nil
}

// Request requests a new user certificate. See [UserCertificate.RequestContext].
func (u *UserCertificate) Request() error {
	return u.RequestContext(context.Background())
}

// RequestContext authenticates using the AuthHandler and requests a new user
// certificate from the CA, saving it to the store. Cancelling ctx stops
// waiting for authentication and aborts the request to the CA.
func (u *UserCertificate) RequestContext(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.AuthHandler == nil {
		return fmt.Errorf("user certificate request: %w", ErrNoAuthHandlerAvailable)
	}

	tokens, err := u.AuthHandler.GetTokensContext(ctx)
	if err != nil {
		return fmt.Errorf("user certificate request: authentication error: %w", err)
	}

	signer, err := u.store.Signer()
	if err != nil {
		return fmt.Errorf("user certificate request: could not get signer: %w", err)
	}
	publicKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	proof, err := proof.GenerateForRequest(signer, http.MethodPost, apiBasePath+"/user/certificates")
	if err != nil {
		return fmt.Errorf("user certificate request: could not generate proof: %w", err)
	}

	lifetime := int(u.Lifetime.Seconds())

	payload := api.UserCertificateIssueRequest{
		PublicKey: publicKey,
		Lifetime:  &lifetime,
		Identity:  tokens.Identity,
	}

	// do request
	res, err := u.client.IssueUserCertificateWithResponse(
		ctx,
		&api.IssueUserCertificateParams{
			Authorization:     "Bearer " + tokens.Access,
			ProofOfPossession: proof.String(),
		},
		payload,
	)
	if err != nil {
		return fmt.Errorf("user certificate request: %w", err)
	}

	// ensure status code was 200 OK
	if res.StatusCode() != http.StatusOK {
		return fmt.Errorf("user certificate request: %w", api.StatusError(res.StatusCode(), res.Body))
	}

	// JSON200 is only set when the response was JSON
	if res.JSON200 == nil {
		return fmt.Errorf("user certificate request: %w: content type %q", ErrUnexpectedResponse, res.HTTPResponse.Header.Get("Content-Type"))
	}

	// parse cert
	cert, err := sshcert.ParseCert(res.JSON200.Certificate)
	if err != nil {
		return fmt.Errorf("user certificate request: could not parse certificate: %w", err)
	}

	// save certificate
	if err := u.store.SaveCertificate(cert); err != nil {
		return fmt.Errorf("user certificate request: could not save certificate: %w", err)
	}

	return nil
}

// Revoke revokes the current user certificate. See [UserCertificate.RevokeContext].
func (u *UserCertificate) Revoke() (time.Time, error) {
	return u.RevokeContext(context.Background())
}

// RevokeContext revokes the current user certificate at the CA using proof of
// possession of the private key, which needs no authentication. Once revoked
// the certificate is removed from the SSH agent and deleted from the store.
// The time of revocation is returned. Cancelling ctx aborts the request to the
// CA.
//
// If the certificate was already revoked the error wraps [ErrAlreadyRevoked],
// although the certificate is still removed. If the certificate was revoked
// but could not be removed from the SSH agent the error wraps
// [ErrRemovingFromAgent].
func (u *UserCertificate) RevokeContext(ctx context.Context) (time.Time, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	revokedAt, err := u.revokeCurrent(ctx, "/user/certificates", u.revokeRequest)
	if err != nil {
		return revokedAt, fmt.Errorf("user certificate revocation: %w", err)
	}

	return revokedAt, nil
}

// RevokeSerialContext revokes the user certificate with serial at the CA, which
// must have been issued for the private key in the store. If serial is the
// current certificate it is removed as for [UserCertificate.RevokeContext]. If the CA
// has no certificate with serial for the key the error wraps
// [ErrUnknownCertificate].
func (u *UserCertificate) RevokeSerialContext(ctx context.Context, serial uint64) (time.Time, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	revokedAt, err := u.revoke(ctx, "/user/certificates", serial, u.revokeRequest)
	if err != nil {
		return revokedAt, fmt.Errorf("user certificate revocation: %w", err)
	}

	return revokedAt, nil
}

func (u *UserCertificate) revokeRequest(ctx context.Context, serial, proof string) (revokeResponse, error) {
	res, err := u.client.RevokeUserCertificateWithResponse(ctx, serial, &api.RevokeUserCertificateParams{
		ProofOfPossession: proof,
	})
	if err != nil {
		return revokeResponse{}, err
	}

	return revokeResponse{
		statusCode:  res.StatusCode(),
		body:        res.Body,
		contentType: res.HTTPResponse.Header.Get("Content-Type"),
		result:      res.JSON200,
	}, nil
}
