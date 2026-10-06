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

var _ Requestable = &UserCertificate{}

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

	proof, err := proof.Generate(signer)
	if err != nil {
		return fmt.Errorf("user certificate request: could not generate proof: %w", err)
	}

	lifetime := int(u.Lifetime.Seconds())

	payload := api.UserCertificateRequest{
		PublicKey: publicKey,
		Lifetime:  &lifetime,
		Identity:  tokens.Identity,
		Proof:     proof.String(),
	}

	// do request
	res, err := u.client.PostUserCertificateWithResponse(
		ctx,
		&api.PostUserCertificateParams{
			Authorization: "Bearer " + tokens.Access,
		},
		payload,
	)
	if err != nil {
		return fmt.Errorf("user certificate request: %w", err)
	}

	// ensure status code was 200 OK
	if res.StatusCode() != http.StatusOK {
		return fmt.Errorf("user certificate request: got bad status code: %d", res.StatusCode())
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
