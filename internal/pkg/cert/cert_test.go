package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

// newCA generates a new CA signer for use in tests
func newCA(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate CA key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("could not create CA signer: %v", err)
	}

	return signer
}

// newKey generates a new ECDSA private key using curve
func newKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	return key
}

// newTypedKey generates a new private key of the given type
func newTypedKey(t *testing.T, keyType sshkey.KeyType) crypto.Signer {
	t.Helper()

	key, err := sshkey.GeneratePrivateKey(keyType, elliptic.P256())
	if err != nil {
		t.Fatalf("could not generate %s key: %v", keyType, err)
	}

	return key
}

// sshPublicKey returns the SSH public key for key
func sshPublicKey(t *testing.T, key crypto.Signer) ssh.PublicKey {
	t.Helper()

	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}

	return pub
}

// signCert signs a user certificate for key using ca that is valid between
// validAfter and validBefore (as unix timestamps)
func signCert(t *testing.T, ca ssh.Signer, key crypto.Signer, validAfter, validBefore uint64) *ssh.Certificate {
	t.Helper()

	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}

	c := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test@example.com",
		ValidPrincipals: []string{"test"},
		ValidAfter:      validAfter,
		ValidBefore:     validBefore,
	}

	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("could not sign certificate: %v", err)
	}

	return c
}

func TestCertificateValid(t *testing.T) {
	ca := newCA(t)
	otherCA := newCA(t)
	key := newKey(t, elliptic.P256())
	otherKey := newKey(t, elliptic.P256())
	p384Key := newKey(t, elliptic.P384())
	edKey := newTypedKey(t, sshkey.KeyTypeEd25519)
	rsaKey := newTypedKey(t, sshkey.KeyTypeRSA)

	// offsets from now are kept a few seconds away from the boundaries so
	// the tests are not affected by the clock ticking over during the test
	at := func(d time.Duration) uint64 {
		return uint64(time.Now().Add(d).Unix())
	}

	tests := []struct {
		name    string
		ca      ssh.PublicKey
		key     crypto.Signer
		cert    *ssh.Certificate
		wantErr error
	}{
		{
			name: "valid",
			ca:   ca.PublicKey(),
			key:  key,
			cert: signCert(t, ca, key, at(-time.Minute), at(time.Hour)),
		},
		{
			name: "valid with p384 key",
			ca:   ca.PublicKey(),
			key:  p384Key,
			cert: signCert(t, ca, p384Key, at(-time.Minute), at(time.Hour)),
		},
		{
			name: "valid after within grace period",
			ca:   ca.PublicKey(),
			key:  key,
			cert: signCert(t, ca, key, at(2*time.Second), at(time.Hour)),
		},
		{
			name: "about to expire",
			ca:   ca.PublicKey(),
			key:  key,
			cert: signCert(t, ca, key, at(-time.Hour), at(3*time.Second)),
		},
		{
			name: "valid from the epoch",
			ca:   ca.PublicKey(),
			key:  key,
			cert: signCert(t, ca, key, 0, at(time.Hour)),
		},
		{
			name: "valid forever",
			ca:   ca.PublicKey(),
			key:  key,
			cert: signCert(t, ca, key, at(-time.Minute), ssh.CertTimeInfinity),
		},
		{
			name: "valid with ed25519 key",
			ca:   ca.PublicKey(),
			key:  edKey,
			cert: signCert(t, ca, edKey, at(-time.Minute), at(time.Hour)),
		},
		{
			name: "valid with rsa key",
			ca:   ca.PublicKey(),
			key:  rsaKey,
			cert: signCert(t, ca, rsaKey, at(-time.Minute), at(time.Hour)),
		},
		{
			name:    "ed25519 certificate for ecdsa key",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, edKey, at(-time.Minute), at(time.Hour)),
			wantErr: ErrCertificateMismatch,
		},
		{
			name:    "rsa certificate for ed25519 key",
			ca:      ca.PublicKey(),
			key:     edKey,
			cert:    signCert(t, ca, rsaKey, at(-time.Minute), at(time.Hour)),
			wantErr: ErrCertificateMismatch,
		},
		{
			name:    "expired",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, key, at(-2*time.Hour), at(-time.Hour)),
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "just expired",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, key, at(-time.Hour), at(-3*time.Second)),
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "not yet valid",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, key, at(time.Minute), at(time.Hour)),
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "valid after just beyond grace period",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, key, at(10*time.Second), at(time.Hour)),
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "never valid",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, key, ssh.CertTimeInfinity, ssh.CertTimeInfinity),
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "unexpected certificate authority",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, otherCA, key, at(-time.Minute), at(time.Hour)),
			wantErr: ErrUnexpectedCertificateAuthority,
		},
		{
			name:    "certificate for different key",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, otherKey, at(-time.Minute), at(time.Hour)),
			wantErr: ErrCertificateMismatch,
		},
		{
			name:    "certificate for different curve",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, ca, p384Key, at(-time.Minute), at(time.Hour)),
			wantErr: ErrCertificateMismatch,
		},
		{
			name:    "expiry checked before certificate authority",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, otherCA, otherKey, at(-2*time.Hour), at(-time.Hour)),
			wantErr: ErrCertificateNotValid,
		},
		{
			name:    "certificate authority checked before key",
			ca:      ca.PublicKey(),
			key:     key,
			cert:    signCert(t, otherCA, otherKey, at(-time.Minute), at(time.Hour)),
			wantErr: ErrUnexpectedCertificateAuthority,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CertificateValid(tt.ca, sshPublicKey(t, tt.key), tt.cert)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("CertificateValid() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// fakeStore is a [Storage] whose results are controlled by the test. Methods
// not implemented here are not used by the code under test and will panic if
// called.
type fakeStore struct {
	Storage

	cert    *ssh.Certificate
	certErr error
	hasKey  bool

	signer    ssh.Signer
	signerErr error

	saved   *ssh.Certificate
	saveErr error
}

var _ Storage = &fakeStore{}

func (s *fakeStore) CertificateBytes() ([]byte, error) {
	if s.certErr != nil {
		return nil, s.certErr
	}

	return ssh.MarshalAuthorizedKey(s.cert), nil
}

func (s *fakeStore) Signer() (ssh.Signer, error) {
	return s.signer, s.signerErr
}

func (s *fakeStore) SaveCertificate(c *ssh.Certificate) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = c

	return nil
}

func (s *fakeStore) Certificate() (*ssh.Certificate, error) {
	return s.cert, s.certErr
}

func (s *fakeStore) HasPrivateKey() bool {
	return s.hasKey
}

// apiHTTPClient returns the *http.Client used by base's API client
func apiHTTPClient(t *testing.T, base *BaseCertificate) *http.Client {
	t.Helper()

	c, ok := base.client.ClientInterface.(*api.Client)
	if !ok {
		t.Fatalf("API client is %T, want *api.Client", base.client.ClientInterface)
	}

	h, ok := c.Client.(*http.Client)
	if !ok {
		t.Fatalf("API HTTP client is %T, want *http.Client", c.Client)
	}

	return h
}

func TestNewBaseCertificate(t *testing.T) {
	const server = "https://ca.example.com"

	t.Run("defaults", func(t *testing.T) {
		store := &fakeStore{}

		base, err := newBaseCertificate(server, store)
		if err != nil {
			t.Fatalf("newBaseCertificate() error = %v", err)
		}

		if base.store != store {
			t.Errorf("store was not set")
		}
		if base.h == nil {
			t.Fatalf("default HTTP client was not set")
		}
		if base.h == http.DefaultClient {
			t.Errorf("HTTP client is http.DefaultClient, want custom client")
		}
		if base.h.Timeout == 0 {
			t.Errorf("default HTTP client has no timeout")
		}
		if base.client == nil {
			t.Fatalf("API client was not set")
		}
		if got := apiHTTPClient(t, base); got != base.h {
			t.Errorf("API client does not use the configured HTTP client")
		}
		if got := base.client.ClientInterface.(*api.Client).Server; got != server+"/" {
			t.Errorf("API server = %q, want %q", got, server+"/")
		}
	})

	t.Run("with http client", func(t *testing.T) {
		h := &http.Client{Timeout: time.Minute}

		base, err := newBaseCertificate(server, &fakeStore{}, WithHTTPClient(h))
		if err != nil {
			t.Fatalf("newBaseCertificate() error = %v", err)
		}

		if base.h != h {
			t.Errorf("HTTP client was not set by WithHTTPClient")
		}
		if got := apiHTTPClient(t, base); got != h {
			t.Errorf("API client does not use the HTTP client from WithHTTPClient")
		}
	})

	t.Run("with store", func(t *testing.T) {
		store := &fakeStore{}

		base, err := newBaseCertificate(server, &fakeStore{}, WithStore(store))
		if err != nil {
			t.Fatalf("newBaseCertificate() error = %v", err)
		}

		if base.store != store {
			t.Errorf("store was not replaced by WithStore")
		}
	})

	t.Run("options applied in order", func(t *testing.T) {
		first := &http.Client{}
		second := &http.Client{}

		base, err := newBaseCertificate(server, &fakeStore{}, WithHTTPClient(first), WithHTTPClient(second))
		if err != nil {
			t.Fatalf("newBaseCertificate() error = %v", err)
		}

		if base.h != second {
			t.Errorf("last WithHTTPClient option did not take effect")
		}
	})
}

func TestRenewalDue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	// cert returns a certificate valid from now+after to now+before
	cert := func(after, before time.Duration) *ssh.Certificate {
		return &ssh.Certificate{
			ValidAfter:  uint64(now.Add(after).Unix()),
			ValidBefore: uint64(now.Add(before).Unix()),
		}
	}

	tests := []struct {
		name string
		cert *ssh.Certificate
		at   float64
		want bool
	}{
		{"just issued", cert(0, 10*time.Hour), 0.5, false},
		{"before half way", cert(-4*time.Hour, 6*time.Hour), 0.5, false},
		{"exactly half way", cert(-5*time.Hour, 5*time.Hour), 0.5, true},
		{"after half way", cert(-6*time.Hour, 4*time.Hour), 0.5, true},
		{"before renew at", cert(-7*time.Hour, 3*time.Hour), 0.8, false},
		{"after renew at", cert(-9*time.Hour, time.Hour), 0.8, true},
		{"renew at zero", cert(-time.Second, 10*time.Hour), 0, true},
		{"renew at one before expiry", cert(-9*time.Hour, time.Hour), 1, false},
		{"expired", cert(-10*time.Hour, -time.Hour), 0.5, true},
		{"expires now", cert(-10*time.Hour, 0), 1, true},
		{"not yet valid", cert(time.Hour, 10*time.Hour), 0.5, false},
		{"zero length validity", cert(-time.Hour, -time.Hour), 0.5, true},
		{"never expires", &ssh.Certificate{ValidAfter: 0, ValidBefore: ssh.CertTimeInfinity}, 0.5, false},
		{"valid from the epoch", &ssh.Certificate{ValidAfter: 0, ValidBefore: uint64(now.Add(time.Hour).Unix())}, 0.5, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RenewalDue(tt.cert, tt.at, now); got != tt.want {
				t.Errorf("RenewalDue() = %v, want %v", got, tt.want)
			}
		})
	}
}
