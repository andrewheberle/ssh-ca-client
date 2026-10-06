package filestore

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/user"
	"sync"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshcert"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"github.com/andrewheberle/sshagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrCertificateMismatch            = cert.ErrCertificateMismatch
	ErrCertificateNotFound            = cert.ErrCertificateNotFound
	ErrCertificateNotValid            = cert.ErrCertificateNotValid
	ErrAddingToAgent                  = cert.ErrAddingToAgent
	ErrKeyNotFound                    = cert.ErrKeyNotFound
	ErrSignerNotFound                 = cert.ErrSignerNotFound
	ErrUnexpectedCertificateAuthority = cert.ErrUnexpectedCertificateAuthority

	// ErrPrivateKeyExists is returned by GeneratePrivateKey when a key file
	// already exists, as overwriting an existing key (such as a SSH host key)
	// would invalidate anything that trusts it
	ErrPrivateKeyExists = errors.New("private key file already exists")
)

type Storage struct {
	capubkey ssh.PublicKey
	keypath  string

	// options
	keyType sshkey.KeyType
	curve   elliptic.Curve
	dial    dialer

	// internal state
	mu   sync.RWMutex
	user string
}

var _ cert.Storage = &Storage{}

func New(capubkey ssh.PublicKey, keypath string, opts ...Option) (*Storage, error) {
	// set up defaults
	s := &Storage{
		capubkey: capubkey,
		keyType:  sshkey.KeyTypeECDSA,
		curve:    elliptic.P256(),
		dial:     dialAgent,
		keypath:  keypath,
	}

	for _, o := range opts {
		o(s)
	}

	// get user details
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("error looking up user %w", err)
	}
	s.user = u.Username

	return s, nil
}

// dialer connects to an SSH agent, returning the agent and a function that
// closes the connection
type dialer func() (agent.ExtendedAgent, func() error, error)

// dialAgent connects to the local SSH agent
func dialAgent() (agent.ExtendedAgent, func() error, error) {
	a, err := sshagent.NewAgent()
	if err != nil {
		return nil, nil, err
	}

	return a, a.Close, nil
}

// Adds the existing key and certificate to the SSH Agent. A new connection to
// the agent is made for each call, so the agent does not need to be running
// until this is called. Failures connecting to or adding to the agent are
// returned as [ErrAddingToAgent].
func (s *Storage) AddToAgent() error {
	s.mu.RLock()
	key, _, keyErr := s.key()
	cert, _, certErr := s.cert()
	s.mu.RUnlock()

	if keyErr != nil {
		return fmt.Errorf("%w: %w", ErrKeyNotFound, keyErr)
	}
	if certErr != nil {
		return fmt.Errorf("%w: %w", ErrCertificateNotFound, certErr)
	}

	a, closeAgent, err := s.dial()
	if err != nil {
		return fmt.Errorf("%w: could not connect to agent: %w", ErrAddingToAgent, err)
	}
	defer closeAgent()

	if err := a.Add(sshcert.AddedKey(key, cert)); err != nil {
		return fmt.Errorf("%w: %w", ErrAddingToAgent, err)
	}

	return nil
}

// Returns a *[ssh.Certificate] for the current certificate. This
// will return an error if no valid private key is found.
func (s *Storage) Certificate() (*ssh.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, _, err := s.cert()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificateNotFound, err)
	}

	return cert, nil
}

// Returns a byte slice containing the stored OpenSSH certificate exactly as
// saved. This will return an error if the certificate is missing or cannot be
// parsed.
func (s *Storage) CertificateBytes() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, cert, err := s.cert()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertificateNotFound, err)
	}

	return cert, nil
}

// GeneratePrivateKey generates a new SSH private key of the configured type
// (see [WithKeyType]). This returns [ErrPrivateKeyExists] rather than
// overwrite an existing key file.
func (s *Storage) GeneratePrivateKey() error {
	key, err := sshkey.GeneratePrivateKey(s.keyType, s.curve)
	if err != nil {
		return fmt.Errorf("could not generate private key: %w", err)
	}

	// encode to openssh format
	privKey, err := ssh.MarshalPrivateKey(key, s.user)
	if err != nil {
		return fmt.Errorf("could not marshal key: %w", err)
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, privKey); err != nil {
		return fmt.Errorf("could not PEM encode key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// never overwrite an existing key, even one that cannot be parsed
	if _, err := os.Lstat(s.keypath); err == nil {
		return fmt.Errorf("%w: %s", ErrPrivateKeyExists, s.keypath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("could not check for existing key file: %w", err)
	}

	if err := atomic.WriteFile(s.keypath, buf, atomic.FileMode(0600)); err != nil {
		return fmt.Errorf("could not write key file: %w", err)
	}

	// delete any existing cert as this is invalid after the key has been updated
	if err := os.Remove(s.keypath + "-cert.pub"); err != nil {
		// any error here except os.ErrNotExist is bad
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not delete certificate: %w", err)
		}
	}

	return nil
}

// Returns true or false depending if a certificate exists
func (s *Storage) HasCertificate() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cert, _, _ := s.cert()
	return cert != nil
}

// Returns true of false depending if a private key exists
func (s *Storage) HasPrivateKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, _, _ := s.key()

	return key != nil
}

// Returns a [crypto.PrivateKey] for the current private key. This will
// return an error if no valid private key is found.
func (s *Storage) PrivateKey() (crypto.PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, _, err := s.key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	}

	return key, nil
}

// Returns a byte slice containing the OpenSSH private key. This will return
// an error if no valid private key is found.
func (s *Storage) PrivateKeyBytes() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, key, err := s.key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	}

	return key, nil
}

// Returns a [ssh.PublicKey] for the current private key. This will
// return an error if no valid private key is found.
func (s *Storage) PublicKey() (ssh.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	signer, err := s.signer()
	if err != nil {
		return nil, err
	}

	return signer.PublicKey(), nil
}

// Returns a byte slice containing the OpenSSH public key for the current
// private key. This will return an error if no valid private key is
// found.
func (s *Storage) PublicKeyBytes() ([]byte, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}

	// marshal into authorized_keys format
	pubBytes := ssh.MarshalAuthorizedKey(pub)

	// return as public key without a newline
	return bytes.TrimSuffix(pubBytes, []byte("\n")), nil
}

// Saves the provided [ssh.Certificate]
func (s *Storage) SaveCertificate(c *ssh.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	signer, err := s.signer()
	if err != nil {
		return err
	}

	// Validate the certificate
	if err := cert.CertificateValid(s.capubkey, signer.PublicKey(), c); err != nil {
		return err
	}

	certBytes := ssh.MarshalAuthorizedKey(c)

	return atomic.WriteFile(s.keypath+"-cert.pub", bytes.NewReader(certBytes), atomic.FileMode(0644))
}

// Returns a [ssh.Signer] for the current private key in the SSH Agent.
// This will return an error if no private key is found.
func (s *Storage) Signer() (ssh.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.signer()
}

func (s *Storage) cert() (*ssh.Certificate, []byte, error) {
	c, err := os.ReadFile(s.keypath + "-cert.pub")
	if err != nil {
		return nil, nil, err
	}

	cert, err := sshcert.ParseCert(c)
	if err != nil {
		return nil, nil, err
	}

	return cert, c, nil
}

// key returns the parsed private key and the raw key file contents. ECDSA,
// Ed25519 and RSA keys are supported.
func (s *Storage) key() (crypto.Signer, []byte, error) {
	k, err := os.ReadFile(s.keypath)
	if err != nil {
		return nil, nil, err
	}

	key, err := sshkey.ParsePrivateKey(k)
	if err != nil {
		return nil, nil, err
	}

	return key, k, nil
}

func (s *Storage) signer() (ssh.Signer, error) {
	key, _, err := s.key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	}

	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		return nil, fmt.Errorf("could not create signer: %w", err)
	}

	return signer, nil
}

type Option func(*Storage)

// WithKeyType sets the type of key created by GeneratePrivateKey. The default
// is [sshkey.KeyTypeECDSA]. Existing keys of any supported type can be used
// regardless of this setting.
func WithKeyType(keyType sshkey.KeyType) Option {
	return func(c *Storage) {
		c.keyType = keyType
	}
}

// WithCurve sets the curve used when GeneratePrivateKey creates an ECDSA key.
// The default is P-256.
func WithCurve(curve elliptic.Curve) Option {
	return func(c *Storage) {
		c.curve = curve
	}
}

// WithAgent uses the provided agent instead of connecting to the local SSH
// agent when AddToAgent is called. The agent is not closed by the [Storage].
func WithAgent(a agent.ExtendedAgent) Option {
	return func(c *Storage) {
		c.dial = func() (agent.ExtendedAgent, func() error, error) {
			return a, func() error { return nil }, nil
		}
	}
}
