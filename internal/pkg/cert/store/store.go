// Package store provides the certificate store: a private key and its
// certificate, kept in a [Backend] such as a file or the system keyring.
package store

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/pem"
	"errors"
	"fmt"
	"os/user"
	"sync"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshcert"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"github.com/andrewheberle/sshagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ErrPrivateKeyExists is returned by GeneratePrivateKey, when created with
// [WithoutKeyReplacement], if a private key is already stored, as replacing
// an existing key (such as a SSH host key) would invalidate anything that
// trusts it
var ErrPrivateKeyExists = errors.New("private key already exists")

// Store is a certificate store. It holds one private key and its
// certificate in a [Backend], validates certificates against the trusted CA
// before saving them and adds them to or removes them from the SSH agent.
type Store struct {
	capubkey ssh.PublicKey
	backend  Backend

	// options
	keyType    sshkey.KeyType
	curve      elliptic.Curve
	dial       dialer
	replaceKey bool

	// internal state
	mu   sync.RWMutex
	user string
}

var _ cert.Storage = &Store{}

// New creates a [Store] that keeps its private key and certificate in
// backend and only accepts certificates signed by capubkey
func New(capubkey ssh.PublicKey, backend Backend, opts ...Option) (*Store, error) {
	// set up defaults
	s := &Store{
		capubkey:   capubkey,
		backend:    backend,
		keyType:    sshkey.KeyTypeECDSA,
		curve:      elliptic.P256(),
		dial:       dialAgent,
		replaceKey: true,
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

// NewFile creates a [Store] using a [FileBackend] for the private key at
// keypath. An existing key file is never replaced (see
// [WithoutKeyReplacement]).
func NewFile(capubkey ssh.PublicKey, keypath string, opts ...Option) (*Store, error) {
	return New(capubkey, NewFileBackend(keypath), append([]Option{WithoutKeyReplacement()}, opts...)...)
}

// NewKeyring creates a [Store] using a [KeyringBackend] for the current user
func NewKeyring(capubkey ssh.PublicKey, opts ...Option) (*Store, error) {
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("error looking up user %w", err)
	}

	return New(capubkey, NewKeyringBackend(u.Username), opts...)
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
// returned as [cert.ErrAddingToAgent].
func (s *Store) AddToAgent() error {
	s.mu.RLock()
	key, _, keyErr := s.key()
	c, _, certErr := s.cert()
	s.mu.RUnlock()

	if keyErr != nil {
		return fmt.Errorf("%w: %w", cert.ErrKeyNotFound, keyErr)
	}
	if certErr != nil {
		return fmt.Errorf("%w: %w", cert.ErrCertificateNotFound, certErr)
	}

	a, closeAgent, err := s.dial()
	if err != nil {
		return fmt.Errorf("%w: could not connect to agent: %w", cert.ErrAddingToAgent, err)
	}
	defer func() { _ = closeAgent() }()

	if err := a.Add(sshcert.AddedKey(key, c)); err != nil {
		return fmt.Errorf("%w: %w", cert.ErrAddingToAgent, err)
	}

	return nil
}

// Returns a *[ssh.Certificate] for the current certificate. This
// will return an error if no valid certificate is found.
func (s *Store) Certificate() (*ssh.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, _, err := s.cert()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cert.ErrCertificateNotFound, err)
	}

	return c, nil
}

// Returns a byte slice containing the stored OpenSSH certificate exactly as
// saved. This will return an error if the certificate is missing or cannot be
// parsed.
func (s *Store) CertificateBytes() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, c, err := s.cert()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cert.ErrCertificateNotFound, err)
	}

	return c, nil
}

// DeleteCertificate deletes the current certificate. It is not an error if
// there is no certificate.
func (s *Store) DeleteCertificate() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.backend.Delete(Cert); err != nil {
		return fmt.Errorf("could not delete certificate: %w", err)
	}

	return nil
}

// GeneratePrivateKey generates a new SSH private key of the configured type
// (see [WithKeyType]), replacing any existing key and deleting any existing
// certificate. With [WithoutKeyReplacement] this returns
// [ErrPrivateKeyExists] rather than replace an existing key.
func (s *Store) GeneratePrivateKey() error {
	key, err := sshkey.GeneratePrivateKey(s.keyType, s.curve)
	if err != nil {
		return fmt.Errorf("could not generate private key: %w", err)
	}

	// encode to openssh format
	privKey, err := ssh.MarshalPrivateKey(key, s.user)
	if err != nil {
		return fmt.Errorf("could not marshal key: %w", err)
	}

	pemBytes := pem.EncodeToMemory(privKey)
	if pemBytes == nil {
		return fmt.Errorf("could not PEM encode key")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.replaceKey {
		// never replace an existing key, even one that cannot be parsed
		if _, err := s.backend.Get(Key); err == nil {
			return ErrPrivateKeyExists
		} else if !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("could not check for existing key: %w", err)
		}
	}

	if err := s.backend.Put(Key, pemBytes); err != nil {
		return fmt.Errorf("could not store key: %w", err)
	}

	// delete any existing cert as this is invalid after the key has been updated
	if err := s.backend.Delete(Cert); err != nil {
		return fmt.Errorf("could not delete certificate: %w", err)
	}

	return nil
}

// Returns true or false depending if a certificate exists
func (s *Store) HasCertificate() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c, _, _ := s.cert()
	return c != nil
}

// Returns true of false depending if a private key exists
func (s *Store) HasPrivateKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, _, _ := s.key()

	return key != nil
}

// Returns a [crypto.PrivateKey] for the current private key. This will
// return an error if no valid private key is found.
func (s *Store) PrivateKey() (crypto.PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, _, err := s.key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cert.ErrKeyNotFound, err)
	}

	return key, nil
}

// Returns a byte slice containing the OpenSSH private key. This will return
// an error if no valid private key is found.
func (s *Store) PrivateKeyBytes() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, key, err := s.key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cert.ErrKeyNotFound, err)
	}

	return key, nil
}

// Returns a [ssh.PublicKey] for the current private key. This will
// return an error if no valid private key is found.
func (s *Store) PublicKey() (ssh.PublicKey, error) {
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
func (s *Store) PublicKeyBytes() ([]byte, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}

	// marshal into authorized_keys format
	pubBytes := ssh.MarshalAuthorizedKey(pub)

	// return as public key without a newline
	return bytes.TrimSuffix(pubBytes, []byte("\n")), nil
}

// RemoveFromAgent removes the current certificate from the SSH Agent, leaving
// the private key and any other identities in place. Nothing is done if there
// is no certificate, if no agent can be connected to or if the agent does not
// hold the certificate. Other failures are returned as
// [cert.ErrRemovingFromAgent].
func (s *Store) RemoveFromAgent() error {
	s.mu.RLock()
	c, _, err := s.cert()
	s.mu.RUnlock()

	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %w", cert.ErrRemovingFromAgent, err)
	}

	// a certificate cannot be held by an agent that is not running
	a, closeAgent, err := s.dial()
	if err != nil {
		return nil
	}
	defer func() { _ = closeAgent() }()

	if err := sshcert.RemoveFromAgent(a, c); err != nil {
		return fmt.Errorf("%w: %w", cert.ErrRemovingFromAgent, err)
	}

	return nil
}

// Saves the provided [ssh.Certificate]
func (s *Store) SaveCertificate(c *ssh.Certificate) error {
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

	return s.backend.Put(Cert, ssh.MarshalAuthorizedKey(c))
}

// Returns a [ssh.Signer] for the current private key.
// This will return an error if no private key is found.
func (s *Store) Signer() (ssh.Signer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.signer()
}

func (s *Store) cert() (*ssh.Certificate, []byte, error) {
	b, err := s.backend.Get(Cert)
	if err != nil {
		return nil, nil, err
	}

	c, err := sshcert.ParseCert(b)
	if err != nil {
		return nil, nil, err
	}

	return c, b, nil
}

// key returns the parsed private key and the raw stored key. ECDSA, Ed25519
// and RSA keys are supported.
func (s *Store) key() (crypto.Signer, []byte, error) {
	k, err := s.backend.Get(Key)
	if err != nil {
		return nil, nil, err
	}

	key, err := sshkey.ParsePrivateKey(k)
	if err != nil {
		return nil, nil, err
	}

	return key, k, nil
}

func (s *Store) signer() (ssh.Signer, error) {
	key, _, err := s.key()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", cert.ErrKeyNotFound, err)
	}

	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		return nil, fmt.Errorf("could not create signer: %w", err)
	}

	return signer, nil
}

type Option func(*Store)

// WithKeyType sets the type of key created by GeneratePrivateKey. The default
// is [sshkey.KeyTypeECDSA]. Existing keys of any supported type can be used
// regardless of this setting.
func WithKeyType(keyType sshkey.KeyType) Option {
	return func(s *Store) {
		s.keyType = keyType
	}
}

// WithCurve sets the curve used when GeneratePrivateKey creates an ECDSA key.
// The default is P-256.
func WithCurve(curve elliptic.Curve) Option {
	return func(s *Store) {
		s.curve = curve
	}
}

// WithAgent uses the provided agent instead of connecting to the local SSH
// agent when AddToAgent is called. The agent is not closed by the [Store].
func WithAgent(a agent.ExtendedAgent) Option {
	return func(s *Store) {
		s.dial = func() (agent.ExtendedAgent, func() error, error) {
			return a, func() error { return nil }, nil
		}
	}
}

// WithoutKeyReplacement makes GeneratePrivateKey return
// [ErrPrivateKeyExists] rather than replace an existing private key, even
// one that cannot be parsed
func WithoutKeyReplacement() Option {
	return func(s *Store) {
		s.replaceKey = false
	}
}
