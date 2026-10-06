package keyringstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os/user"
	"strings"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/keyringutil"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// newAgent returns an in-memory SSH agent
func newAgent() agent.ExtendedAgent {
	return agent.NewKeyring().(agent.ExtendedAgent)
}

// newStorage returns a *Storage backed by a freshly initialised mock keyring
// and an in-memory agent (unless overridden by opts)
func newStorage(t *testing.T, ca ssh.Signer, opts ...Option) *Storage {
	t.Helper()

	keyring.MockInit()

	s, err := New(ca.PublicKey(), append([]Option{WithAgent(newAgent())}, opts...)...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return s
}

// pemEncode PEM encodes block and fails the test on error
func pemEncode(t *testing.T, block *pem.Block) []byte {
	t.Helper()

	b := pem.EncodeToMemory(block)
	if b == nil {
		t.Fatalf("could not PEM encode block")
	}

	return b
}

// generatePrivateKey generates a key in the store and fails the test on error
func generatePrivateKey(t *testing.T, s *Storage) {
	t.Helper()

	if err := s.GeneratePrivateKey(); err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}
}

// storeKey writes raw private key data to the keyring
func storeKey(t *testing.T, s *Storage, data []byte) {
	t.Helper()

	if err := keyring.Set(storeKeyService, s.user, string(data)); err != nil {
		t.Fatalf("keyring.Set() error = %v", err)
	}
}

// storeCert writes raw certificate data to the keyring
func storeCert(t *testing.T, s *Storage, data []byte) {
	t.Helper()

	if err := keyring.Set(storeCertService, s.user, string(data)); err != nil {
		t.Fatalf("keyring.Set() error = %v", err)
	}
}

// signCert signs a user certificate for pub using ca that is valid between
// validAfter and validBefore
func signCert(t *testing.T, ca ssh.Signer, pub ssh.PublicKey, validAfter, validBefore time.Time) *ssh.Certificate {
	t.Helper()

	c := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test@example.com",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
	}

	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("could not sign certificate: %v", err)
	}

	return c
}

// validCert generates a key in the store and returns a currently valid
// certificate for it signed by ca
func validCert(t *testing.T, s *Storage, ca ssh.Signer) *ssh.Certificate {
	t.Helper()

	generatePrivateKey(t, s)

	pub, err := s.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() error = %v", err)
	}

	now := time.Now()

	return signCert(t, ca, pub, now.Add(-time.Minute), now.Add(time.Hour))
}

func TestNew(t *testing.T) {
	ca := newCA(t)

	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current() error = %v", err)
	}

	t.Run("defaults", func(t *testing.T) {
		keyring.MockInit()

		s, err := New(ca.PublicKey(), WithAgent(newAgent()))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if s.curve != elliptic.P256() {
			t.Errorf("curve = %v, want %v", s.curve.Params().Name, elliptic.P256().Params().Name)
		}
		if s.user != u.Username {
			t.Errorf("user = %q, want %q", s.user, u.Username)
		}
		if !bytes.Equal(s.capubkey.Marshal(), ca.PublicKey().Marshal()) {
			t.Errorf("capubkey does not match CA public key")
		}
	})

	t.Run("with options", func(t *testing.T) {
		a := newAgent()
		s := newStorage(t, ca, WithCurve(elliptic.P384()), WithAgent(a))

		if s.curve != elliptic.P384() {
			t.Errorf("curve = %v, want %v", s.curve.Params().Name, elliptic.P384().Params().Name)
		}
		if got, _, err := s.dial(); err != nil || got != a {
			t.Errorf("agent was not set by WithAgent")
		}
	})
}

func TestStorage_GeneratePrivateKey(t *testing.T) {
	ca := newCA(t)

	tests := []struct {
		name  string
		curve elliptic.Curve
		want  elliptic.Curve
	}{
		{"default curve", nil, elliptic.P256()},
		{"p256", elliptic.P256(), elliptic.P256()},
		{"p384", elliptic.P384(), elliptic.P384()},
		{"p521", elliptic.P521(), elliptic.P521()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []Option
			if tt.curve != nil {
				opts = append(opts, WithCurve(tt.curve))
			}
			s := newStorage(t, ca, opts...)

			generatePrivateKey(t, s)

			k, err := keyring.Get(storeKeyService, s.user)
			if err != nil {
				t.Fatalf("key not stored in keyring: %v", err)
			}

			key, err := parseECDSAKey([]byte(k))
			if err != nil {
				t.Fatalf("stored key could not be parsed: %v", err)
			}

			if key.Curve != tt.want {
				t.Errorf("key curve = %v, want %v", key.Curve.Params().Name, tt.want.Params().Name)
			}
		})
	}

	t.Run("new key replaces existing key", func(t *testing.T) {
		s := newStorage(t, ca)

		generatePrivateKey(t, s)
		first, err := s.PublicKeyBytes()
		if err != nil {
			t.Fatalf("PublicKeyBytes() error = %v", err)
		}

		generatePrivateKey(t, s)
		second, err := s.PublicKeyBytes()
		if err != nil {
			t.Fatalf("PublicKeyBytes() error = %v", err)
		}

		if bytes.Equal(first, second) {
			t.Errorf("GeneratePrivateKey() did not replace existing key")
		}
	})

	t.Run("removes existing certificate", func(t *testing.T) {
		s := newStorage(t, ca)

		if err := s.SaveCertificate(validCert(t, s, ca)); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		generatePrivateKey(t, s)

		if _, err := keyring.Get(storeCertService, s.user); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("certificate still in keyring after GeneratePrivateKey(), err = %v", err)
		}
		if _, err := s.Certificate(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("Certificate() error = %v, want %v", err, ErrCertificateNotFound)
		}
	})

	t.Run("unsupported curve", func(t *testing.T) {
		// P-224 is supported by crypto/ecdsa but not by OpenSSH
		s := newStorage(t, ca, WithCurve(elliptic.P224()))

		if err := s.GeneratePrivateKey(); err == nil {
			t.Errorf("GeneratePrivateKey() error = nil, want error")
		}

		if _, err := keyring.Get(storeKeyService, s.user); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("key was stored in keyring despite error, err = %v", err)
		}
	})

	t.Run("keyring error", func(t *testing.T) {
		s := newStorage(t, ca)

		keyringErr := errors.New("keyring unavailable")
		keyring.MockInitWithError(keyringErr)

		if err := s.GeneratePrivateKey(); !errors.Is(err, keyringErr) {
			t.Errorf("GeneratePrivateKey() error = %v, want %v", err, keyringErr)
		}
	})
}

func TestStorage_PublicKey(t *testing.T) {
	ca := newCA(t)

	t.Run("no key", func(t *testing.T) {
		s := newStorage(t, ca)

		if _, err := s.PublicKey(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PublicKey() error = %v, want %v", err, ErrKeyNotFound)
		}
		if _, err := s.PublicKeyBytes(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PublicKeyBytes() error = %v, want %v", err, ErrKeyNotFound)
		}
	})

	t.Run("invalid key in keyring", func(t *testing.T) {
		s := newStorage(t, ca)

		if err := keyring.Set(storeKeyService, s.user, "not a key"); err != nil {
			t.Fatalf("keyring.Set() error = %v", err)
		}

		if _, err := s.PublicKey(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PublicKey() error = %v, want %v", err, ErrKeyNotFound)
		}
	})

	t.Run("undersized rsa key in keyring", func(t *testing.T) {
		s := newStorage(t, ca)

		// RSA keys below the minimum size are not supported
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("could not generate key: %v", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatalf("could not marshal key: %v", err)
		}
		if err := keyring.Set(storeKeyService, s.user, string(pemEncode(t, block))); err != nil {
			t.Fatalf("keyring.Set() error = %v", err)
		}

		if _, err := s.PublicKey(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PublicKey() error = %v, want %v", err, ErrKeyNotFound)
		}
	})

	t.Run("valid key", func(t *testing.T) {
		s := newStorage(t, ca)
		generatePrivateKey(t, s)

		k, err := keyring.Get(storeKeyService, s.user)
		if err != nil {
			t.Fatalf("keyring.Get() error = %v", err)
		}
		key, err := parseECDSAKey([]byte(k))
		if err != nil {
			t.Fatalf("ParseKey() error = %v", err)
		}
		want, err := ssh.NewPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("NewPublicKey() error = %v", err)
		}

		pub, err := s.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey() error = %v", err)
		}
		if !bytes.Equal(pub.Marshal(), want.Marshal()) {
			t.Errorf("PublicKey() does not match stored private key")
		}

		pubBytes, err := s.PublicKeyBytes()
		if err != nil {
			t.Fatalf("PublicKeyBytes() error = %v", err)
		}
		if bytes.HasSuffix(pubBytes, []byte("\n")) {
			t.Errorf("PublicKeyBytes() has trailing newline")
		}
		if !strings.HasPrefix(string(pubBytes), ssh.KeyAlgoECDSA256+" ") {
			t.Errorf("PublicKeyBytes() = %q, want prefix %q", pubBytes, ssh.KeyAlgoECDSA256)
		}

		parsed, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
		if err != nil {
			t.Fatalf("PublicKeyBytes() could not be parsed: %v", err)
		}
		if !bytes.Equal(parsed.Marshal(), want.Marshal()) {
			t.Errorf("PublicKeyBytes() does not match stored private key")
		}
	})
}

func TestStorage_HasPrivateKey(t *testing.T) {
	ca := newCA(t)

	t.Run("no key", func(t *testing.T) {
		s := newStorage(t, ca)

		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true, want false")
		}
	})

	t.Run("invalid key in keyring", func(t *testing.T) {
		s := newStorage(t, ca)

		if err := keyring.Set(storeKeyService, s.user, "not a key"); err != nil {
			t.Fatalf("keyring.Set() error = %v", err)
		}

		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true, want false")
		}
	})

	t.Run("undersized rsa key in keyring", func(t *testing.T) {
		s := newStorage(t, ca)

		// RSA keys below the minimum size are not supported
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("could not generate key: %v", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatalf("could not marshal key: %v", err)
		}
		if err := keyring.Set(storeKeyService, s.user, string(pemEncode(t, block))); err != nil {
			t.Fatalf("keyring.Set() error = %v", err)
		}

		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true, want false")
		}
	})

	t.Run("keyring error", func(t *testing.T) {
		s := newStorage(t, ca)
		generatePrivateKey(t, s)

		keyring.MockInitWithError(errors.New("keyring unavailable"))

		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true, want false")
		}
	})

	t.Run("valid key", func(t *testing.T) {
		s := newStorage(t, ca)
		generatePrivateKey(t, s)

		if !s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = false, want true")
		}
	})

	t.Run("key generation failed", func(t *testing.T) {
		// P-224 is supported by crypto/ecdsa but not by OpenSSH
		s := newStorage(t, ca, WithCurve(elliptic.P224()))

		if err := s.GeneratePrivateKey(); err == nil {
			t.Fatalf("GeneratePrivateKey() error = nil, want error")
		}

		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true, want false")
		}
	})
}

func TestStorage_HasCertificate(t *testing.T) {
	ca := newCA(t)

	t.Run("no certificate", func(t *testing.T) {
		s := newStorage(t, ca)

		if s.HasCertificate() {
			t.Errorf("HasCertificate() = true, want false")
		}
	})

	t.Run("invalid certificate", func(t *testing.T) {
		s := newStorage(t, ca)
		storeCert(t, s, []byte("not a certificate"))

		if s.HasCertificate() {
			t.Errorf("HasCertificate() = true, want false")
		}
	})

	t.Run("public key rather than certificate", func(t *testing.T) {
		s := newStorage(t, ca)
		storeCert(t, s, ssh.MarshalAuthorizedKey(ca.PublicKey()))

		if s.HasCertificate() {
			t.Errorf("HasCertificate() = true, want false")
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		s := newStorage(t, ca)
		if err := s.SaveCertificate(validCert(t, s, ca)); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		if !s.HasCertificate() {
			t.Errorf("HasCertificate() = false, want true")
		}
	})

	t.Run("certificate removed by new private key", func(t *testing.T) {
		s := newStorage(t, ca)
		if err := s.SaveCertificate(validCert(t, s, ca)); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		generatePrivateKey(t, s)

		if s.HasCertificate() {
			t.Errorf("HasCertificate() = true, want false")
		}
	})

	t.Run("keyring error", func(t *testing.T) {
		s := newStorage(t, ca)
		if err := s.SaveCertificate(validCert(t, s, ca)); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		keyring.MockInitWithError(errors.New("keyring unavailable"))

		if s.HasCertificate() {
			t.Errorf("HasCertificate() = true, want false")
		}
	})
}

func TestStorage_PrivateKey(t *testing.T) {
	ca := newCA(t)

	// assertNoKey checks both PrivateKey and PrivateKeyBytes report no key
	assertNoKey := func(t *testing.T, s *Storage) {
		t.Helper()

		if _, err := s.PrivateKey(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PrivateKey() error = %v, want %v", err, ErrKeyNotFound)
		}
		if _, err := s.PrivateKeyBytes(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PrivateKeyBytes() error = %v, want %v", err, ErrKeyNotFound)
		}
	}

	t.Run("no key", func(t *testing.T) {
		assertNoKey(t, newStorage(t, ca))
	})

	t.Run("invalid key", func(t *testing.T) {
		s := newStorage(t, ca)
		storeKey(t, s, []byte("not a key"))

		assertNoKey(t, s)
	})

	t.Run("undersized rsa key", func(t *testing.T) {
		s := newStorage(t, ca)

		// RSA keys below the minimum size are not supported
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("could not generate key: %v", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatalf("could not marshal key: %v", err)
		}
		storeKey(t, s, pemEncode(t, block))

		assertNoKey(t, s)
	})

	t.Run("keyring error", func(t *testing.T) {
		s := newStorage(t, ca)
		generatePrivateKey(t, s)

		keyring.MockInitWithError(errors.New("keyring unavailable"))

		if _, err := s.PrivateKey(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PrivateKey() error = %v, want %v", err, ErrKeyNotFound)
		}
		if _, err := s.PrivateKeyBytes(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("PrivateKeyBytes() error = %v, want %v", err, ErrKeyNotFound)
		}
	})

	t.Run("existing key", func(t *testing.T) {
		s := newStorage(t, ca)

		// a key generated outside the store (eg by ssh-keygen)
		want, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("could not generate key: %v", err)
		}
		block, err := ssh.MarshalPrivateKey(want, "someone@example.com")
		if err != nil {
			t.Fatalf("could not marshal key: %v", err)
		}
		stored := pemEncode(t, block)
		storeKey(t, s, stored)

		got, err := s.PrivateKey()
		if err != nil {
			t.Fatalf("PrivateKey() error = %v", err)
		}
		if !want.Equal(got) {
			t.Errorf("PrivateKey() does not match stored key")
		}

		gotBytes, err := s.PrivateKeyBytes()
		if err != nil {
			t.Fatalf("PrivateKeyBytes() error = %v", err)
		}
		parsed, err := parseECDSAKey(gotBytes)
		if err != nil {
			t.Fatalf("PrivateKeyBytes() could not be parsed: %v", err)
		}
		if !want.Equal(parsed) {
			t.Errorf("PrivateKeyBytes() does not match stored key")
		}

		// the stored bytes are returned unchanged, preserving the comment,
		// and are the same on every call
		if !bytes.Equal(gotBytes, stored) {
			t.Errorf("PrivateKeyBytes() = %q, want stored bytes %q", gotBytes, stored)
		}
		again, err := s.PrivateKeyBytes()
		if err != nil {
			t.Fatalf("PrivateKeyBytes() error = %v", err)
		}
		if !bytes.Equal(again, gotBytes) {
			t.Errorf("PrivateKeyBytes() returned different bytes on second call")
		}
	})

	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, curve := range curves {
		t.Run("generated "+curve.Params().Name+" key", func(t *testing.T) {
			s := newStorage(t, ca, WithCurve(curve))
			generatePrivateKey(t, s)

			key, err := s.PrivateKey()
			if err != nil {
				t.Fatalf("PrivateKey() error = %v", err)
			}
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("PrivateKey() = %T, want *ecdsa.PrivateKey", key)
			}
			if ecKey.Curve != curve {
				t.Errorf("PrivateKey() curve = %v, want %v", ecKey.Curve.Params().Name, curve.Params().Name)
			}

			// the private key must match the public key and signer
			pub, err := s.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey() error = %v", err)
			}
			want, err := ssh.NewPublicKey(&ecKey.PublicKey)
			if err != nil {
				t.Fatalf("NewPublicKey() error = %v", err)
			}
			if !bytes.Equal(pub.Marshal(), want.Marshal()) {
				t.Errorf("PrivateKey() does not match PublicKey()")
			}

			// the PEM bytes must be an unencrypted OpenSSH private key for
			// the same key
			pemBytes, err := s.PrivateKeyBytes()
			if err != nil {
				t.Fatalf("PrivateKeyBytes() error = %v", err)
			}
			block, _ := pem.Decode(pemBytes)
			if block == nil {
				t.Fatalf("PrivateKeyBytes() is not PEM encoded")
			}
			if block.Type != "OPENSSH PRIVATE KEY" {
				t.Errorf("PrivateKeyBytes() PEM type = %q, want %q", block.Type, "OPENSSH PRIVATE KEY")
			}
			signer, err := ssh.ParsePrivateKey(pemBytes)
			if err != nil {
				t.Fatalf("PrivateKeyBytes() could not be parsed: %v", err)
			}
			if !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
				t.Errorf("PrivateKeyBytes() does not match PublicKey()")
			}
		})
	}
}

func TestStorage_Signer(t *testing.T) {
	ca := newCA(t)

	t.Run("no key", func(t *testing.T) {
		s := newStorage(t, ca)

		if _, err := s.Signer(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("Signer() error = %v, want %v", err, ErrKeyNotFound)
		}
	})

	t.Run("valid key", func(t *testing.T) {
		s := newStorage(t, ca)
		generatePrivateKey(t, s)

		signer, err := s.Signer()
		if err != nil {
			t.Fatalf("Signer() error = %v", err)
		}

		pub, err := s.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey() error = %v", err)
		}
		if !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
			t.Errorf("Signer() public key does not match PublicKey()")
		}

		data := []byte("some data to sign")
		sig, err := signer.Sign(rand.Reader, data)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if err := pub.Verify(data, sig); err != nil {
			t.Errorf("signature did not verify: %v", err)
		}
	})
}

func TestStorage_SaveCertificate(t *testing.T) {
	ca := newCA(t)
	otherCA := newCA(t)
	now := time.Now()

	// a public key that does not belong to the store
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}
	otherPub, err := ssh.NewPublicKey(&otherKey.PublicKey)
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}

	tests := []struct {
		name    string
		cert    func(t *testing.T, s *Storage) *ssh.Certificate
		wantErr error
	}{
		{
			name: "valid",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				return validCert(t, s, ca)
			},
		},
		{
			name: "valid after within grace period",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				generatePrivateKey(t, s)
				pub, _ := s.PublicKey()
				return signCert(t, ca, pub, now.Add(3*time.Second), now.Add(time.Hour))
			},
		},
		{
			name: "no key",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				return signCert(t, ca, otherPub, now.Add(-time.Minute), now.Add(time.Hour))
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name: "expired",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				generatePrivateKey(t, s)
				pub, _ := s.PublicKey()
				return signCert(t, ca, pub, now.Add(-2*time.Hour), now.Add(-time.Hour))
			},
			wantErr: ErrCertificateNotValid,
		},
		{
			name: "not yet valid",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				generatePrivateKey(t, s)
				pub, _ := s.PublicKey()
				return signCert(t, ca, pub, now.Add(time.Minute), now.Add(time.Hour))
			},
			wantErr: ErrCertificateNotValid,
		},
		{
			name: "unexpected certificate authority",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				generatePrivateKey(t, s)
				pub, _ := s.PublicKey()
				return signCert(t, otherCA, pub, now.Add(-time.Minute), now.Add(time.Hour))
			},
			wantErr: ErrUnexpectedCertificateAuthority,
		},
		{
			name: "certificate for different key",
			cert: func(t *testing.T, s *Storage) *ssh.Certificate {
				generatePrivateKey(t, s)
				return signCert(t, ca, otherPub, now.Add(-time.Minute), now.Add(time.Hour))
			},
			wantErr: ErrCertificateMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStorage(t, ca)
			c := tt.cert(t, s)

			err := s.SaveCertificate(c)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SaveCertificate() error = %v, want %v", err, tt.wantErr)
			}

			stored, getErr := keyring.Get(storeCertService, s.user)
			if tt.wantErr != nil {
				if !errors.Is(getErr, keyring.ErrNotFound) {
					t.Errorf("certificate stored in keyring despite error, err = %v", getErr)
				}
				return
			}

			if getErr != nil {
				t.Fatalf("certificate not stored in keyring: %v", getErr)
			}
			if stored != string(ssh.MarshalAuthorizedKey(c)) {
				t.Errorf("stored certificate = %q, want %q", stored, ssh.MarshalAuthorizedKey(c))
			}
		})
	}
}

func TestStorage_Certificate(t *testing.T) {
	ca := newCA(t)

	t.Run("no certificate", func(t *testing.T) {
		s := newStorage(t, ca)

		if _, err := s.Certificate(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("Certificate() error = %v, want %v", err, ErrCertificateNotFound)
		}
		if _, err := s.CertificateBytes(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("CertificateBytes() error = %v, want %v", err, ErrCertificateNotFound)
		}
	})

	t.Run("invalid certificate in keyring", func(t *testing.T) {
		s := newStorage(t, ca)

		if err := keyring.Set(storeCertService, s.user, "not a certificate"); err != nil {
			t.Fatalf("keyring.Set() error = %v", err)
		}

		if _, err := s.Certificate(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("Certificate() error = %v, want %v", err, ErrCertificateNotFound)
		}
	})

	t.Run("public key rather than certificate in keyring", func(t *testing.T) {
		s := newStorage(t, ca)

		if err := keyring.Set(storeCertService, s.user, string(ssh.MarshalAuthorizedKey(ca.PublicKey()))); err != nil {
			t.Fatalf("keyring.Set() error = %v", err)
		}

		if _, err := s.Certificate(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("Certificate() error = %v, want %v", err, ErrCertificateNotFound)
		}
	})

	t.Run("valid certificate", func(t *testing.T) {
		s := newStorage(t, ca)
		want := validCert(t, s, ca)

		if err := s.SaveCertificate(want); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		got, err := s.Certificate()
		if err != nil {
			t.Fatalf("Certificate() error = %v", err)
		}
		if !bytes.Equal(got.Marshal(), want.Marshal()) {
			t.Errorf("Certificate() does not match saved certificate")
		}

		gotBytes, err := s.CertificateBytes()
		if err != nil {
			t.Fatalf("CertificateBytes() error = %v", err)
		}
		if !bytes.Equal(gotBytes, ssh.MarshalAuthorizedKey(want)) {
			t.Errorf("CertificateBytes() = %q, want %q", gotBytes, ssh.MarshalAuthorizedKey(want))
		}
	})
}

func TestStorage_AddToAgent(t *testing.T) {
	ca := newCA(t)

	t.Run("no key", func(t *testing.T) {
		s := newStorage(t, ca)

		if err := s.AddToAgent(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("AddToAgent() error = %v, want %v", err, ErrKeyNotFound)
		}
	})

	t.Run("no certificate", func(t *testing.T) {
		s := newStorage(t, ca)
		generatePrivateKey(t, s)

		if err := s.AddToAgent(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("AddToAgent() error = %v, want %v", err, ErrCertificateNotFound)
		}
	})

	t.Run("adds certificate to agent", func(t *testing.T) {
		a := newAgent()
		s := newStorage(t, ca, WithAgent(a))

		c := validCert(t, s, ca)
		if err := s.SaveCertificate(c); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		if err := s.AddToAgent(); err != nil {
			t.Fatalf("AddToAgent() error = %v", err)
		}

		assertCertInAgent(t, a, c)
	})

	t.Run("agent error", func(t *testing.T) {
		a := newAgent()
		if err := a.Lock([]byte("passphrase")); err != nil {
			t.Fatalf("agent Lock() error = %v", err)
		}
		s := newStorage(t, ca, WithAgent(a))

		c := validCert(t, s, ca)
		if err := s.SaveCertificate(c); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		if err := s.AddToAgent(); !errors.Is(err, ErrAddingToAgent) {
			t.Errorf("AddToAgent() error = %v, want %v from locked agent", err, ErrAddingToAgent)
		}
	})
}

// assertCertInAgent checks the agent holds the provided certificate and
// that it can be used to sign
func assertCertInAgent(t *testing.T, a agent.Agent, c *ssh.Certificate) {
	t.Helper()

	keys, err := a.List()
	if err != nil {
		t.Fatalf("agent List() error = %v", err)
	}

	for _, k := range keys {
		if bytes.Equal(k.Marshal(), c.Marshal()) {
			if k.Comment != c.KeyId {
				t.Errorf("agent key comment = %q, want %q", k.Comment, c.KeyId)
			}

			data := []byte("some data to sign")
			sig, err := a.Sign(c, data)
			if err != nil {
				t.Fatalf("agent Sign() error = %v", err)
			}
			if err := c.Key.Verify(data, sig); err != nil {
				t.Errorf("agent signature did not verify: %v", err)
			}

			return
		}
	}

	t.Errorf("certificate not found in agent, got %d keys", len(keys))
}

// keyEqualer is implemented by all supported private key types
type keyEqualer interface {
	Equal(crypto.PrivateKey) bool
}

// typedKeyPEM returns key PEM encoded in OpenSSH format
func typedKeyPEM(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(key, "test@example.com")
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	return pemEncode(t, block)
}

// newTypedKey generates a private key of the given type
func newTypedKey(t *testing.T, keyType sshkey.KeyType, curve elliptic.Curve) crypto.Signer {
	t.Helper()

	key, err := sshkey.GeneratePrivateKey(keyType, curve)
	if err != nil {
		t.Fatalf("could not generate %s key: %v", keyType, err)
	}

	return key
}

func TestStorage_KeyTypes(t *testing.T) {
	ca := newCA(t)

	p256 := newTypedKey(t, sshkey.KeyTypeECDSA, elliptic.P256())
	p384 := newTypedKey(t, sshkey.KeyTypeECDSA, elliptic.P384())
	p521 := newTypedKey(t, sshkey.KeyTypeECDSA, elliptic.P521())
	ed := newTypedKey(t, sshkey.KeyTypeEd25519, nil)
	rsa3072 := newTypedKey(t, sshkey.KeyTypeRSA, nil)
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	sec1, err := x509.MarshalECPrivateKey(p256.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	tests := []struct {
		name string
		key  crypto.Signer
		pem  []byte
	}{
		{"ecdsa p256", p256, typedKeyPEM(t, p256)},
		{"ecdsa p384", p384, typedKeyPEM(t, p384)},
		{"ecdsa p521", p521, typedKeyPEM(t, p521)},
		{"ed25519", ed, typedKeyPEM(t, ed)},
		{"rsa 2048", rsa2048, typedKeyPEM(t, rsa2048)},
		{"rsa 3072", rsa3072, typedKeyPEM(t, rsa3072)},
		{"sec1 ecdsa", p256, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})},
		{"pkcs1 rsa", rsa2048, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsa2048)})},
		{"pkcs8 ed25519", ed, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAgent()
			s := newStorage(t, ca, WithAgent(a))
			storeKey(t, s, tt.pem)

			want, err := ssh.NewPublicKey(tt.key.Public())
			if err != nil {
				t.Fatalf("NewPublicKey() error = %v", err)
			}

			if !s.HasPrivateKey() {
				t.Fatalf("HasPrivateKey() = false, want true")
			}

			key, err := s.PrivateKey()
			if err != nil {
				t.Fatalf("PrivateKey() error = %v", err)
			}
			if !tt.key.(keyEqualer).Equal(key) {
				t.Errorf("PrivateKey() does not match stored key")
			}

			keyBytes, err := s.PrivateKeyBytes()
			if err != nil {
				t.Fatalf("PrivateKeyBytes() error = %v", err)
			}
			if !bytes.Equal(keyBytes, tt.pem) {
				t.Errorf("PrivateKeyBytes() did not return the stored bytes")
			}

			pub, err := s.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey() error = %v", err)
			}
			if !bytes.Equal(pub.Marshal(), want.Marshal()) {
				t.Errorf("PublicKey() does not match stored key")
			}

			signer, err := s.Signer()
			if err != nil {
				t.Fatalf("Signer() error = %v", err)
			}
			data := []byte("some data to sign")
			sig, err := signer.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			if err := want.Verify(data, sig); err != nil {
				t.Errorf("signature did not verify: %v", err)
			}

			now := time.Now()
			c := signCert(t, ca, pub, now.Add(-time.Minute), now.Add(time.Hour))
			if err := s.SaveCertificate(c); err != nil {
				t.Fatalf("SaveCertificate() error = %v", err)
			}
			if !s.HasCertificate() {
				t.Errorf("HasCertificate() = false, want true")
			}

			if err := s.AddToAgent(); err != nil {
				t.Fatalf("AddToAgent() error = %v", err)
			}
			assertCertInAgent(t, a, c)
		})
	}

	t.Run("certificate for a different key type", func(t *testing.T) {
		s := newStorage(t, ca)
		storeKey(t, s, typedKeyPEM(t, p256))

		pub, err := ssh.NewPublicKey(ed.Public())
		if err != nil {
			t.Fatalf("NewPublicKey() error = %v", err)
		}
		now := time.Now()
		c := signCert(t, ca, pub, now.Add(-time.Minute), now.Add(time.Hour))

		if err := s.SaveCertificate(c); !errors.Is(err, ErrCertificateMismatch) {
			t.Errorf("SaveCertificate() error = %v, want %v", err, ErrCertificateMismatch)
		}
	})

	t.Run("passphrase protected key", func(t *testing.T) {
		s := newStorage(t, ca)

		block, err := ssh.MarshalPrivateKeyWithPassphrase(ed, "", []byte("passphrase"))
		if err != nil {
			t.Fatalf("could not marshal key: %v", err)
		}
		storeKey(t, s, pemEncode(t, block))

		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true, want false")
		}
		_, err = s.PrivateKey()
		if !errors.Is(err, ErrKeyNotFound) || !errors.Is(err, sshkey.ErrEncryptedKey) {
			t.Errorf("PrivateKey() error = %v, want %v and %v", err, ErrKeyNotFound, sshkey.ErrEncryptedKey)
		}
	})
}

func TestStorage_GeneratePrivateKey_KeyType(t *testing.T) {
	ca := newCA(t)

	tests := []struct {
		name    string
		opts    []Option
		checkFn func(t *testing.T, key crypto.PrivateKey)
	}{
		{
			name: "default is ecdsa p256",
			checkFn: func(t *testing.T, key crypto.PrivateKey) {
				if k, ok := key.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
					t.Errorf("PrivateKey() = %T, want P-256 *ecdsa.PrivateKey", key)
				}
			},
		},
		{
			name: "ecdsa with curve",
			opts: []Option{WithKeyType(sshkey.KeyTypeECDSA), WithCurve(elliptic.P384())},
			checkFn: func(t *testing.T, key crypto.PrivateKey) {
				if k, ok := key.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P384() {
					t.Errorf("PrivateKey() = %T, want P-384 *ecdsa.PrivateKey", key)
				}
			},
		},
		{
			name: "ed25519",
			opts: []Option{WithKeyType(sshkey.KeyTypeEd25519)},
			checkFn: func(t *testing.T, key crypto.PrivateKey) {
				if _, ok := key.(ed25519.PrivateKey); !ok {
					t.Errorf("PrivateKey() = %T, want ed25519.PrivateKey", key)
				}
			},
		},
		{
			name: "rsa",
			opts: []Option{WithKeyType(sshkey.KeyTypeRSA)},
			checkFn: func(t *testing.T, key crypto.PrivateKey) {
				k, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("PrivateKey() = %T, want *rsa.PrivateKey", key)
				}
				if k.N.BitLen() < 2048 {
					t.Errorf("generated RSA key is %d bits, want at least 2048", k.N.BitLen())
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newStorage(t, ca, tt.opts...)
			generatePrivateKey(t, s)

			key, err := s.PrivateKey()
			if err != nil {
				t.Fatalf("PrivateKey() error = %v", err)
			}
			tt.checkFn(t, key)
		})
	}

	t.Run("unsupported key type", func(t *testing.T) {
		s := newStorage(t, ca, WithKeyType("dsa"))

		if err := s.GeneratePrivateKey(); !errors.Is(err, sshkey.ErrUnsupportedKeyType) {
			t.Errorf("GeneratePrivateKey() error = %v, want %v", err, sshkey.ErrUnsupportedKeyType)
		}
		if s.HasPrivateKey() {
			t.Errorf("HasPrivateKey() = true after failed generation")
		}
	})
}

// parseECDSAKey parses an ECDSA private key, the type GeneratePrivateKey
// creates by default
func parseECDSAKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	key, err := sshkey.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	k, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want *ecdsa.PrivateKey", key)
	}

	return k, nil
}

func TestStorage_LargeKey(t *testing.T) {
	// a RSA-3072 key is larger than a single Windows Credential Manager entry
	// so is stored in parts
	ca := newCA(t)
	s := newStorage(t, ca, WithKeyType(sshkey.KeyTypeRSA))
	generatePrivateKey(t, s)

	if _, err := keyring.Get(storeKeyService+" #1", s.user); err != nil {
		t.Fatalf("key was not stored in parts: %v", err)
	}

	keyBytes, err := s.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes() error = %v", err)
	}
	if len(keyBytes) <= keyringutil.ChunkSize {
		t.Fatalf("key is %d bytes, want more than %d", len(keyBytes), keyringutil.ChunkSize)
	}

	if !s.HasPrivateKey() {
		t.Errorf("HasPrivateKey() = false, want true")
	}

	// a certificate for a new (also RSA) key is stored alongside it
	if err := s.SaveCertificate(validCert(t, s, ca)); err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}
	if !s.HasCertificate() {
		t.Errorf("HasCertificate() = false, want true")
	}
}
