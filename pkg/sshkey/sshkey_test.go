package sshkey

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // DSA keys are generated to test they are rejected
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"golang.org/x/crypto/ssh"
)

// equaler is implemented by all supported private key types
type equaler interface {
	Equal(crypto.PrivateKey) bool
}

func newECDSAKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("could not generate ECDSA key: %v", err)
	}

	return key
}

func newEd25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate Ed25519 key: %v", err)
	}

	return key
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("could not generate RSA key: %v", err)
	}

	return key
}

// openSSHPEM returns key PEM encoded in OpenSSH format
func openSSHPEM(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(key, "test@example.com")
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	return pem.EncodeToMemory(block)
}

// pkcs8PEM returns key PEM encoded in PKCS#8 format
func pkcs8PEM(t *testing.T, key crypto.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// sec1PEM returns key PEM encoded in SEC1 format
func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// pkcs1PEM returns key PEM encoded in PKCS#1 format
func pkcs1PEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// dsaPEM returns a new DSA key PEM encoded in the legacy OpenSSL format
func dsaPEM(t *testing.T) []byte {
	t.Helper()

	var key dsa.PrivateKey
	if err := dsa.GenerateParameters(&key.Parameters, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatalf("could not generate DSA parameters: %v", err)
	}
	if err := dsa.GenerateKey(&key, rand.Reader); err != nil {
		t.Fatalf("could not generate DSA key: %v", err)
	}

	der, err := asn1.Marshal(struct {
		Version       int
		P, Q, G, Y, X *big.Int
	}{0, key.P, key.Q, key.G, key.Y, key.X})
	if err != nil {
		t.Fatalf("could not marshal DSA key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: der})
}

func TestParsePrivateKey(t *testing.T) {
	p256 := newECDSAKey(t, elliptic.P256())
	p384 := newECDSAKey(t, elliptic.P384())
	p521 := newECDSAKey(t, elliptic.P521())
	ed := newEd25519Key(t)
	rsa2048 := newRSAKey(t, 2048)
	rsa3072 := newRSAKey(t, 3072)

	tests := []struct {
		name string
		pem  []byte
		want crypto.Signer
	}{
		{"openssh ecdsa p256", openSSHPEM(t, p256), p256},
		{"openssh ecdsa p384", openSSHPEM(t, p384), p384},
		{"openssh ecdsa p521", openSSHPEM(t, p521), p521},
		{"openssh ed25519", openSSHPEM(t, ed), ed},
		{"openssh rsa 2048", openSSHPEM(t, rsa2048), rsa2048},
		{"openssh rsa 3072", openSSHPEM(t, rsa3072), rsa3072},
		{"sec1 ecdsa", sec1PEM(t, p256), p256},
		{"pkcs1 rsa", pkcs1PEM(rsa2048), rsa2048},
		{"pkcs8 ecdsa", pkcs8PEM(t, p384), p384},
		{"pkcs8 ed25519", pkcs8PEM(t, ed), ed},
		{"pkcs8 rsa", pkcs8PEM(t, rsa3072), rsa3072},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrivateKey(tt.pem)
			if err != nil {
				t.Fatalf("ParsePrivateKey() error = %v", err)
			}

			if !tt.want.(equaler).Equal(got) {
				t.Errorf("ParsePrivateKey() did not return the encoded key")
			}

			// ed25519 keys are always returned by value
			if _, ok := got.(*ed25519.PrivateKey); ok {
				t.Errorf("ParsePrivateKey() returned *ed25519.PrivateKey, want ed25519.PrivateKey")
			}

			// the key can be used for SSH
			if _, err := ssh.NewSignerFromSigner(got); err != nil {
				t.Errorf("NewSignerFromSigner() error = %v", err)
			}
		})
	}
}

func TestParsePrivateKey_Errors(t *testing.T) {
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(newEd25519Key(t), "", []byte("passphrase"))
	if err != nil {
		t.Fatalf("could not marshal encrypted key: %v", err)
	}

	tests := []struct {
		name    string
		pem     []byte
		wantErr error // checked with errors.Is when set
	}{
		{"rsa below minimum size", openSSHPEM(t, newRSAKey(t, 1024)), ErrRSAKeyTooSmall},
		{"pkcs1 rsa below minimum size", pkcs1PEM(newRSAKey(t, 1024)), ErrRSAKeyTooSmall},
		{"dsa", dsaPEM(t), ErrUnsupportedKeyType},
		{"passphrase protected", pem.EncodeToMemory(encrypted), ErrEncryptedKey},
		{"not a key", []byte("not a key"), nil},
		{"empty", nil, nil},
		{"public key", ssh.MarshalAuthorizedKey(mustPublicKey(t, newEd25519Key(t))), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrivateKey(tt.pem)
			if err == nil {
				t.Fatalf("ParsePrivateKey() = %T, want error", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePrivateKey() error = %v, want %v", err, tt.wantErr)
			}
			if got != nil {
				t.Errorf("ParsePrivateKey() = %T, want nil on error", got)
			}
		})
	}
}

func mustPublicKey(t *testing.T, key crypto.Signer) ssh.PublicKey {
	t.Helper()

	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}

	return pub
}

func TestGeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		curve   elliptic.Curve
		check   func(t *testing.T, key crypto.Signer)
	}{
		{
			name:    "ecdsa p256",
			keyType: KeyTypeECDSA,
			curve:   elliptic.P256(),
			check: func(t *testing.T, key crypto.Signer) {
				if k, ok := key.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P256() {
					t.Errorf("key = %T, want P-256 *ecdsa.PrivateKey", key)
				}
			},
		},
		{
			name:    "ecdsa p384",
			keyType: KeyTypeECDSA,
			curve:   elliptic.P384(),
			check: func(t *testing.T, key crypto.Signer) {
				if k, ok := key.(*ecdsa.PrivateKey); !ok || k.Curve != elliptic.P384() {
					t.Errorf("key = %T, want P-384 *ecdsa.PrivateKey", key)
				}
			},
		},
		{
			name:    "ed25519 ignores curve",
			keyType: KeyTypeEd25519,
			curve:   elliptic.P256(),
			check: func(t *testing.T, key crypto.Signer) {
				if _, ok := key.(ed25519.PrivateKey); !ok {
					t.Errorf("key = %T, want ed25519.PrivateKey", key)
				}
			},
		},
		{
			name:    "rsa",
			keyType: KeyTypeRSA,
			check: func(t *testing.T, key crypto.Signer) {
				k, ok := key.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("key = %T, want *rsa.PrivateKey", key)
				}
				if k.N.BitLen() != defaultRSAKeyBits {
					t.Errorf("key size = %d bits, want %d", k.N.BitLen(), defaultRSAKeyBits)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GeneratePrivateKey(tt.keyType, tt.curve)
			if err != nil {
				t.Fatalf("GeneratePrivateKey() error = %v", err)
			}
			tt.check(t, key)

			// generated keys can be stored and parsed again
			parsed, err := ParsePrivateKey(openSSHPEM(t, key))
			if err != nil {
				t.Fatalf("ParsePrivateKey() error = %v", err)
			}
			if !key.(equaler).Equal(parsed) {
				t.Errorf("parsed key does not match generated key")
			}
		})
	}

	t.Run("unsupported type", func(t *testing.T) {
		if _, err := GeneratePrivateKey("dsa", nil); !errors.Is(err, ErrUnsupportedKeyType) {
			t.Errorf("GeneratePrivateKey() error = %v, want %v", err, ErrUnsupportedKeyType)
		}
	})
}

func TestMinRSAKeyBits(t *testing.T) {
	// the generated RSA key size must be accepted when parsed
	if defaultRSAKeyBits < minRSAKeyBits {
		t.Errorf("defaultRSAKeyBits (%d) is below minRSAKeyBits (%d)", defaultRSAKeyBits, minRSAKeyBits)
	}
}
