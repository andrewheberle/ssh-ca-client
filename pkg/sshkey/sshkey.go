// The sshkey package provides simple ways to generate and parse SSH private
// keys. ECDSA, Ed25519 and RSA keys are supported.
package sshkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// minRSAKeyBits is the smallest RSA key size accepted by [ParsePrivateKey].
// Update this as the minimum acceptable RSA key size increases.
const minRSAKeyBits = 2048

// defaultRSAKeyBits is the size of RSA keys created by [GeneratePrivateKey],
// matching the ssh-keygen default.
const defaultRSAKeyBits = 3072

var (
	ErrEncryptedKey       = errors.New("private key is passphrase protected")
	ErrRSAKeyTooSmall     = fmt.Errorf("RSA key is smaller than the minimum of %d bits", minRSAKeyBits)
	ErrUnsupportedKeyType = errors.New("unsupported private key type")
)

// KeyType is a supported type of SSH private key
type KeyType string

const (
	KeyTypeECDSA   KeyType = "ecdsa"
	KeyTypeEd25519 KeyType = "ed25519"
	KeyTypeRSA     KeyType = "rsa"
)

// GeneratePrivateKey generates a new private key of the given type. The curve
// is used for ECDSA keys and ignored otherwise. RSA keys are 3072 bits.
func GeneratePrivateKey(keyType KeyType, curve elliptic.Curve) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeECDSA:
		return ecdsa.GenerateKey(curve, rand.Reader)
	case KeyTypeEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		return key, err
	case KeyTypeRSA:
		return rsa.GenerateKey(rand.Reader, defaultRSAKeyBits)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKeyType, keyType)
	}
}

// ParsePrivateKey parses an unencrypted PEM encoded private key in OpenSSH,
// PKCS#1, SEC1 or PKCS#8 format and returns it as a [crypto.Signer].
//
// The returned key is an *[ecdsa.PrivateKey], an [ed25519.PrivateKey] or an
// *[rsa.PrivateKey]. Other key types, passphrase protected keys and RSA keys
// smaller than 2048 bits are rejected.
func ParsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, ErrEncryptedKey
		}

		return nil, fmt.Errorf("could not parse private key: %w", err)
	}

	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	case ed25519.PrivateKey:
		return key, nil
	case *ed25519.PrivateKey:
		// OpenSSH format ed25519 keys are returned as a pointer
		return *key, nil
	case *rsa.PrivateKey:
		if key.N.BitLen() < minRSAKeyBits {
			return nil, fmt.Errorf("%w: key is %d bits", ErrRSAKeyTooSmall, key.N.BitLen())
		}
		return key, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKeyType, privateKey)
	}
}

// GenerateKey will generate an OpenSSH ECDSA private key using
// the P-256 elliptic curve.
//
// The resulting key is returned as a byte slice in OpenSSH PEM
// format.
func GenerateKey(comment string) ([]byte, error) {
	// generate ECDSA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// encode to openssh format
	privKey, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(privKey)
	if pemBytes == nil {
		return nil, fmt.Errorf("could not encode key")
	}

	return pemBytes, nil
}

// ParseKey will parse the provided byte slice (in OpenSSH ECDSA Private Key format)
// and return an *[ecdsa.PrivateKey].
//
// Any parsing errors will result in a nil *[ecdsa.PrivateKey] returned along
// with the error.
//
// Only ECDSA format private keys are supported by this function.
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key file: %w", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key; its type is %T", privateKey)
	}

	return ecdsaKey, nil
}
