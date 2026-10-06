package sshcert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newSigner generates a new ed25519 private key and matching SSH signer
func newSigner(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("could not create signer: %v", err)
	}

	return priv, signer
}

// signCert signs a certificate of certType for key using ca that is valid
// for the provided duration from now
func signCert(t *testing.T, ca, key ssh.Signer, certType uint32, valid time.Duration) *ssh.Certificate {
	t.Helper()

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        certType,
		KeyId:           "test@example.com",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(valid).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("could not sign certificate: %v", err)
	}

	return cert
}

func TestParseCert(t *testing.T) {
	_, ca := newSigner(t)
	_, key := newSigner(t)

	userCert := signCert(t, ca, key, ssh.UserCert, time.Hour)
	hostCert := signCert(t, ca, key, ssh.HostCert, time.Hour)

	tests := []struct {
		name    string
		input   []byte
		want    *ssh.Certificate
		wantErr bool
	}{
		{
			name:  "user certificate",
			input: ssh.MarshalAuthorizedKey(userCert),
			want:  userCert,
		},
		{
			name:  "host certificate",
			input: ssh.MarshalAuthorizedKey(hostCert),
			want:  hostCert,
		},
		{
			name:  "certificate with comment",
			input: append(bytes.TrimSpace(ssh.MarshalAuthorizedKey(userCert)), []byte(" user@host\n")...),
			want:  userCert,
		},
		{
			name:  "certificate without trailing newline",
			input: bytes.TrimSpace(ssh.MarshalAuthorizedKey(userCert)),
			want:  userCert,
		},
		{
			name:    "public key is not a certificate",
			input:   ssh.MarshalAuthorizedKey(key.PublicKey()),
			wantErr: true,
		},
		{
			name:    "invalid data",
			input:   []byte("not a certificate"),
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCert(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCert() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				if got != nil {
					t.Errorf("ParseCert() = %v, want nil on error", got)
				}
				return
			}

			if !bytes.Equal(got.Marshal(), tt.want.Marshal()) {
				t.Errorf("ParseCert() returned certificate does not match original")
			}
			if got.CertType != tt.want.CertType {
				t.Errorf("ParseCert() CertType = %d, want %d", got.CertType, tt.want.CertType)
			}
			if got.KeyId != tt.want.KeyId {
				t.Errorf("ParseCert() KeyId = %q, want %q", got.KeyId, tt.want.KeyId)
			}
		})
	}
}

func TestAddedKey(t *testing.T) {
	_, ca := newSigner(t)
	priv, key := newSigner(t)

	tests := []struct {
		name string
		cert *ssh.Certificate
	}{
		{
			name: "user certificate",
			cert: signCert(t, ca, key, ssh.UserCert, time.Hour),
		},
		{
			name: "host certificate",
			cert: signCert(t, ca, key, ssh.HostCert, 24*time.Hour),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AddedKey(priv, tt.cert)

			if pk, ok := got.PrivateKey.(ed25519.PrivateKey); !ok || !pk.Equal(priv) {
				t.Errorf("AddedKey() PrivateKey = %v, want %v", got.PrivateKey, priv)
			}
			if got.Certificate != tt.cert {
				t.Errorf("AddedKey() Certificate = %p, want %p", got.Certificate, tt.cert)
			}
			if got.Comment != tt.cert.KeyId {
				t.Errorf("AddedKey() Comment = %q, want %q", got.Comment, tt.cert.KeyId)
			}
		})
	}
}
