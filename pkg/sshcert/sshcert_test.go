package sshcert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// failingAgent is an [agent.Agent] whose List or Remove return an error
type failingAgent struct {
	agent.Agent

	listErr   error
	removeErr error
}

func (a *failingAgent) List() ([]*agent.Key, error) {
	if a.listErr != nil {
		return nil, a.listErr
	}

	return a.Agent.List()
}

func (a *failingAgent) Remove(key ssh.PublicKey) error {
	if a.removeErr != nil {
		return a.removeErr
	}

	return a.Agent.Remove(key)
}

func TestRemoveFromAgent(t *testing.T) {
	_, ca := newSigner(t)
	priv, key := newSigner(t)
	cert := signCert(t, ca, key, ssh.UserCert, time.Hour)
	other := signCert(t, ca, key, ssh.UserCert, 2*time.Hour)

	tests := []struct {
		name     string
		add      []*ssh.Certificate
		addPlain bool
		failing  *failingAgent
		want     [][]byte
		wantErr  bool
	}{
		{"removes certificate", []*ssh.Certificate{cert}, false, nil, nil, false},
		{"keeps plain key", []*ssh.Certificate{cert}, true, nil, [][]byte{key.PublicKey().Marshal()}, false},
		{"keeps other certificate", []*ssh.Certificate{cert, other}, false, nil, [][]byte{other.Marshal()}, false},
		{"not in agent", []*ssh.Certificate{other}, false, nil, [][]byte{other.Marshal()}, false},
		{"empty agent", nil, false, nil, nil, false},
		{"list error", []*ssh.Certificate{cert}, false, &failingAgent{listErr: errors.New("list failed")}, nil, true},
		{"remove error", []*ssh.Certificate{cert}, false, &failingAgent{removeErr: errors.New("remove failed")}, nil, true},
		{"remove error not attempted when absent", []*ssh.Certificate{other}, false, &failingAgent{removeErr: errors.New("remove failed")}, [][]byte{other.Marshal()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := agent.NewKeyring()
			for _, c := range tt.add {
				if err := a.Add(agent.AddedKey{PrivateKey: priv, Certificate: c}); err != nil {
					t.Fatalf("agent Add() error = %v", err)
				}
			}
			if tt.addPlain {
				if err := a.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
					t.Fatalf("agent Add() error = %v", err)
				}
			}
			under := a
			if tt.failing != nil {
				tt.failing.Agent = a
				under = tt.failing
			}

			err := RemoveFromAgent(under, cert)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RemoveFromAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			keys, err := a.List()
			if err != nil {
				t.Fatalf("agent List() error = %v", err)
			}
			if len(keys) != len(tt.want) {
				t.Fatalf("agent holds %d keys, want %d", len(keys), len(tt.want))
			}
			for i, k := range keys {
				if !bytes.Equal(k.Marshal(), tt.want[i]) {
					t.Errorf("agent key %d = %s, want %s", i, k.Format, ssh.MarshalAuthorizedKey(k))
				}
			}
		})
	}
}
