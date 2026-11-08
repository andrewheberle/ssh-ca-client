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

// signCertValidity signs a certificate of certType for key using ca that is
// valid between after and before
func signCertValidity(t *testing.T, ca, key ssh.Signer, certType uint32, after, before uint64) *ssh.Certificate {
	t.Helper()

	cert := &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        certType,
		KeyId:           "test@example.com",
		ValidPrincipals: []string{"test"},
		ValidAfter:      after,
		ValidBefore:     before,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("could not sign certificate: %v", err)
	}

	return cert
}

func TestRemoveStale(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	past := uint64(now.Add(-time.Hour).Unix())
	future := uint64(now.Add(time.Hour).Unix())
	longAgo := uint64(now.Add(-48 * time.Hour).Unix())

	_, ca := newSigner(t)
	_, otherCA := newSigner(t)

	// each identity uses its own key, as the Windows agent holds one
	// certificate per key
	type identity struct {
		priv ed25519.PrivateKey
		cert *ssh.Certificate // nil for a plain key
	}
	newIdentity := func(signer ssh.Signer, certType uint32, after, before uint64) identity {
		priv, key := newSigner(t)
		return identity{priv, signCertValidity(t, signer, key, certType, after, before)}
	}
	plainPriv, plainKey := newSigner(t)
	plain := identity{priv: plainPriv}

	expired := newIdentity(ca, ssh.UserCert, longAgo, past)
	expiredAgain := newIdentity(ca, ssh.UserCert, longAgo, past)
	expiresNow := newIdentity(ca, ssh.UserCert, longAgo, uint64(now.Unix()))
	current := newIdentity(ca, ssh.UserCert, past, future)
	notYetValid := newIdentity(ca, ssh.UserCert, future, future+3600)
	neverExpires := newIdentity(ca, ssh.UserCert, past, ssh.CertTimeInfinity)
	otherCAExpired := newIdentity(otherCA, ssh.UserCert, longAgo, past)
	hostExpired := newIdentity(ca, ssh.HostCert, longAgo, past)

	blob := func(id identity) []byte {
		if id.cert == nil {
			return plainKey.PublicKey().Marshal()
		}
		return id.cert.Marshal()
	}

	tests := []struct {
		name        string
		add         []identity
		failing     *failingAgent
		wantRemoved []identity
		wantKept    []identity
		wantErr     bool
	}{
		{name: "empty agent"},
		{name: "removes expired certificate", add: []identity{expired}, wantRemoved: []identity{expired}},
		{name: "removes certificate expiring now", add: []identity{expiresNow}, wantRemoved: []identity{expiresNow}},
		{name: "keeps current certificate", add: []identity{current}, wantKept: []identity{current}},
		{name: "keeps certificate not yet valid", add: []identity{notYetValid}, wantKept: []identity{notYetValid}},
		{name: "keeps certificate that never expires", add: []identity{neverExpires}, wantKept: []identity{neverExpires}},
		{name: "keeps certificate from another CA", add: []identity{otherCAExpired}, wantKept: []identity{otherCAExpired}},
		{name: "keeps host certificate", add: []identity{hostExpired}, wantKept: []identity{hostExpired}},
		{name: "keeps plain key", add: []identity{plain}, wantKept: []identity{plain}},
		{
			name:        "mixed",
			add:         []identity{plain, expired, current, otherCAExpired, expiredAgain, hostExpired, neverExpires},
			wantRemoved: []identity{expired, expiredAgain},
			wantKept:    []identity{plain, current, otherCAExpired, hostExpired, neverExpires},
		},
		{name: "list error", add: []identity{expired}, failing: &failingAgent{listErr: errors.New("list failed")}, wantKept: []identity{expired}, wantErr: true},
		{name: "remove error", add: []identity{expired, expiredAgain}, failing: &failingAgent{removeErr: errors.New("remove failed")}, wantKept: []identity{expired, expiredAgain}, wantErr: true},
		{name: "remove not attempted when nothing is stale", add: []identity{current}, failing: &failingAgent{removeErr: errors.New("remove failed")}, wantKept: []identity{current}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := agent.NewKeyring()
			for _, id := range tt.add {
				if err := a.Add(agent.AddedKey{PrivateKey: id.priv, Certificate: id.cert}); err != nil {
					t.Fatalf("agent Add() error = %v", err)
				}
			}
			under := a
			if tt.failing != nil {
				tt.failing.Agent = a
				under = tt.failing
			}

			removed, err := RemoveStale(under, ca.PublicKey(), now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RemoveStale() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(removed) != len(tt.wantRemoved) {
				t.Fatalf("RemoveStale() removed %d certificates, want %d", len(removed), len(tt.wantRemoved))
			}
			for i, c := range removed {
				if !bytes.Equal(c.Marshal(), tt.wantRemoved[i].cert.Marshal()) {
					t.Errorf("RemoveStale() removed certificate %d is not the expected certificate", i)
				}
			}

			keys, err := a.List()
			if err != nil {
				t.Fatalf("agent List() error = %v", err)
			}
			if len(keys) != len(tt.wantKept) {
				t.Fatalf("agent holds %d keys, want %d", len(keys), len(tt.wantKept))
			}
			for _, want := range tt.wantKept {
				found := false
				for _, k := range keys {
					if bytes.Equal(k.Marshal(), blob(want)) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("agent no longer holds key %x", blob(want))
				}
			}
		})
	}
}
