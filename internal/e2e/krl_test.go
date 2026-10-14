//go:build e2e

package e2e

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
)

// certificateType is a type of certificate as used by the KRL and revocation
// endpoints
type certificateType struct {
	name string
	kind krl.CertificateType
}

var (
	userType = certificateType{"user", krl.User}
	hostType = certificateType{"host", krl.Host}
)

// request returns a store with a certificate of type ct issued by ca
func (ca *testCA) request(t *testing.T, ct certificateType) cert.Storage {
	t.Helper()

	store := ca.newStore(t)

	var r cert.Requestable
	switch ct {
	case userType:
		r = ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com"))
	case hostType:
		r = ca.hostCertificate(t, store, ca.IDP.tokens(t, "host-admin@example.com"), "host1.example.com")
	}

	if err := r.Request(); err != nil {
		t.Fatalf("requesting %s certificate: %v", ct.name, err)
	}

	return store
}

func TestKRL(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	for _, ct := range []certificateType{userType, hostType} {
		t.Run(ct.name, func(t *testing.T) {
			t.Parallel()

			c := certificate(t, ca.request(t, ct))

			if ca.krl(t, ct.kind).IsRevoked(c) {
				t.Error("certificate is revoked by the KRL but was never revoked")
			}
		})
	}
}

// TestKRL_NotOlder checks the CA generates KRLs that CheckNotOlder orders
// correctly: a KRL fetched again is not older than the KRL fetched before it,
// and a KRL from before a revocation is older than one from after it
func TestKRL_NotOlder(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	for _, ct := range []certificateType{userType, hostType} {
		t.Run(ct.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "revocation_list")

			first := ca.fetchKRL(t, ct.kind)
			install(t, first, path)

			store := ca.request(t, ct)
			if err := ca.revoke(t, ct.kind, certificate(t, store).Serial, store); err != nil {
				t.Fatalf("revoking certificate: %v", err)
			}

			revoked := ca.fetchKRL(t, ct.kind)
			if got := install(t, revoked, path); got != krl.Written {
				t.Errorf("Install() of later KRL = %v, want %v", got, krl.Written)
			}

			// the KRL fetched again is the same, or regenerated with a later date
			if got := install(t, ca.fetchKRL(t, ct.kind), path); got != krl.Unchanged && got != krl.Written {
				t.Errorf("Install() of KRL fetched again = %v, want %v or %v", got, krl.Unchanged, krl.Written)
			}
			installed, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading installed KRL: %v", err)
			}

			if _, err := first.Install(path); !errors.Is(err, krl.ErrOlderKRL) {
				t.Errorf("Install() of earlier KRL error = %v, want %v", err, krl.ErrOlderKRL)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading installed KRL: %v", err)
			}
			if !bytes.Equal(after, installed) {
				t.Error("installed KRL was changed by an earlier KRL")
			}
		})
	}
}

// install installs verified at path and returns the outcome
func install(t *testing.T, verified *krl.Verified, path string) krl.Outcome {
	t.Helper()

	outcome, err := verified.Install(path)
	if err != nil {
		t.Fatalf("installing KRL: %v", err)
	}

	return outcome
}

func TestRevocation(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	tests := []struct {
		ct    certificateType
		other certificateType
	}{
		{userType, hostType},
		{hostType, userType},
	}

	for _, tt := range tests {
		t.Run(tt.ct.name, func(t *testing.T) {
			t.Parallel()

			store := ca.request(t, tt.ct)
			c := certificate(t, store)

			if err := ca.revoke(t, tt.ct.kind, c.Serial, store); err != nil {
				t.Fatalf("revoking certificate: %v", err)
			}

			if store.HasCertificate() {
				t.Error("certificate was not deleted after it was revoked")
			}

			if !ca.krl(t, tt.ct.kind).IsRevoked(c) {
				t.Errorf("certificate is not revoked by the %s KRL", tt.ct.name)
			}

			if ca.krl(t, tt.other.kind).IsRevoked(c) {
				t.Errorf("certificate is revoked by the %s KRL", tt.other.name)
			}

			if err := ca.revoke(t, tt.ct.kind, c.Serial, store); !errors.Is(err, cert.ErrAlreadyRevoked) {
				t.Errorf("repeated revocation error = %v, want %v", err, cert.ErrAlreadyRevoked)
			}
		})
	}
}

func TestRevocation_Rejected(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	tests := []struct {
		name string
		// returns the type and serial of the certificate to revoke and the
		// store with the private key to prove possession of
		revoke func(t *testing.T) (certificateType, uint64, cert.Storage)
	}{
		{
			name: "wrong certificate type",
			revoke: func(t *testing.T) (certificateType, uint64, cert.Storage) {
				store := ca.request(t, userType)
				return hostType, certificate(t, store).Serial, store
			},
		},
		{
			name: "certificate for another key",
			revoke: func(t *testing.T) (certificateType, uint64, cert.Storage) {
				store := ca.request(t, userType)
				return userType, certificate(t, store).Serial, ca.newStore(t)
			},
		},
		{
			name: "unknown serial",
			revoke: func(t *testing.T) (certificateType, uint64, cert.Storage) {
				store := ca.request(t, userType)
				return userType, certificate(t, store).Serial + 1, store
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ct, serial, store := tt.revoke(t)

			// the CA does not say which, so all are reported as unknown
			if err := ca.revoke(t, ct.kind, serial, store); !errors.Is(err, cert.ErrUnknownCertificate) {
				t.Errorf("revocation error = %v, want %v", err, cert.ErrUnknownCertificate)
			}
		})
	}
}
