//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
)

// certificateType is a type of certificate as used by the KRL and revocation
// endpoints
type certificateType struct {
	name   string
	krl    api.GetCertificateTypeKrlParamsCertificateType
	revoke api.PostCertificateTypeRevokeParamsCertificateType
}

var (
	userType = certificateType{"user", api.GetCertificateTypeKrlParamsCertificateTypeUser, api.PostCertificateTypeRevokeParamsCertificateTypeUser}
	hostType = certificateType{"host", api.GetCertificateTypeKrlParamsCertificateTypeHost, api.PostCertificateTypeRevokeParamsCertificateTypeHost}
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

			if ca.krl(t, ct.krl).IsRevoked(c) {
				t.Error("certificate is revoked by the KRL but was never revoked")
			}
		})
	}
}

// TestKRL_NotOlder checks the CA generates KRLs that CheckNotOlder orders
// correctly, as the CA does not increase the KRL version
func TestKRL_NotOlder(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	for _, ct := range []certificateType{userType, hostType} {
		t.Run(ct.name, func(t *testing.T) {
			t.Parallel()

			first := ca.krlResponse(t, ct.krl)

			// the generated date has a resolution of one second
			time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + time.Millisecond*50)))

			second := ca.krlResponse(t, ct.krl)

			if err := second.CheckNotOlder(first.Krl); err != nil {
				t.Errorf("CheckNotOlder() of later KRL error = %v, want nil", err)
			}

			if err := first.CheckNotOlder(second.Krl); !errors.Is(err, krl.ErrOlderKRL) {
				t.Errorf("CheckNotOlder() of earlier KRL error = %v, want %v", err, krl.ErrOlderKRL)
			}
		})
	}
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

			if code := ca.revoke(t, tt.ct.revoke, c.Serial, store); code != http.StatusOK {
				t.Fatalf("revocation status code = %d, want %d", code, http.StatusOK)
			}

			if !ca.krl(t, tt.ct.krl).IsRevoked(c) {
				t.Errorf("certificate is not revoked by the %s KRL", tt.ct.name)
			}

			if ca.krl(t, tt.other.krl).IsRevoked(c) {
				t.Errorf("certificate is revoked by the %s KRL", tt.other.name)
			}

			if code := ca.revoke(t, tt.ct.revoke, c.Serial, store); code != http.StatusConflict {
				t.Errorf("repeated revocation status code = %d, want %d", code, http.StatusConflict)
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
		revoke   func(t *testing.T) (certificateType, uint64, cert.Storage)
		wantCode int
	}{
		{
			name: "wrong certificate type",
			revoke: func(t *testing.T) (certificateType, uint64, cert.Storage) {
				store := ca.request(t, userType)
				return hostType, certificate(t, store).Serial, store
			},
			wantCode: http.StatusNotFound,
		},
		{
			name: "certificate for another key",
			revoke: func(t *testing.T) (certificateType, uint64, cert.Storage) {
				store := ca.request(t, userType)
				return userType, certificate(t, store).Serial, ca.newStore(t)
			},
			wantCode: http.StatusNotFound,
		},
		{
			name: "unknown serial",
			revoke: func(t *testing.T) (certificateType, uint64, cert.Storage) {
				store := ca.request(t, userType)
				return userType, certificate(t, store).Serial + 1, store
			},
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ct, serial, store := tt.revoke(t)

			if code := ca.revoke(t, ct.revoke, serial, store); code != tt.wantCode {
				t.Errorf("revocation status code = %d, want %d", code, tt.wantCode)
			}
		})
	}
}
