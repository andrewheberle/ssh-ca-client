//go:build e2e

package e2e

import (
	"context"
	"crypto/elliptic"
	"net/http"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

func TestCA_PublicKey(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	res, err := ca.client(t).GetCaWithResponse(context.Background())
	if err != nil {
		t.Fatalf("getting CA public key: %v", err)
	}

	if res.StatusCode() != http.StatusOK {
		t.Fatalf("status code = %d, want %d", res.StatusCode(), http.StatusOK)
	}

	pub, comment, _, _, err := ssh.ParseAuthorizedKey(res.Body)
	if err != nil {
		t.Fatalf("parsing CA public key: %v", err)
	}

	if !keysEqual(pub, ca.PublicKey) {
		t.Errorf("CA public key = %s, want %s", ssh.MarshalAuthorizedKey(pub), ssh.MarshalAuthorizedKey(ca.PublicKey))
	}

	if want := "CN=SSH CA,O=ssh-ca-client e2e,C=AU"; comment != want {
		t.Errorf("CA public key comment = %q, want %q", comment, want)
	}
}

// TestCA_KeyTypes checks certificates and KRLs signed with each type of CA
// key are accepted by the client
func TestCA_KeyTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		keyType     sshkey.KeyType
		curve       elliptic.Curve
		unsupported bool
	}{
		{"ed25519", sshkey.KeyTypeEd25519, nil, false},
		{"ecdsa p256", sshkey.KeyTypeECDSA, elliptic.P256(), false},
		{"ecdsa p384", sshkey.KeyTypeECDSA, elliptic.P384(), false},
		{"ecdsa p521", sshkey.KeyTypeECDSA, elliptic.P521(), false},
		// RSA CA keys cannot be used on the Workers runtime
		{"rsa", sshkey.KeyTypeRSA, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := newCA(t, withCAKeyType(tt.keyType, tt.curve))

			store := ca.newStore(t)
			u := ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com"))
			if tt.unsupported {
				assertStatus(t, u.Request(), http.StatusInternalServerError)
				if store.HasCertificate() {
					t.Error("a certificate was saved after the request failed")
				}
				return
			}

			if err := u.Request(); err != nil {
				t.Fatalf("requesting user certificate: %v", err)
			}

			c := certificate(t, store)
			pub, err := store.PublicKey()
			if err != nil {
				t.Fatalf("getting public key: %v", err)
			}
			if err := cert.CertificateValid(ca.PublicKey, pub, c); err != nil {
				t.Errorf("certificate not valid: %v", err)
			}

			ca.krl(t, api.GetCertificateTypeKrlParamsCertificateTypeUser)
			ca.krl(t, api.GetCertificateTypeKrlParamsCertificateTypeHost)
		})
	}
}
