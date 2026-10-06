//go:build e2e

package e2e

import (
	"crypto/elliptic"
	"maps"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/filestore"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/keyringstore"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

func TestUserCertificate_Request(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		bindings       map[string]string
		groups         []string
		wantPrincipals []string
		wantExtensions []string
	}{
		{
			name:           "default",
			groups:         []string{"ssh-admin"},
			wantPrincipals: []string{"alice", "ssh-admin"},
			wantExtensions: []string{"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"},
		},
		{
			name:           "no groups claim",
			wantPrincipals: []string{"alice"},
			wantExtensions: []string{"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"},
		},
		{
			name:           "groups with spaces",
			groups:         []string{"ssh admins"},
			wantPrincipals: []string{"alice", "ssh_admins"},
			wantExtensions: []string{"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"},
		},
		{
			name: "include email",
			bindings: map[string]string{
				"SSH_CERTIFICATE_INCLUDE_SELF_EMAIL": "true",
			},
			groups:         []string{"ssh-admin"},
			wantPrincipals: []string{"alice", "alice@example.com", "ssh-admin"},
			wantExtensions: []string{"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"},
		},
		{
			name: "static principals only",
			bindings: map[string]string{
				"SSH_CERTIFICATE_INCLUDE_SELF": "false",
				"SSH_CERTIFICATE_PRINCIPALS":   "everyone,staff",
			},
			groups:         []string{"ssh-admin"},
			wantPrincipals: []string{"ssh-admin", "everyone", "staff"},
			wantExtensions: []string{"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"},
		},
		{
			name: "other principals claim",
			bindings: map[string]string{
				"JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM": "roles",
			},
			groups:         []string{"ssh-admin"},
			wantPrincipals: []string{"alice"},
			wantExtensions: []string{"permit-agent-forwarding", "permit-port-forwarding", "permit-pty"},
		},
		{
			name: "extensions",
			bindings: map[string]string{
				"SSH_CERTIFICATE_EXTENSIONS": "permit-pty",
			},
			wantPrincipals: []string{"alice"},
			wantExtensions: []string{"permit-pty"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ca := newCA(t, withBindings(tt.bindings))

			store := ca.newStore(t)
			u := ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com", tt.groups...))
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

			if c.CertType != ssh.UserCert {
				t.Errorf("certificate type = %d, want %d", c.CertType, ssh.UserCert)
			}

			if want := "alice@example.com"; c.KeyId != want {
				t.Errorf("key id = %q, want %q", c.KeyId, want)
			}

			if !slices.Equal(c.ValidPrincipals, tt.wantPrincipals) {
				t.Errorf("principals = %v, want %v", c.ValidPrincipals, tt.wantPrincipals)
			}

			if got := slices.Sorted(maps.Keys(c.Extensions)); !slices.Equal(got, tt.wantExtensions) {
				t.Errorf("extensions = %v, want %v", got, tt.wantExtensions)
			}

			if len(c.CriticalOptions) != 0 {
				t.Errorf("critical options = %v, want none", c.CriticalOptions)
			}

			assertLifetime(t, c, cert.DefaultUserCertificateLifetime)
		})
	}
}

func TestUserCertificate_Lifetime(t *testing.T) {
	t.Parallel()

	ca := newCA(t, withBinding("SSH_CERTIFICATE_LIFETIME", "12 hours"))

	tests := []struct {
		name     string
		lifetime time.Duration
		want     time.Duration
		wantCode int
	}{
		{"shorter than maximum", time.Hour, time.Hour, 0},
		{"maximum", time.Hour * 12, time.Hour * 12, 0},
		{"minimum", time.Minute * 5, time.Minute * 5, 0},
		// the CA rejects rather than limits lifetimes outside its range
		{"longer than maximum", cert.DefaultUserCertificateLifetime, 0, http.StatusBadRequest},
		{"shorter than minimum", time.Minute, 0, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := ca.newStore(t)
			u := ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com"))
			u.Lifetime = tt.lifetime

			err := u.Request()
			if tt.wantCode != 0 {
				assertStatus(t, err, tt.wantCode)
				if store.HasCertificate() {
					t.Error("a certificate was saved after the request failed")
				}
				return
			}

			if err != nil {
				t.Fatalf("requesting user certificate: %v", err)
			}

			assertLifetime(t, certificate(t, store), tt.want)
		})
	}
}

func TestUserCertificate_KeyTypes(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	tests := []struct {
		name    string
		keyType sshkey.KeyType
		curve   elliptic.Curve
	}{
		{"ecdsa p256", sshkey.KeyTypeECDSA, elliptic.P256()},
		{"ecdsa p384", sshkey.KeyTypeECDSA, elliptic.P384()},
		{"ecdsa p521", sshkey.KeyTypeECDSA, elliptic.P521()},
		{"ed25519", sshkey.KeyTypeEd25519, nil},
		{"rsa", sshkey.KeyTypeRSA, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := ca.newStore(t, filestore.WithKeyType(tt.keyType), filestore.WithCurve(tt.curve))
			u := ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com"))
			if err := u.Request(); err != nil {
				t.Fatalf("requesting user certificate: %v", err)
			}

			pub, err := store.PublicKey()
			if err != nil {
				t.Fatalf("getting public key: %v", err)
			}
			if err := cert.CertificateValid(ca.PublicKey, pub, certificate(t, store)); err != nil {
				t.Errorf("certificate not valid: %v", err)
			}
		})
	}
}

// TestUserCertificate_KeyringStore checks certificates can be requested when
// using the keyring for storage. This is not run in parallel as the mock
// keyring is shared.
func TestUserCertificate_KeyringStore(t *testing.T) {
	keyring.MockInit()

	ca := newCA(t)

	store, err := keyringstore.New(ca.PublicKey, keyringstore.WithKeyType(sshkey.KeyTypeEd25519))
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	if err := store.GeneratePrivateKey(); err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	u := ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com"))
	if err := u.Request(); err != nil {
		t.Fatalf("requesting user certificate: %v", err)
	}

	pub, err := store.PublicKey()
	if err != nil {
		t.Fatalf("getting public key: %v", err)
	}
	if err := cert.CertificateValid(ca.PublicKey, pub, certificate(t, store)); err != nil {
		t.Errorf("certificate not valid: %v", err)
	}
}

// TestUserCertificate_Renewal checks requesting a certificate again replaces
// the existing certificate, as user certificates are renewed by requesting a
// new certificate
func TestUserCertificate_Renewal(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	store := ca.newStore(t)
	u := ca.userCertificate(t, store, ca.IDP.tokens(t, "alice@example.com"))

	if err := u.Request(); err != nil {
		t.Fatalf("requesting user certificate: %v", err)
	}
	first := certificate(t, store)

	if err := u.Request(); err != nil {
		t.Fatalf("requesting user certificate again: %v", err)
	}
	second := certificate(t, store)

	if first.Serial == second.Serial {
		t.Errorf("serial was not changed: %d", second.Serial)
	}

	if !keysEqual(first.Key, second.Key) {
		t.Error("certificate is for a different key")
	}
}

func TestUserCertificate_Rejected(t *testing.T) {
	t.Parallel()

	// signs tokens with a key the CA does not trust
	other := newIDP(t)

	tests := []struct {
		name       string
		tokens     func(t *testing.T, idp *testIDP) *auth.Tokens
		wantCode   int
		wantReason string
	}{
		{
			name: "token substitution",
			tokens: func(t *testing.T, idp *testIDP) *auth.Tokens {
				return &auth.Tokens{
					Access:   idp.sign(t, idp.claims("alice@example.com")),
					Identity: idp.sign(t, idp.claims("mallory@example.com", "ssh-admin")),
				}
			},
			wantCode:   http.StatusForbidden,
			wantReason: "Possible token substitution",
		},
		{
			name: "expired",
			tokens: func(t *testing.T, idp *testIDP) *auth.Tokens {
				claims := idp.claims("alice@example.com")
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
				token := idp.sign(t, claims)
				return &auth.Tokens{Access: token, Identity: token}
			},
			wantCode:   http.StatusBadRequest,
			wantReason: "the access token has expired",
		},
		{
			name: "wrong issuer",
			tokens: func(t *testing.T, idp *testIDP) *auth.Tokens {
				claims := idp.claims("alice@example.com")
				claims["iss"] = "https://idp.example.com"
				token := idp.sign(t, claims)
				return &auth.Tokens{Access: token, Identity: token}
			},
			wantCode:   http.StatusBadRequest,
			wantReason: "claim validation of the JWT failed",
		},
		{
			name: "identity token for another audience",
			tokens: func(t *testing.T, idp *testIDP) *auth.Tokens {
				claims := idp.claims("alice@example.com")
				claims["aud"] = "another-client"
				return &auth.Tokens{
					Access:   idp.sign(t, idp.claims("alice@example.com")),
					Identity: idp.sign(t, claims),
				}
			},
			wantCode:   http.StatusBadRequest,
			wantReason: "problem parsing identity token",
		},
		{
			name: "access token without email",
			tokens: func(t *testing.T, idp *testIDP) *auth.Tokens {
				claims := idp.claims("alice@example.com")
				delete(claims, "email")
				token := idp.sign(t, claims)
				return &auth.Tokens{Access: token, Identity: token}
			},
			wantCode:   http.StatusBadRequest,
			wantReason: "missing required email claim",
		},
		{
			name: "signed by untrusted key",
			tokens: func(t *testing.T, idp *testIDP) *auth.Tokens {
				token := other.sign(t, idp.claims("alice@example.com"))
				return &auth.Tokens{Access: token, Identity: token}
			},
			wantCode:   http.StatusBadRequest,
			wantReason: "the access token signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// a CA for each test so the reason for rejection can be checked
			ca := newCA(t)

			store := ca.newStore(t)
			u := ca.userCertificate(t, store, tt.tokens(t, ca.IDP))

			assertStatus(t, u.Request(), tt.wantCode)
			ca.assertRejected(t, tt.wantReason)

			if store.HasCertificate() {
				t.Error("a certificate was saved after the request failed")
			}
		})
	}
}
