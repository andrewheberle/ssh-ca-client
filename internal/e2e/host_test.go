//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"golang.org/x/crypto/ssh"
)

// hostLifetime is the maximum host certificate lifetime configured on the CA
const hostLifetime = time.Hour * 24 * 30

func TestHostCertificate_Request(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	tests := []struct {
		name       string
		tokens     func(t *testing.T) *auth.Tokens
		principals []string
		wantCode   int
	}{
		{
			name:       "allowed by email",
			tokens:     func(t *testing.T) *auth.Tokens { return ca.IDP.tokens(t, "host-admin@example.com") },
			principals: []string{"host1.example.com"},
		},
		{
			name:       "allowed by role",
			tokens:     func(t *testing.T) *auth.Tokens { return ca.IDP.tokens(t, "bob@example.com", "host-admins") },
			principals: []string{"host1.example.com"},
		},
		{
			name:       "several principals",
			tokens:     func(t *testing.T) *auth.Tokens { return ca.IDP.tokens(t, "host-admin@example.com") },
			principals: []string{"host1", "host1.example.com", "192.0.2.1"},
		},
		{
			name:       "not allowed",
			tokens:     func(t *testing.T) *auth.Tokens { return ca.IDP.tokens(t, "bob@example.com", "ssh-admin") },
			principals: []string{"host1.example.com"},
			wantCode:   http.StatusUnauthorized,
		},
		{
			name: "token substitution",
			tokens: func(t *testing.T) *auth.Tokens {
				return &auth.Tokens{
					Access:   ca.IDP.sign(t, ca.IDP.claims("host-admin@example.com")),
					Identity: ca.IDP.sign(t, ca.IDP.claims("bob@example.com", "host-admins")),
				}
			},
			principals: []string{"host1.example.com"},
			wantCode:   http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := ca.newStore(t)
			h := ca.hostCertificate(t, store, tt.tokens(t), tt.principals...)

			err := h.Request()
			if tt.wantCode != 0 {
				assertStatus(t, err, tt.wantCode)
				if store.HasCertificate() {
					t.Error("a certificate was saved after the request failed")
				}
				return
			}

			if err != nil {
				t.Fatalf("requesting host certificate: %v", err)
			}

			c := certificate(t, store)

			pub, err := store.PublicKey()
			if err != nil {
				t.Fatalf("getting public key: %v", err)
			}
			if err := cert.CertificateValid(ca.PublicKey, pub, c); err != nil {
				t.Errorf("certificate not valid: %v", err)
			}

			if c.CertType != ssh.HostCert {
				t.Errorf("certificate type = %d, want %d", c.CertType, ssh.HostCert)
			}

			if !slices.Equal(c.ValidPrincipals, tt.principals) {
				t.Errorf("principals = %v, want %v", c.ValidPrincipals, tt.principals)
			}

			if len(c.Extensions) != 0 {
				t.Errorf("extensions = %v, want none", c.Extensions)
			}

			assertLifetime(t, c, cert.DefaultHostCertificateLifetime)
		})
	}
}

func TestHostCertificate_Lifetime(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	tests := []struct {
		name     string
		lifetime time.Duration
		want     time.Duration
		wantCode int
	}{
		{"shorter than maximum", time.Hour * 48, time.Hour * 48, 0},
		{"maximum", hostLifetime, hostLifetime, 0},
		{"minimum", time.Hour * 24, time.Hour * 24, 0},
		// the CA rejects rather than limits lifetimes outside its range
		{"longer than maximum", hostLifetime * 2, 0, http.StatusBadRequest},
		{"shorter than minimum", time.Hour, 0, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := ca.newStore(t)
			h := ca.hostCertificate(t, store, ca.IDP.tokens(t, "host-admin@example.com"), "host1.example.com")
			h.Lifetime = tt.lifetime

			err := h.Request()
			if tt.wantCode != 0 {
				assertStatus(t, err, tt.wantCode)
				return
			}

			if err != nil {
				t.Fatalf("requesting host certificate: %v", err)
			}

			assertLifetime(t, certificate(t, store), tt.want)
		})
	}
}

func TestHostCertificate_Renew(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	tests := []struct {
		name            string
		requestLifetime time.Duration
		renewLifetime   time.Duration
		want            time.Duration
		wantCode        int
	}{
		{"same lifetime", hostLifetime, hostLifetime, hostLifetime, 0},
		{"shorter lifetime", hostLifetime, time.Hour * 48, time.Hour * 48, 0},
		// renewals cannot extend the lifetime of the original certificate
		{"longer lifetime", time.Hour * 48, hostLifetime, time.Hour * 48, 0},
		{"longer than maximum", hostLifetime, hostLifetime * 2, 0, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store := ca.newStore(t)
			h := ca.hostCertificate(t, store, ca.IDP.tokens(t, "host-admin@example.com"), "host1", "host1.example.com")
			h.Lifetime = tt.requestLifetime
			if err := h.Request(); err != nil {
				t.Fatalf("requesting host certificate: %v", err)
			}
			original := certificate(t, store)
			waitUntilValid(original)

			h.Lifetime = tt.renewLifetime
			err := h.Renew()
			if tt.wantCode != 0 {
				assertStatus(t, err, tt.wantCode)
				if c := certificate(t, store); c.Serial != original.Serial {
					t.Error("certificate was replaced after the renewal failed")
				}
				return
			}

			if err != nil {
				t.Fatalf("renewing host certificate: %v", err)
			}
			renewed := certificate(t, store)

			pub, err := store.PublicKey()
			if err != nil {
				t.Fatalf("getting public key: %v", err)
			}
			if err := cert.CertificateValid(ca.PublicKey, pub, renewed); err != nil {
				t.Errorf("renewed certificate not valid: %v", err)
			}

			if renewed.Serial == original.Serial {
				t.Errorf("serial was not changed: %d", renewed.Serial)
			}

			if renewed.CertType != ssh.HostCert {
				t.Errorf("certificate type = %d, want %d", renewed.CertType, ssh.HostCert)
			}

			if !slices.Equal(renewed.ValidPrincipals, original.ValidPrincipals) {
				t.Errorf("principals = %v, want %v", renewed.ValidPrincipals, original.ValidPrincipals)
			}

			assertLifetime(t, renewed, tt.want)
		})
	}
}

// TestHostCertificate_Renew_Repeated checks a renewed certificate can itself
// be renewed, as happens to a host over time
func TestHostCertificate_Renew_Repeated(t *testing.T) {
	t.Parallel()

	ca := newCA(t)

	store := ca.newStore(t)
	h := ca.hostCertificate(t, store, ca.IDP.tokens(t, "host-admin@example.com"), "host1.example.com")
	if err := h.Request(); err != nil {
		t.Fatalf("requesting host certificate: %v", err)
	}

	// renewals do not need authentication
	h.AuthHandler = nil

	serials := []uint64{certificate(t, store).Serial}
	for i := range 3 {
		waitUntilValid(certificate(t, store))

		if err := h.Renew(); err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}

		serial := certificate(t, store).Serial
		if slices.Contains(serials, serial) {
			t.Errorf("renewal %d: serial %d was reused", i+1, serial)
		}
		serials = append(serials, serial)
	}
}

func TestHostCertificate_Renew_Rejected(t *testing.T) {
	t.Parallel()

	// returns a host certificate for the key in store, signed by sign
	hostCert := func(t *testing.T, store cert.Storage, validAfter, validBefore time.Time, sign func(*ssh.Certificate)) *ssh.Certificate {
		pub, err := store.PublicKey()
		if err != nil {
			t.Fatalf("getting public key: %v", err)
		}

		c := &ssh.Certificate{
			Key:             pub,
			Serial:          1,
			CertType:        ssh.HostCert,
			KeyId:           "host_host1.example.com",
			ValidPrincipals: []string{"host1.example.com"},
			ValidAfter:      uint64(validAfter.Unix()),
			ValidBefore:     uint64(validBefore.Unix()),
		}
		sign(c)

		return c
	}

	// returns a store with a host certificate issued by ca
	issued := func(t *testing.T, ca *testCA) cert.Storage {
		store := ca.newStore(t)
		if err := ca.hostCertificate(t, store, ca.IDP.tokens(t, "host-admin@example.com"), "host1.example.com").Request(); err != nil {
			t.Fatalf("requesting host certificate: %v", err)
		}

		return store
	}

	tests := []struct {
		name       string
		store      func(t *testing.T, ca *testCA) cert.Storage
		wantReason string
	}{
		{
			name: "revoked",
			store: func(t *testing.T, ca *testCA) cert.Storage {
				store := issued(t, ca)

				if code := ca.revoke(t, api.PostCertificateTypeRevokeParamsCertificateTypeHost, certificate(t, store).Serial, store); code != http.StatusOK {
					t.Fatalf("revocation status code = %d, want %d", code, http.StatusOK)
				}

				return store
			},
			wantReason: "the provided certificate is revoked",
		},
		{
			name: "expired",
			store: func(t *testing.T, ca *testCA) cert.Storage {
				store := ca.newStore(t)
				now := time.Now()

				return &certStore{
					Storage:     store,
					certificate: hostCert(t, store, now.Add(-time.Hour*2), now.Add(-time.Hour), func(c *ssh.Certificate) { ca.sign(t, c) }),
				}
			},
			wantReason: "the provided certificate is expired",
		},
		{
			name: "issued by another CA",
			store: func(t *testing.T, ca *testCA) cert.Storage {
				store := ca.newStore(t)
				now := time.Now()

				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generating key: %v", err)
				}
				other, err := ssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatalf("creating signer: %v", err)
				}

				return &certStore{
					Storage: store,
					certificate: hostCert(t, store, now.Add(-time.Minute), now.Add(time.Hour), func(c *ssh.Certificate) {
						if err := c.SignCert(rand.Reader, other); err != nil {
							t.Fatalf("signing certificate: %v", err)
						}
					}),
				}
			},
			wantReason: "the provided certificate was not signed by this CA",
		},
		{
			name: "certificate for another key",
			store: func(t *testing.T, ca *testCA) cert.Storage {
				return &certStore{
					Storage:     ca.newStore(t),
					certificate: certificate(t, issued(t, ca)),
				}
			},
			wantReason: "proof of possession fingerprints did not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// a CA for each test so the reason for rejection can be checked
			ca := newCA(t)

			store := tt.store(t, ca)
			original := certificate(t, store)
			waitUntilValid(original)

			h := ca.hostCertificate(t, store, nil)
			assertStatus(t, h.Renew(), http.StatusBadRequest)
			ca.assertRejected(t, tt.wantReason)

			if c := certificate(t, store); c.Serial != original.Serial {
				t.Error("certificate was replaced after the renewal failed")
			}
		})
	}
}
