package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

var testPrincipals = []string{"host.example.com", "host"}

// newTestHostCertificate returns a HostCertificate for server using store,
// with test principals and an auth handler that returns test tokens
func newTestHostCertificate(t *testing.T, server string, store Storage) *HostCertificate {
	t.Helper()

	h, err := NewHostCertificate(server, store)
	if err != nil {
		t.Fatalf("NewHostCertificate() error = %v", err)
	}
	h.AuthHandler = &fakeAuth{tokens: &auth.Tokens{Access: "access-token", Identity: "identity-token"}}
	h.Principals = testPrincipals

	return h
}

// existingHostCert returns a currently valid host certificate for key with
// the test principals, signed by ca
func existingHostCert(t *testing.T, ca ssh.Signer, key crypto.Signer) *ssh.Certificate {
	t.Helper()

	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatalf("could not get public key: %v", err)
	}

	now := time.Now()
	c := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.HostCert,
		KeyId:           "host",
		ValidPrincipals: testPrincipals,
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("could not sign certificate: %v", err)
	}

	return c
}

// renewableStore returns a fakeStore holding a new key and an existing host
// certificate for it issued by ca
func renewableStore(t *testing.T, ca *fakeCA) (*fakeStore, *ecdsa.PrivateKey) {
	t.Helper()

	key, signer := newKeySigner(t)

	return &fakeStore{signer: signer, cert: existingHostCert(t, ca.ca, key)}, key
}

func TestNewHostCertificate(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		store := &fakeStore{}

		h, err := NewHostCertificate("https://ca.example.com", store)
		if err != nil {
			t.Fatalf("NewHostCertificate() error = %v", err)
		}

		if h.Lifetime != DefaultHostCertificateLifetime {
			t.Errorf("Lifetime = %v, want %v", h.Lifetime, DefaultHostCertificateLifetime)
		}
		if h.AuthHandler != nil {
			t.Errorf("AuthHandler = %v, want nil", h.AuthHandler)
		}
		if h.Store() != store {
			t.Errorf("Store() did not return the provided store")
		}

		hostname, err := os.Hostname()
		if err != nil {
			t.Skipf("could not get hostname: %v", err)
		}
		want := []string{strings.ToLower(hostname)}
		if !reflect.DeepEqual(h.Principals, want) {
			t.Errorf("Principals = %v, want %v", h.Principals, want)
		}
	})

	t.Run("with options", func(t *testing.T) {
		hc := &http.Client{}

		h, err := NewHostCertificate("https://ca.example.com", &fakeStore{}, WithHTTPClient(hc))
		if err != nil {
			t.Fatalf("NewHostCertificate() error = %v", err)
		}

		if got := apiHTTPClient(t, h.BaseCertificate); got != hc {
			t.Errorf("API client does not use the HTTP client from WithHTTPClient")
		}
	})
}

func TestHostCertificate_Request(t *testing.T) {
	tests := []struct {
		name         string
		lifetime     time.Duration
		principals   []string
		wantLifetime int
	}{
		{"defaults", 0, testPrincipals, int(DefaultHostCertificateLifetime.Seconds())},
		{"custom lifetime", time.Hour, testPrincipals, 3600},
		{"single principal", 0, []string{"only.example.com"}, int(DefaultHostCertificateLifetime.Seconds())},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCA(t)
			_, signer := newKeySigner(t)
			store := &fakeStore{signer: signer}
			h := newTestHostCertificate(t, ca.URL, store)
			h.Principals = tt.principals
			if tt.lifetime != 0 {
				h.Lifetime = tt.lifetime
			}

			if err := h.Request(); err != nil {
				t.Fatalf("Request() error = %v", err)
			}

			if ca.path != hostCertificatePath {
				t.Errorf("request path = %q, want %q", ca.path, hostCertificatePath)
			}
			if ca.auth != "Bearer access-token" {
				t.Errorf("Authorization = %q, want %q", ca.auth, "Bearer access-token")
			}
			if ca.payload.Identity != "identity-token" {
				t.Errorf("identity = %q, want %q", ca.payload.Identity, "identity-token")
			}
			if !reflect.DeepEqual(ca.payload.Principals, tt.principals) {
				t.Errorf("principals = %v, want %v", ca.payload.Principals, tt.principals)
			}
			if string(ca.payload.PublicKey) != string(ssh.MarshalAuthorizedKey(signer.PublicKey())) {
				t.Errorf("public key = %q, want %q", ca.payload.PublicKey, ssh.MarshalAuthorizedKey(signer.PublicKey()))
			}
			if ca.payload.Lifetime == nil || *ca.payload.Lifetime != tt.wantLifetime {
				t.Errorf("lifetime = %v, want %d", ca.payload.Lifetime, tt.wantLifetime)
			}
			if ca.proofErr != nil {
				t.Errorf("proof did not verify: %v", ca.proofErr)
			}

			if store.saved == nil {
				t.Fatalf("certificate was not saved")
			}
			if string(store.saved.Marshal()) != string(ca.issued.Marshal()) {
				t.Errorf("saved certificate does not match issued certificate")
			}
			if store.saved.CertType != ssh.HostCert {
				t.Errorf("saved certificate type = %d, want %d", store.saved.CertType, ssh.HostCert)
			}
			if err := CertificateValid(ca.ca.PublicKey(), signer.PublicKey(), store.saved); err != nil {
				t.Errorf("saved certificate is not valid: %v", err)
			}
		})
	}
}

func TestHostCertificate_Request_Errors(t *testing.T) {
	authErr := errors.New("login failed")

	tests := []struct {
		name      string
		setup     func(h *HostCertificate, store *fakeStore)
		wantErr   error
		wantLogin bool // the auth handler is expected to be called
	}{
		{
			name:    "no auth handler",
			setup:   func(h *HostCertificate, store *fakeStore) { h.AuthHandler = nil },
			wantErr: ErrNoAuthHandlerAvailable,
		},
		{
			name: "authentication error",
			setup: func(h *HostCertificate, store *fakeStore) {
				h.AuthHandler = &fakeAuth{err: authErr}
			},
			wantErr:   authErr,
			wantLogin: true,
		},
		{
			name:    "nil principals",
			setup:   func(h *HostCertificate, store *fakeStore) { h.Principals = nil },
			wantErr: ErrEmptyPrincipalsList,
		},
		{
			name:    "empty principals",
			setup:   func(h *HostCertificate, store *fakeStore) { h.Principals = []string{} },
			wantErr: ErrEmptyPrincipalsList,
		},
		{
			name: "no signer",
			setup: func(h *HostCertificate, store *fakeStore) {
				store.signer, store.signerErr = nil, ErrKeyNotFound
			},
			wantErr:   ErrKeyNotFound,
			wantLogin: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCA(t)
			store := &fakeStore{signer: newSigner(t)}
			h := newTestHostCertificate(t, ca.URL, store)
			tt.setup(h, store)

			err := h.Request()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Request() error = %v, want %v", err, tt.wantErr)
			}
			if got := ca.requestCount(); got != 0 {
				t.Errorf("CA received %d requests, want 0", got)
			}
			if a, ok := h.AuthHandler.(*fakeAuth); ok {
				if called := a.calls.Load() > 0; called != tt.wantLogin {
					t.Errorf("auth handler called = %v, want %v", called, tt.wantLogin)
				}
			}
			if store.saved != nil {
				t.Errorf("certificate was saved despite error")
			}
		})
	}
}

func TestHostCertificate_RequestContext(t *testing.T) {
	t.Run("cancelled while authenticating", func(t *testing.T) {
		ca := newFakeCA(t)
		store := &fakeStore{signer: newSigner(t)}
		h := newTestHostCertificate(t, ca.URL, store)
		h.AuthHandler = &fakeAuth{block: true}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		if err := h.RequestContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("RequestContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
		if got := ca.requestCount(); got != 0 {
			t.Errorf("CA received %d requests, want 0", got)
		}
	})

	t.Run("cancelled during CA request", func(t *testing.T) {
		ca := newFakeCA(t)
		ca.hang = true
		store := &fakeStore{signer: newSigner(t)}
		h := newTestHostCertificate(t, ca.URL, store)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		if err := h.RequestContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("RequestContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("RequestContext() took %v after cancellation, want < 1s", elapsed)
		}
		if store.saved != nil {
			t.Errorf("certificate was saved despite cancellation")
		}
	})

	t.Run("already cancelled", func(t *testing.T) {
		ca := newFakeCA(t)
		store := &fakeStore{signer: newSigner(t)}
		h := newTestHostCertificate(t, ca.URL, store)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := h.RequestContext(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("RequestContext() error = %v, want %v", err, context.Canceled)
		}
		if got := ca.requestCount(); got != 0 {
			t.Errorf("CA received %d requests, want 0", got)
		}
	})
}

func TestHostCertificate_Renew(t *testing.T) {
	tests := []struct {
		name         string
		lifetime     time.Duration
		wantLifetime int
	}{
		{"default lifetime", 0, int(DefaultHostCertificateLifetime.Seconds())},
		{"custom lifetime", time.Hour, 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCA(t)
			store, _ := renewableStore(t, ca)
			existing := ssh.MarshalAuthorizedKey(store.cert)

			h := newTestHostCertificate(t, ca.URL, store)
			// renewal uses proof of possession so needs no auth handler
			h.AuthHandler = nil
			if tt.lifetime != 0 {
				h.Lifetime = tt.lifetime
			}

			if err := h.Renew(); err != nil {
				t.Fatalf("Renew() error = %v", err)
			}

			if ca.path != hostRenewPath {
				t.Errorf("request path = %q, want %q", ca.path, hostRenewPath)
			}
			if ca.auth != "" {
				t.Errorf("Authorization = %q, want none", ca.auth)
			}
			if string(ca.payload.Certificate) != string(existing) {
				t.Errorf("certificate = %q, want existing certificate %q", ca.payload.Certificate, existing)
			}
			if string(ca.payload.PublicKey) != string(ssh.MarshalAuthorizedKey(store.signer.PublicKey())) {
				t.Errorf("public key = %q, want %q", ca.payload.PublicKey, ssh.MarshalAuthorizedKey(store.signer.PublicKey()))
			}
			if ca.payload.Lifetime == nil || *ca.payload.Lifetime != tt.wantLifetime {
				t.Errorf("lifetime = %v, want %d", ca.payload.Lifetime, tt.wantLifetime)
			}
			if ca.proofErr != nil {
				t.Errorf("proof did not verify: %v", ca.proofErr)
			}

			if store.saved == nil {
				t.Fatalf("certificate was not saved")
			}
			if string(store.saved.Marshal()) != string(ca.issued.Marshal()) {
				t.Errorf("saved certificate does not match issued certificate")
			}
			if !reflect.DeepEqual(store.saved.ValidPrincipals, testPrincipals) {
				t.Errorf("saved principals = %v, want %v", store.saved.ValidPrincipals, testPrincipals)
			}
			if err := CertificateValid(ca.ca.PublicKey(), store.signer.PublicKey(), store.saved); err != nil {
				t.Errorf("saved certificate is not valid: %v", err)
			}
		})
	}
}

func TestHostCertificate_Renew_Errors(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(store *fakeStore)
		wantErr error
	}{
		{
			name:    "no certificate",
			setup:   func(store *fakeStore) { store.cert, store.certErr = nil, ErrCertificateNotFound },
			wantErr: ErrCertificateNotFound,
		},
		{
			name:    "no signer",
			setup:   func(store *fakeStore) { store.signer, store.signerErr = nil, ErrKeyNotFound },
			wantErr: ErrKeyNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCA(t)
			store, _ := renewableStore(t, ca)
			h := newTestHostCertificate(t, ca.URL, store)
			tt.setup(store)

			if err := h.Renew(); !errors.Is(err, tt.wantErr) {
				t.Errorf("Renew() error = %v, want %v", err, tt.wantErr)
			}
			if got := ca.requestCount(); got != 0 {
				t.Errorf("CA received %d requests, want 0", got)
			}
			if store.saved != nil {
				t.Errorf("certificate was saved despite error")
			}
		})
	}
}

func TestHostCertificate_RenewContext(t *testing.T) {
	t.Run("cancelled during CA request", func(t *testing.T) {
		ca := newFakeCA(t)
		ca.hang = true
		store, _ := renewableStore(t, ca)
		h := newTestHostCertificate(t, ca.URL, store)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		if err := h.RenewContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("RenewContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("RenewContext() took %v after cancellation, want < 1s", elapsed)
		}
		if store.saved != nil {
			t.Errorf("certificate was saved despite cancellation")
		}
	})

	t.Run("already cancelled", func(t *testing.T) {
		ca := newFakeCA(t)
		store, _ := renewableStore(t, ca)
		h := newTestHostCertificate(t, ca.URL, store)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := h.RenewContext(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("RenewContext() error = %v, want %v", err, context.Canceled)
		}
		if store.saved != nil {
			t.Errorf("certificate was saved despite cancellation")
		}
	})
}

// TestHostCertificate_ResponseErrors checks Request and Renew handle the same
// CA response failures
func TestHostCertificate_ResponseErrors(t *testing.T) {
	saveErr := errors.New("disk full")

	ops := []struct {
		name string
		call func(h *HostCertificate) error
	}{
		{"Request", (*HostCertificate).Request},
		{"Renew", (*HostCertificate).Renew},
	}

	tests := []struct {
		name         string
		setup        func(ca *fakeCA, store *fakeStore)
		wantErr      error  // checked with errors.Is when set
		wantMsg      string // checked with strings.Contains when set
		wantRequests int
	}{
		{
			name:    "server unavailable",
			setup:   func(ca *fakeCA, store *fakeStore) { ca.Close() },
			wantMsg: "host certificate",
		},
		{
			name:         "unauthorized",
			setup:        func(ca *fakeCA, store *fakeStore) { ca.status = http.StatusUnauthorized },
			wantMsg:      "bad status code: 401",
			wantRequests: 1,
		},
		{
			name:         "server error",
			setup:        func(ca *fakeCA, store *fakeStore) { ca.status = http.StatusInternalServerError },
			wantMsg:      "bad status code: 500",
			wantRequests: 1,
		},
		{
			name: "forbidden with error messages",
			setup: func(ca *fakeCA, store *fakeStore) {
				ca.status = http.StatusForbidden
				ca.body = `{"success":false,"errors":[{"code":403,"message":"host not allowed"}]}`
			},
			wantMsg:      "bad status code: 403: host not allowed",
			wantRequests: 1,
		},
		{
			name:         "invalid json response",
			setup:        func(ca *fakeCA, store *fakeStore) { ca.body = "not json" },
			wantMsg:      "host certificate",
			wantRequests: 1,
		},
		{
			name: "non-json response",
			setup: func(ca *fakeCA, store *fakeStore) {
				ca.contentType = "text/plain"
				ca.body = "ok"
			},
			wantErr:      ErrUnexpectedResponse,
			wantRequests: 1,
		},
		{
			name:         "invalid certificate in response",
			setup:        func(ca *fakeCA, store *fakeStore) { ca.body = `{"certificate":"bm90IGEgY2VydA=="}` },
			wantMsg:      "could not parse certificate",
			wantRequests: 1,
		},
		{
			name:         "save failed",
			setup:        func(ca *fakeCA, store *fakeStore) { store.saveErr = saveErr },
			wantErr:      saveErr,
			wantRequests: 1,
		},
	}
	for _, op := range ops {
		for _, tt := range tests {
			t.Run(op.name+"/"+tt.name, func(t *testing.T) {
				ca := newFakeCA(t)
				store, _ := renewableStore(t, ca)
				h := newTestHostCertificate(t, ca.URL, store)
				tt.setup(ca, store)

				err := op.call(h)
				if err == nil {
					t.Fatalf("%s() error = nil, want error", op.name)
				}
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("%s() error = %v, want %v", op.name, err, tt.wantErr)
				}
				if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("%s() error = %q, want it to contain %q", op.name, err, tt.wantMsg)
				}
				if got := ca.requestCount(); got != tt.wantRequests {
					t.Errorf("CA received %d requests, want %d", got, tt.wantRequests)
				}
				if store.saved != nil {
					t.Errorf("certificate was saved despite error")
				}
			})
		}
	}
}

func TestHostCertificate_Concurrent(t *testing.T) {
	ca := newFakeCA(t)
	store, _ := renewableStore(t, ca)
	h := newTestHostCertificate(t, ca.URL, store)

	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 3 {
		wg.Go(func() { errs <- h.Request() })
		wg.Go(func() { errs <- h.Renew() })
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("Request()/Renew() error = %v", err)
		}
	}
	if got := ca.requestCount(); got != 6 {
		t.Errorf("CA received %d requests, want 6", got)
	}
}

// TestHostCertificate_KeyTypes checks requests and renewals work, including
// proof of possession, for each supported key type
func TestHostCertificate_KeyTypes(t *testing.T) {
	keyTypes := []sshkey.KeyType{sshkey.KeyTypeECDSA, sshkey.KeyTypeEd25519, sshkey.KeyTypeRSA}

	for _, keyType := range keyTypes {
		t.Run(string(keyType), func(t *testing.T) {
			ca := newFakeCA(t)
			key := newTypedKey(t, keyType)
			signer, err := ssh.NewSignerFromSigner(key)
			if err != nil {
				t.Fatalf("could not create signer: %v", err)
			}
			store := &fakeStore{signer: signer}
			h := newTestHostCertificate(t, ca.URL, store)

			if err := h.Request(); err != nil {
				t.Fatalf("Request() error = %v", err)
			}
			if ca.proofErr != nil {
				t.Errorf("Request() proof did not verify: %v", ca.proofErr)
			}
			if err := CertificateValid(ca.ca.PublicKey(), signer.PublicKey(), store.saved); err != nil {
				t.Errorf("requested certificate is not valid: %v", err)
			}

			// renew the certificate that was just issued
			store.cert, store.saved = store.saved, nil
			if err := h.Renew(); err != nil {
				t.Fatalf("Renew() error = %v", err)
			}
			if ca.proofErr != nil {
				t.Errorf("Renew() proof did not verify: %v", ca.proofErr)
			}
			if err := CertificateValid(ca.ca.PublicKey(), signer.PublicKey(), store.saved); err != nil {
				t.Errorf("renewed certificate is not valid: %v", err)
			}
		})
	}
}
