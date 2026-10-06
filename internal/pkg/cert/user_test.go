package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/pkg/proof"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshcert"
	"golang.org/x/crypto/ssh"
)

// fakeAuth is an [auth.Handler] that returns fixed tokens
type fakeAuth struct {
	auth.Handler

	tokens *auth.Tokens
	err    error
	block  bool // block until ctx is done, as an interactive login would

	calls atomic.Int32
}

func (a *fakeAuth) GetTokens() (*auth.Tokens, error) {
	return a.GetTokensContext(context.Background())
}

func (a *fakeAuth) GetTokensContext(ctx context.Context) (*auth.Tokens, error) {
	a.calls.Add(1)

	if a.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	return a.tokens, a.err
}

// CA API endpoints served by fakeCA
const (
	userCertificatePath = "/api/v3/user/certificate"
	hostCertificatePath = "/api/v3/host/certificate"
	hostRenewPath       = "/api/v3/host/renew"
)

// caRequest holds the fields of any of the user certificate, host
// certificate and host renewal request payloads
type caRequest struct {
	Certificate []byte   `json:"certificate"`
	Identity    string   `json:"identity"`
	Lifetime    *int     `json:"lifetime"`
	Principals  []string `json:"principals"`
	Proof       string   `json:"proof"`
	PublicKey   []byte   `json:"public_key"`
}

// fakeCA is a test CA server for the user and host certificate endpoints. By
// default it verifies the proof and returns a certificate signed by its CA
// key.
type fakeCA struct {
	*httptest.Server

	ca ssh.Signer

	// behaviour overrides
	status      int    // non-zero to respond with this status
	contentType string // overrides the response content type
	body        string // overrides the response body
	hang        bool   // do not respond until the test finishes

	release chan struct{} // closed when the test finishes

	mu       sync.Mutex
	requests int
	path     string
	auth     string
	payload  caRequest
	proofErr error
	issued   *ssh.Certificate
}

func newFakeCA(t *testing.T) *fakeCA {
	t.Helper()

	ca := &fakeCA{ca: newCA(t), release: make(chan struct{})}
	ca.Server = httptest.NewServer(http.HandlerFunc(ca.handle))
	t.Cleanup(ca.Close)
	// cleanups run last-in first-out so hung handlers are released before
	// the server is closed
	t.Cleanup(func() { close(ca.release) })

	return ca
}

func (ca *fakeCA) handle(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	switch r.URL.Path {
	case userCertificatePath, hostCertificatePath, hostRenewPath:
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ca.requests++
	ca.path = r.URL.Path
	ca.auth = r.Header.Get("Authorization")

	if ca.hang {
		<-ca.release
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&ca.payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	contentType := "application/json"
	if ca.contentType != "" {
		contentType = ca.contentType
	}
	w.Header().Set("Content-Type", contentType)

	if ca.status != 0 {
		w.WriteHeader(ca.status)
		_, _ = w.Write([]byte(`{"success":false,"errors":[]}`))
		return
	}

	if ca.body != "" {
		_, _ = w.Write([]byte(ca.body))
		return
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(ca.payload.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// record whether the proof of possession verifies for the public key
	p, err := proof.Parse(ca.payload.Proof)
	if err == nil {
		err = p.Verify(pub, time.Minute)
	}
	ca.proofErr = err

	lifetime := time.Hour
	if ca.payload.Lifetime != nil {
		lifetime = time.Duration(*ca.payload.Lifetime) * time.Second
	}

	now := time.Now()
	c := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "test@example.com",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(lifetime).Unix()),
	}
	switch ca.path {
	case hostCertificatePath:
		c.CertType = ssh.HostCert
		c.KeyId = "host"
		c.ValidPrincipals = ca.payload.Principals
	case hostRenewPath:
		// a renewal keeps the principals of the existing certificate
		c.CertType = ssh.HostCert
		c.KeyId = "host"
		if existing, err := sshcert.ParseCert(ca.payload.Certificate); err == nil {
			c.ValidPrincipals = existing.ValidPrincipals
		}
	}
	if err := c.SignCert(rand.Reader, ca.ca); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ca.issued = c

	_ = json.NewEncoder(w).Encode(api.CertificateResponse{Certificate: ssh.MarshalAuthorizedKey(c)})
}

// requestCount returns the number of certificate requests the CA received
func (ca *fakeCA) requestCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	return ca.requests
}

// newKeySigner returns a new ECDSA P-256 key and an ssh.Signer for it
func newKeySigner(t *testing.T) (*ecdsa.PrivateKey, ssh.Signer) {
	t.Helper()

	key := newKey(t, elliptic.P256())
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("could not create signer: %v", err)
	}

	return key, signer
}

// newSigner returns an ssh.Signer for a new ECDSA P-256 key
func newSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, signer := newKeySigner(t)

	return signer
}

// newTestUserCertificate returns a UserCertificate for server using store,
// with an auth handler that returns test tokens
func newTestUserCertificate(t *testing.T, server string, store Storage) *UserCertificate {
	t.Helper()

	u, err := NewUserCertificate(server, store)
	if err != nil {
		t.Fatalf("NewUserCertificate() error = %v", err)
	}
	u.AuthHandler = &fakeAuth{tokens: &auth.Tokens{Access: "access-token", Identity: "identity-token"}}

	return u
}

func TestNewUserCertificate(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		store := &fakeStore{}

		u, err := NewUserCertificate("https://ca.example.com", store)
		if err != nil {
			t.Fatalf("NewUserCertificate() error = %v", err)
		}

		if u.Lifetime != DefaultUserCertificateLifetime {
			t.Errorf("Lifetime = %v, want %v", u.Lifetime, DefaultUserCertificateLifetime)
		}
		if u.AuthHandler != nil {
			t.Errorf("AuthHandler = %v, want nil", u.AuthHandler)
		}
		if u.store != store {
			t.Errorf("store was not set")
		}
		if u.client == nil {
			t.Errorf("API client was not set")
		}
	})

	t.Run("with options", func(t *testing.T) {
		h := &http.Client{}

		u, err := NewUserCertificate("https://ca.example.com", &fakeStore{}, WithHTTPClient(h))
		if err != nil {
			t.Fatalf("NewUserCertificate() error = %v", err)
		}

		if got := apiHTTPClient(t, u.BaseCertificate); got != h {
			t.Errorf("API client does not use the HTTP client from WithHTTPClient")
		}
	})
}

func TestUserCertificate_Request(t *testing.T) {
	tests := []struct {
		name         string
		lifetime     time.Duration
		wantLifetime int
	}{
		{"default lifetime", 0, int(DefaultUserCertificateLifetime.Seconds())},
		{"custom lifetime", time.Hour, 3600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCA(t)
			_, signer := newKeySigner(t)
			store := &fakeStore{signer: signer}
			u := newTestUserCertificate(t, ca.URL, store)
			if tt.lifetime != 0 {
				u.Lifetime = tt.lifetime
			}

			if err := u.Request(); err != nil {
				t.Fatalf("Request() error = %v", err)
			}

			if ca.path != userCertificatePath {
				t.Errorf("request path = %q, want %q", ca.path, userCertificatePath)
			}
			if ca.auth != "Bearer access-token" {
				t.Errorf("Authorization = %q, want %q", ca.auth, "Bearer access-token")
			}
			if ca.payload.Identity != "identity-token" {
				t.Errorf("identity = %q, want %q", ca.payload.Identity, "identity-token")
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
			if err := CertificateValid(ca.ca.PublicKey(), signer.PublicKey(), store.saved); err != nil {
				t.Errorf("saved certificate is not valid: %v", err)
			}
		})
	}
}

func TestUserCertificate_Request_Errors(t *testing.T) {
	authErr := errors.New("login failed")
	saveErr := errors.New("disk full")

	tests := []struct {
		name         string
		setup        func(ca *fakeCA, u *UserCertificate, store *fakeStore)
		wantErr      error  // checked with errors.Is when set
		wantMsg      string // checked with strings.Contains when set
		wantRequests int
	}{
		{
			name:    "no auth handler",
			setup:   func(ca *fakeCA, u *UserCertificate, store *fakeStore) { u.AuthHandler = nil },
			wantErr: ErrNoAuthHandlerAvailable,
		},
		{
			name: "authentication error",
			setup: func(ca *fakeCA, u *UserCertificate, store *fakeStore) {
				u.AuthHandler = &fakeAuth{err: authErr}
			},
			wantErr: authErr,
		},
		{
			name: "no signer",
			setup: func(ca *fakeCA, u *UserCertificate, store *fakeStore) {
				store.signer, store.signerErr = nil, ErrKeyNotFound
			},
			wantErr: ErrKeyNotFound,
		},
		{
			name:         "server unavailable",
			setup:        func(ca *fakeCA, u *UserCertificate, store *fakeStore) { ca.Close() },
			wantMsg:      "user certificate request:",
			wantRequests: 0,
		},
		{
			name:         "unauthorized",
			setup:        func(ca *fakeCA, u *UserCertificate, store *fakeStore) { ca.status = http.StatusUnauthorized },
			wantMsg:      "bad status code: 401",
			wantRequests: 1,
		},
		{
			name:         "server error",
			setup:        func(ca *fakeCA, u *UserCertificate, store *fakeStore) { ca.status = http.StatusInternalServerError },
			wantMsg:      "bad status code: 500",
			wantRequests: 1,
		},
		{
			name:         "invalid json response",
			setup:        func(ca *fakeCA, u *UserCertificate, store *fakeStore) { ca.body = "not json" },
			wantMsg:      "user certificate request:",
			wantRequests: 1,
		},
		{
			name: "non-json response",
			setup: func(ca *fakeCA, u *UserCertificate, store *fakeStore) {
				ca.contentType = "text/plain"
				ca.body = "ok"
			},
			wantErr:      ErrUnexpectedResponse,
			wantRequests: 1,
		},
		{
			name:         "invalid certificate in response",
			setup:        func(ca *fakeCA, u *UserCertificate, store *fakeStore) { ca.body = `{"certificate":"bm90IGEgY2VydA=="}` },
			wantMsg:      "could not parse certificate",
			wantRequests: 1,
		},
		{
			name:         "save failed",
			setup:        func(ca *fakeCA, u *UserCertificate, store *fakeStore) { store.saveErr = saveErr },
			wantErr:      saveErr,
			wantRequests: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newFakeCA(t)
			store := &fakeStore{signer: newSigner(t)}
			u := newTestUserCertificate(t, ca.URL, store)
			tt.setup(ca, u, store)

			err := u.Request()
			if err == nil {
				t.Fatalf("Request() error = nil, want error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Request() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Request() error = %q, want it to contain %q", err, tt.wantMsg)
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

func TestUserCertificate_Request_Concurrent(t *testing.T) {
	ca := newFakeCA(t)
	store := &fakeStore{signer: newSigner(t)}
	u := newTestUserCertificate(t, ca.URL, store)

	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for range 5 {
		wg.Go(func() { errs <- u.Request() })
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("Request() error = %v", err)
		}
	}
	if got := ca.requestCount(); got != 5 {
		t.Errorf("CA received %d requests, want 5", got)
	}
}

func TestUserCertificate_RequestContext(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ca := newFakeCA(t)
		store := &fakeStore{signer: newSigner(t)}
		u := newTestUserCertificate(t, ca.URL, store)

		if err := u.RequestContext(context.Background()); err != nil {
			t.Fatalf("RequestContext() error = %v", err)
		}
		if store.saved == nil {
			t.Errorf("certificate was not saved")
		}
	})

	t.Run("cancelled while authenticating", func(t *testing.T) {
		ca := newFakeCA(t)
		store := &fakeStore{signer: newSigner(t)}
		u := newTestUserCertificate(t, ca.URL, store)
		u.AuthHandler = &fakeAuth{block: true}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		err := u.RequestContext(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
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
		u := newTestUserCertificate(t, ca.URL, store)

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		err := u.RequestContext(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("RequestContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
		// the default HTTP client timeout is 3s, so returning sooner shows
		// the context aborted the request
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
		u := newTestUserCertificate(t, ca.URL, store)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if err := u.RequestContext(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("RequestContext() error = %v, want %v", err, context.Canceled)
		}
		if got := ca.requestCount(); got != 0 {
			t.Errorf("CA received %d requests, want 0", got)
		}
	})
}
