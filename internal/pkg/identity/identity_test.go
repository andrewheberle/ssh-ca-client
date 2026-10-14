package identity_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/identity"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// testCA is a CA that issues a user certificate for any request
type testCA struct {
	signer ssh.Signer
	config *config.ClientConfig

	mu       sync.Mutex
	requests int
	auth     string
	lifetime int
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating CA signer: %v", err)
	}

	ca := &testCA{signer: signer}
	srv := httptest.NewServer(http.HandlerFunc(ca.handle))
	t.Cleanup(srv.Close)

	// built in code as LoadClientConfig reads the registry on Windows
	ca.config, err = config.NewClientConfig(config.ClientConfig{
		Issuer:                      "http://127.0.0.1:1/",
		ClientID:                    "test-client",
		Scopes:                      []string{"openid"},
		RedirectURL:                 "http://127.0.0.1:1/auth/callback",
		CertificateAuthorityURL:     srv.URL + "/",
		TrustedCertificateAuthority: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	})
	if err != nil {
		t.Fatalf("creating config: %v", err)
	}

	return ca
}

func (ca *testCA) handle(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.requests++
	ca.auth = r.Header.Get("Authorization")

	var req api.UserCertificateIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Lifetime != nil {
		ca.lifetime = *req.Lifetime
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(req.PublicKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	now := time.Now()
	c := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		KeyId:           "alice@example.com",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca.signer); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.CertificateResponse{Certificate: ssh.MarshalAuthorizedKey(c)})
}

func (ca *testCA) requestCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	return ca.requests
}

// fakeAuth is an [auth.Handler] that returns err, or tokens, and records
// whether each call was non-interactive
type fakeAuth struct {
	err error

	mu    sync.Mutex
	calls []bool
}

func (a *fakeAuth) GetTokens() (*auth.Tokens, error) {
	return a.GetTokensContext(context.Background())
}

func (a *fakeAuth) GetTokensContext(ctx context.Context) (*auth.Tokens, error) {
	a.mu.Lock()
	a.calls = append(a.calls, auth.IsNonInteractive(ctx))
	a.mu.Unlock()

	if a.err != nil {
		return nil, a.err
	}

	return &auth.Tokens{Access: "access-token", Identity: "identity-token"}, nil
}

// newUser returns a [identity.User] for ca with a generated key in memory,
// using a and an in-memory agent
func newUser(t *testing.T, ca *testCA, a auth.Handler, sshAgent agent.ExtendedAgent, opts ...identity.Option) (*identity.User, *store.Store) {
	t.Helper()

	s, err := store.New(ca.signer.PublicKey(), store.NewMemoryBackend(), store.WithAgent(sshAgent))
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	if err := s.GeneratePrivateKey(); err != nil {
		t.Fatalf("generating key: %v", err)
	}

	u, err := identity.NewUser(ca.config, append([]identity.Option{identity.WithStore(s), identity.WithAuthHandler(a)}, opts...)...)
	if err != nil {
		t.Fatalf("NewUser() error = %v", err)
	}

	return u, s
}

func newAgent() agent.ExtendedAgent {
	return agent.NewKeyring().(agent.ExtendedAgent)
}

// agentHolds reports whether a holds c
func agentHolds(t *testing.T, a agent.Agent, c *ssh.Certificate) bool {
	t.Helper()

	keys, err := a.List()
	if err != nil {
		t.Fatalf("agent List() error = %v", err)
	}
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), c.Marshal()) {
			return true
		}
	}

	return false
}

func TestNewUser(t *testing.T) {
	// the defaults use the system keyring
	keyring.MockInit()
	ca := newTestCA(t)

	// the CA and identity provider are not contacted
	u, err := identity.NewUser(ca.config)
	if err != nil {
		t.Fatalf("NewUser() error = %v", err)
	}
	if ca.requestCount() != 0 {
		t.Errorf("NewUser() made %d requests to the CA", ca.requestCount())
	}
	if u.HasPrivateKey() {
		t.Errorf("HasPrivateKey() = true for an empty keyring")
	}
	if _, err := u.Certificate(); !errors.Is(err, cert.ErrCertificateNotFound) {
		t.Errorf("Certificate() error = %v, want %v", err, cert.ErrCertificateNotFound)
	}
}

func TestUser_Obtain(t *testing.T) {
	authErr := errors.New("login failed")

	tests := []struct {
		name            string
		opts            []identity.ObtainOption
		authErr         error
		lockedAgent     bool
		wantErr         error
		wantCert        bool
		wantInAgent     bool
		wantInteractive bool
	}{
		{name: "interactive and added to agent", wantCert: true, wantInAgent: true, wantInteractive: true},
		{name: "without interactive login", opts: []identity.ObtainOption{identity.WithoutInteractiveLogin}, wantCert: true, wantInAgent: true},
		{name: "without agent", opts: []identity.ObtainOption{identity.WithoutAgent}, wantCert: true, wantInteractive: true},
		{name: "both options", opts: []identity.ObtainOption{identity.WithoutAgent, identity.WithoutInteractiveLogin}, wantCert: true},
		{name: "login fails", authErr: authErr, wantErr: authErr, wantInteractive: true},
		{name: "agent fails after certificate is saved", lockedAgent: true, wantErr: cert.ErrAddingToAgent, wantCert: true, wantInteractive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := newTestCA(t)
			a := &fakeAuth{err: tt.authErr}
			sshAgent := newAgent()
			if tt.lockedAgent {
				if err := sshAgent.Lock([]byte("passphrase")); err != nil {
					t.Fatalf("locking agent: %v", err)
				}
			}
			u, _ := newUser(t, ca, a, sshAgent)

			err := u.Obtain(t.Context(), tt.opts...)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Obtain() error = %v, want %v", err, tt.wantErr)
			}

			if len(a.calls) != 1 || a.calls[0] == tt.wantInteractive {
				t.Errorf("authentication calls (non-interactive) = %v, want [%v]", a.calls, !tt.wantInteractive)
			}

			c, certErr := u.Certificate()
			if (certErr == nil) != tt.wantCert {
				t.Fatalf("certificate saved = %v (error %v), want %v", certErr == nil, certErr, tt.wantCert)
			}
			if !tt.wantCert {
				if ca.requestCount() != 0 {
					t.Errorf("%d requests made to the CA, want 0", ca.requestCount())
				}
				return
			}
			if ca.auth != "Bearer access-token" {
				t.Errorf("CA request Authorization = %q, want %q", ca.auth, "Bearer access-token")
			}

			if !tt.lockedAgent {
				if got := agentHolds(t, sshAgent, c); got != tt.wantInAgent {
					t.Errorf("agent holds certificate = %v, want %v", got, tt.wantInAgent)
				}
			}
		})
	}

	t.Run("lifetime", func(t *testing.T) {
		tests := []struct {
			name string
			opts []identity.Option
			want int
		}{
			{"default", nil, int(cert.DefaultUserCertificateLifetime.Seconds())},
			{"with lifetime", []identity.Option{identity.WithLifetime(8 * time.Hour)}, int((8 * time.Hour).Seconds())},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ca := newTestCA(t)
				u, _ := newUser(t, ca, &fakeAuth{}, newAgent(), tt.opts...)

				if err := u.Obtain(t.Context(), identity.WithoutAgent); err != nil {
					t.Fatalf("Obtain() error = %v", err)
				}
				if ca.lifetime != tt.want {
					t.Errorf("requested lifetime = %d, want %d", ca.lifetime, tt.want)
				}
			})
		}
	})
}

func TestUser_AddToAgent(t *testing.T) {
	ca := newTestCA(t)
	sshAgent := newAgent()
	u, _ := newUser(t, ca, &fakeAuth{}, sshAgent)

	if err := u.AddToAgent(); !errors.Is(err, cert.ErrCertificateNotFound) {
		t.Errorf("AddToAgent() without a certificate error = %v, want %v", err, cert.ErrCertificateNotFound)
	}

	if err := u.Obtain(t.Context(), identity.WithoutAgent); err != nil {
		t.Fatalf("Obtain() error = %v", err)
	}
	if err := u.AddToAgent(); err != nil {
		t.Fatalf("AddToAgent() error = %v", err)
	}

	c, err := u.Certificate()
	if err != nil {
		t.Fatalf("Certificate() error = %v", err)
	}
	if !agentHolds(t, sshAgent, c) {
		t.Errorf("agent does not hold the certificate")
	}
}

func TestUser_GeneratePrivateKey(t *testing.T) {
	ca := newTestCA(t)
	u, s := newUser(t, ca, &fakeAuth{}, newAgent())

	if err := u.Obtain(t.Context(), identity.WithoutAgent); err != nil {
		t.Fatalf("Obtain() error = %v", err)
	}
	before, err := s.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}

	if err := u.GeneratePrivateKey(); err != nil {
		t.Fatalf("GeneratePrivateKey() error = %v", err)
	}
	if !u.HasPrivateKey() {
		t.Errorf("HasPrivateKey() = false after GeneratePrivateKey()")
	}
	after, err := s.PublicKeyBytes()
	if err != nil {
		t.Fatalf("PublicKeyBytes() error = %v", err)
	}
	if bytes.Equal(before, after) {
		t.Errorf("GeneratePrivateKey() did not replace the key")
	}

	// the certificate was for the old key
	if _, err := u.Certificate(); !errors.Is(err, cert.ErrCertificateNotFound) {
		t.Errorf("Certificate() error = %v, want %v", err, cert.ErrCertificateNotFound)
	}
}
