//go:build !snap && !windows

package cli_test

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// testRevokeCA records revocation requests and responds with status
type testRevokeCA struct {
	config string
	signer ssh.Signer
	status int

	mu    sync.Mutex
	paths []string
}

func (ca *testRevokeCA) requested() []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	return slices.Clone(ca.paths)
}

// revokeCA serves the revocation endpoints with a config file that trusts
// its CA key
func revokeCA(t *testing.T, status int) *testRevokeCA {
	t.Helper()

	ca := &testRevokeCA{signer: newKRLSigner(t), status: status}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.Header.Get("Proof-Of-Possession") == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		ca.mu.Lock()
		ca.paths = append(ca.paths, r.URL.Path)
		ca.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if ca.status != http.StatusOK {
			w.WriteHeader(ca.status)
			_, _ = w.Write([]byte(`{"success":false,"errors":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(api.RevocationResponse{RevokedAt: time.Now()})
	}))
	t.Cleanup(srv.Close)

	ca.config = filepath.Join(t.TempDir(), "config.yml")
	content := fmt.Sprintf(`issuer: http://127.0.0.1:1/
client_id: test-client
scopes: ["openid"]
redirect_url: http://127.0.0.1:1/auth/callback
ca_url: %s/
trusted_ca: %s`, srv.URL, ssh.MarshalAuthorizedKey(ca.signer.PublicKey()))
	if err := os.WriteFile(ca.config, []byte(content), 0600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	return ca
}

// issue generates a key in store and saves a certificate of certType for it
// with serial issued by ca, which is valid for the next hour
func (ca *testRevokeCA) issue(t *testing.T, store cert.Storage, certType uint32, serial uint64) {
	t.Helper()

	now := time.Now()
	ca.issueValid(t, store, certType, serial, now.Add(-time.Minute), now.Add(time.Hour))
}

// issueValid is as for issue with a certificate valid between after and
// before
func (ca *testRevokeCA) issueValid(t *testing.T, store cert.Storage, certType uint32, serial uint64, after, before time.Time) {
	t.Helper()

	if err := store.GeneratePrivateKey(); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, err := store.PublicKey()
	if err != nil {
		t.Fatalf("getting public key: %v", err)
	}

	c := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        certType,
		KeyId:           "test",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(after.Unix()),
		ValidBefore:     uint64(before.Unix()),
	}
	if err := c.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	if err := store.SaveCertificate(c); err != nil {
		t.Fatalf("saving certificate: %v", err)
	}
}

func TestExecute_Revoke(t *testing.T) {
	// keep any running agent out of the tests
	t.Setenv("SSH_AUTH_SOCK", "")

	const serial uint64 = 12345678901234567890

	tests := []struct {
		name      string
		status    int
		serials   []uint64
		wantPaths []string
		wantErr   error
		wantAny   bool
		wantKept  bool
	}{
		{name: "current", status: http.StatusOK, wantPaths: []string{"%s/12345678901234567890"}},
		{name: "already revoked", status: http.StatusConflict, wantPaths: []string{"%s/12345678901234567890"}},
		{name: "unknown", status: http.StatusNotFound, wantPaths: []string{"%s/12345678901234567890"}, wantErr: cert.ErrUnknownCertificate, wantKept: true},
		{name: "server error", status: http.StatusInternalServerError, wantPaths: []string{"%s/12345678901234567890"}, wantAny: true, wantKept: true},
		{name: "other serials", status: http.StatusOK, serials: []uint64{1, 2}, wantPaths: []string{"%s/1", "%s/2"}, wantKept: true},
		{name: "current serial", status: http.StatusOK, serials: []uint64{serial}, wantPaths: []string{"%s/12345678901234567890"}},
	}

	kinds := []struct {
		name     string
		path     string
		certType uint32
		args     func(keypath string) []string
		store    func(t *testing.T, ca *testRevokeCA, keypath string) cert.Storage
	}{
		{
			name:     "user",
			path:     "/api/v4/user/certificates",
			certType: ssh.UserCert,
			args:     func(string) []string { return nil },
			store: func(t *testing.T, ca *testRevokeCA, _ string) cert.Storage {
				keyring.MockInit()
				store, err := store.NewKeyring(ca.signer.PublicKey())
				if err != nil {
					t.Fatalf("creating store: %v", err)
				}
				return store
			},
		},
		{
			name:     "host",
			path:     "/api/v4/host/certificates",
			certType: ssh.HostCert,
			args:     func(keypath string) []string { return []string{"--host", "--key", keypath} },
			store: func(t *testing.T, ca *testRevokeCA, keypath string) cert.Storage {
				store, err := store.NewFile(ca.signer.PublicKey(), keypath)
				if err != nil {
					t.Fatalf("creating store: %v", err)
				}
				return store
			},
		},
	}

	for _, kind := range kinds {
		for _, tt := range tests {
			t.Run(kind.name+"/"+tt.name, func(t *testing.T) {
				ca := revokeCA(t, tt.status)
				keypath := filepath.Join(t.TempDir(), "ssh_host_ed25519_key")
				store := kind.store(t, ca, keypath)
				ca.issue(t, store, kind.certType, serial)

				args := append([]string{"--config", ca.config, "revoke", "--yes"}, kind.args(keypath)...)
				for _, s := range tt.serials {
					args = append(args, "--serial", strconv.FormatUint(s, 10))
				}

				err := execute(t, args...)
				switch {
				case tt.wantErr != nil:
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("Execute() error = %v, want %v", err, tt.wantErr)
					}
				case tt.wantAny:
					if err == nil {
						t.Error("Execute() error = nil, want error")
					}
				case err != nil:
					t.Errorf("Execute() error = %v", err)
				}

				want := make([]string, 0, len(tt.wantPaths))
				for _, p := range tt.wantPaths {
					want = append(want, fmt.Sprintf(p, kind.path))
				}
				if got := ca.requested(); !slices.Equal(got, want) {
					t.Errorf("requested %q, want %q", got, want)
				}

				if got := store.HasCertificate(); got != tt.wantKept {
					t.Errorf("HasCertificate() = %v, want %v", got, tt.wantKept)
				}
				if !store.HasPrivateKey() {
					t.Error("HasPrivateKey() = false, want the key kept")
				}
			})
		}
	}

	t.Run("host skips keys without a certificate", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)
		dir := t.TempDir()
		withCert := filepath.Join(dir, "ssh_host_ed25519_key")
		withoutCert := filepath.Join(dir, "ssh_host_ecdsa_key")

		store, err := store.NewFile(ca.signer.PublicKey(), withCert)
		if err != nil {
			t.Fatalf("creating store: %v", err)
		}
		ca.issue(t, store, ssh.HostCert, serial)

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--host", "--key", withCert, "--key", withoutCert); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if got, want := ca.requested(), []string{"/api/v4/host/certificates/12345678901234567890"}; !slices.Equal(got, want) {
			t.Errorf("requested %q, want %q", got, want)
		}
	})

	t.Run("nothing to revoke", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)
		keypath := filepath.Join(t.TempDir(), "ssh_host_ed25519_key")

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--host", "--key", keypath); !errors.Is(err, cli.ErrNothingToRevoke) {
			t.Errorf("Execute() error = %v, want %v", err, cli.ErrNothingToRevoke)
		}
		if got := ca.requested(); len(got) != 0 {
			t.Errorf("requested %q, want no requests", got)
		}
	})

	t.Run("invalid serial", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--serial", "abc"); err == nil {
			t.Error("Execute() error = nil, want error")
		}
	})

	t.Run("host serial needs a single key", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--host", "--serial", "1"); err == nil {
			t.Error("Execute() error = nil, want error")
		}
		if got := ca.requested(); len(got) != 0 {
			t.Errorf("requested %q, want no requests", got)
		}
	})
}
