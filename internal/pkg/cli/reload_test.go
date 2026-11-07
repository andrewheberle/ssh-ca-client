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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
	"golang.org/x/crypto/ssh"
)

// renewCA serves host certificate renewals, failing the renewal of serial
// fail, with a config file that trusts its CA key
func renewCA(t *testing.T, fail uint64) *testRevokeCA {
	t.Helper()

	ca := &testRevokeCA{signer: newKRLSigner(t)}
	var serial atomic.Uint64
	serial.Store(1000)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/renew") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/"+strconv.FormatUint(fail, 10)+"/renew") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success":false,"errors":[]}`))
			return
		}

		var req api.HostCertificateRenewalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(req.Certificate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		existing, ok := pub.(*ssh.Certificate)
		if !ok {
			http.Error(w, "not a certificate", http.StatusBadRequest)
			return
		}

		now := time.Now()
		c := &ssh.Certificate{
			Key:             existing.Key,
			Serial:          serial.Add(1),
			CertType:        ssh.HostCert,
			KeyId:           existing.KeyId,
			ValidPrincipals: existing.ValidPrincipals,
			ValidAfter:      uint64(now.Add(-time.Minute).Unix()),
			ValidBefore:     uint64(now.Add(time.Hour).Unix()),
		}
		if err := c.SignCert(rand.Reader, ca.signer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.CertificateResponse{Certificate: ssh.MarshalAuthorizedKey(c)})
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

// hostKey creates a host key at name in dir with a certificate from ca, that
// is due for renewal when due is set
func hostKey(t *testing.T, ca *testRevokeCA, dir, name string, serial uint64, due bool) (string, cert.Storage) {
	t.Helper()

	keypath := filepath.Join(dir, name)
	s, err := store.NewFile(ca.signer.PublicKey(), keypath)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}

	now := time.Now()
	if due {
		ca.issueValid(t, s, ssh.HostCert, serial, now.Add(-time.Hour), now.Add(time.Minute))
	} else {
		ca.issueValid(t, s, ssh.HostCert, serial, now.Add(-time.Minute), now.Add(time.Hour))
	}

	return keypath, s
}

// reloadCommand returns a reload command that appends a line to a file each
// time it runs, and a function that counts the runs
func reloadCommand(t *testing.T) (string, func() int) {
	t.Helper()

	marker := filepath.Join(t.TempDir(), "reloads")

	return fmt.Sprintf("echo reloaded >> %q", marker), func() int {
		b, err := os.ReadFile(marker)
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		if err != nil {
			t.Fatalf("reading marker: %v", err)
		}
		return strings.Count(string(b), "reloaded")
	}
}

// executeOutput is as for execute but returns what was written to stdout,
// where the logs go
func executeOutput(t *testing.T, args ...string) (string, error) {
	t.Helper()

	f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatalf("creating output file: %v", err)
	}
	defer func() { _ = f.Close() }()

	stdout := os.Stdout
	os.Stdout = f
	err = cli.Execute(t.Context(), args)
	os.Stdout = stdout

	out, rerr := os.ReadFile(f.Name())
	if rerr != nil {
		t.Fatalf("reading output: %v", rerr)
	}

	return string(out), err
}

func TestExecute_HostRenewReloadCommand(t *testing.T) {
	t.Run("not due does not reload", func(t *testing.T) {
		ca := renewCA(t, 0)
		keypath, _ := hostKey(t, ca, t.TempDir(), "ssh_host_ed25519_key", 1, false)
		command, runs := reloadCommand(t)

		if err := execute(t, "--config", ca.config, "host", "--renew", "--delay", "0", "--key", keypath, "--reload-command", command); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if got := runs(); got != 0 {
			t.Errorf("reload command ran %d times, want 0", got)
		}
	})

	t.Run("renewal reloads once", func(t *testing.T) {
		ca := renewCA(t, 0)
		dir := t.TempDir()
		ed25519, _ := hostKey(t, ca, dir, "ssh_host_ed25519_key", 1, true)
		ecdsa, _ := hostKey(t, ca, dir, "ssh_host_ecdsa_key", 2, true)
		command, runs := reloadCommand(t)

		if err := execute(t, "--config", ca.config, "host", "--renew", "--delay", "0", "--key", ed25519, "--key", ecdsa, "--reload-command", command); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if got := runs(); got != 1 {
			t.Errorf("reload command ran %d times, want 1", got)
		}
	})

	t.Run("partial failure still reloads", func(t *testing.T) {
		ca := renewCA(t, 2)
		dir := t.TempDir()
		renewed, renewedStore := hostKey(t, ca, dir, "ssh_host_ed25519_key", 1, true)
		failed, _ := hostKey(t, ca, dir, "ssh_host_ecdsa_key", 2, true)
		command, runs := reloadCommand(t)

		if err := execute(t, "--config", ca.config, "host", "--renew", "--delay", "0", "--key", renewed, "--key", failed, "--reload-command", command); err == nil {
			t.Error("Execute() error = nil, want the failed renewal")
		}
		if got := runs(); got != 1 {
			t.Errorf("reload command ran %d times, want 1", got)
		}
		if c, err := renewedStore.Certificate(); err != nil || c.Serial == 1 {
			t.Errorf("certificate was not renewed: %v", err)
		}
	})

	t.Run("failing reload command fails", func(t *testing.T) {
		ca := renewCA(t, 0)
		keypath, s := hostKey(t, ca, t.TempDir(), "ssh_host_ed25519_key", 1, true)

		err := execute(t, "--config", ca.config, "host", "--renew", "--delay", "0", "--key", keypath, "--reload-command", "exit 3")
		if !errors.Is(err, cli.ErrReloadFailed) {
			t.Errorf("Execute() error = %v, want %v", err, cli.ErrReloadFailed)
		}
		if c, err := s.Certificate(); err != nil || c.Serial == 1 {
			t.Errorf("renewed certificate was not kept: %v", err)
		}
	})

	t.Run("without reload command logs a reminder", func(t *testing.T) {
		ca := renewCA(t, 0)
		keypath, _ := hostKey(t, ca, t.TempDir(), "ssh_host_ed25519_key", 1, true)

		out, err := executeOutput(t, "--config", ca.config, "host", "--renew", "--delay", "0", "--key", keypath)
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if !strings.Contains(out, "reload sshd") {
			t.Errorf("output %q does not remind to reload sshd", out)
		}
	})
}

func TestExecute_RevokeHostReloadCommand(t *testing.T) {
	const serial uint64 = 12345678901234567890

	t.Run("revoking the current certificate reloads", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)
		keypath, _ := hostKey(t, ca, t.TempDir(), "ssh_host_ed25519_key", serial, false)
		command, runs := reloadCommand(t)

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--host", "--key", keypath, "--reload-command", command); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if got := runs(); got != 1 {
			t.Errorf("reload command ran %d times, want 1", got)
		}
	})

	t.Run("revoking a previous certificate does not reload", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)
		keypath, _ := hostKey(t, ca, t.TempDir(), "ssh_host_ed25519_key", serial, false)
		command, runs := reloadCommand(t)

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--host", "--key", keypath, "--serial", "1", "--reload-command", command); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if got := runs(); got != 0 {
			t.Errorf("reload command ran %d times, want 0", got)
		}
	})

	t.Run("requires --host", func(t *testing.T) {
		ca := revokeCA(t, http.StatusOK)
		command, runs := reloadCommand(t)

		if err := execute(t, "--config", ca.config, "revoke", "--yes", "--reload-command", command); err == nil {
			t.Error("Execute() error = nil, want error")
		}
		if got := runs(); got != 0 {
			t.Errorf("reload command ran %d times, want 0", got)
		}
		if got := ca.requested(); len(got) != 0 {
			t.Errorf("requested %q, want no requests", got)
		}
	})
}
