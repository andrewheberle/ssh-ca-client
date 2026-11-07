//go:build e2e && !windows

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
	"golang.org/x/crypto/ssh"
)

// TestHostCertificate_RenewReloadCommand checks "host --renew" runs the
// reload command once it has renewed a certificate from the CA, so sshd can be
// reloaded to present it
func TestHostCertificate_RenewReloadCommand(t *testing.T) {
	t.Parallel()

	ca := newCA(t)
	dir := t.TempDir()

	keypath := filepath.Join(dir, "ssh_host_ed25519_key")
	s, err := store.NewFile(ca.PublicKey, keypath)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	if err := s.GeneratePrivateKey(); err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	h := ca.hostCertificate(t, s, ca.IDP.tokens(t, "host-admin@example.com"), "host1", "host1.example.com")
	if err := h.Request(); err != nil {
		t.Fatalf("requesting host certificate: %v", err)
	}
	original := certificate(t, s)
	waitUntilValid(original)

	config := filepath.Join(dir, "config.yml")
	content := fmt.Sprintf(`issuer: http://127.0.0.1:1/
client_id: test-client
scopes: ["openid"]
redirect_url: http://127.0.0.1:1/auth/callback
ca_url: %s/
trusted_ca: %s`, strings.TrimSuffix(ca.URL, "/"), ssh.MarshalAuthorizedKey(ca.PublicKey))
	if err := os.WriteFile(config, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	marker := filepath.Join(dir, "reloaded")
	err = cli.Execute(t.Context(), []string{
		"--config", config,
		"host", "--renew", "--force", "--delay", "0",
		"--key", keypath,
		"--reload-command", fmt.Sprintf("echo reloaded >> %q", marker),
	})
	if err != nil {
		t.Fatalf("host --renew: %v", err)
	}

	if renewed := certificate(t, s); renewed.Serial == original.Serial {
		t.Errorf("serial was not changed: %d", renewed.Serial)
	}

	b, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("reload command did not run: %v", err)
	}
	if got := strings.Count(string(b), "reloaded"); got != 1 {
		t.Errorf("reload command ran %d times, want 1", got)
	}
}
