//go:build !snap && !windows

package cli_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/keyringstore"
	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
)

// userStore returns an empty user key store in a mocked keyring that trusts
// the key of ca, which is the store the CLI uses with ca.config
func userStore(t *testing.T, ca *testRevokeCA) *keyringstore.Storage {
	t.Helper()

	keyring.MockInit()
	store, err := keyringstore.New(ca.signer.PublicKey())
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}

	return store
}

// publicKey returns the stored public key, or nil if there is no private key
func publicKey(t *testing.T, store *keyringstore.Storage) []byte {
	t.Helper()

	if !store.HasPrivateKey() {
		return nil
	}

	pub, err := store.PublicKey()
	if err != nil {
		t.Fatalf("getting public key: %v", err)
	}

	return pub.Marshal()
}

func TestExecute_Generate(t *testing.T) {
	tests := []struct {
		name        string
		existing    bool
		args        []string
		wantErr     bool
		wantKey     bool
		wantReplace bool
	}{
		{name: "new key", args: nil, wantKey: true},
		{name: "new key dry run", args: []string{"--dryrun"}},
		{name: "existing key is kept", existing: true, wantErr: true, wantKey: true},
		{name: "existing key replaced with force", existing: true, args: []string{"--force"}, wantKey: true, wantReplace: true},
		{name: "existing key dry run", existing: true, args: []string{"--dryrun"}, wantKey: true},
		{name: "existing key dry run with force", existing: true, args: []string{"--dryrun", "--force"}, wantKey: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := revokeCA(t, 0)
			store := userStore(t, ca)
			if tt.existing {
				if err := store.GeneratePrivateKey(); err != nil {
					t.Fatalf("generating key: %v", err)
				}
			}
			before := publicKey(t, store)

			err := execute(t, append([]string{"--config", ca.config, "generate"}, tt.args...)...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}

			after := publicKey(t, store)
			if (after != nil) != tt.wantKey {
				t.Fatalf("private key stored = %v, want %v", after != nil, tt.wantKey)
			}
			if tt.existing {
				if replaced := !bytes.Equal(before, after); replaced != tt.wantReplace {
					t.Errorf("private key replaced = %v, want %v", replaced, tt.wantReplace)
				}
			}
		})
	}
}

// TestExecute_Login checks a new certificate is only requested once half the
// lifetime of the current certificate has passed, unless forced. The issuer in
// the config cannot be reached, so any login attempt fails.
func TestExecute_Login(t *testing.T) {
	// keep any running agent out of the tests
	t.Setenv("SSH_AUTH_SOCK", "")

	const serial = 1234

	tests := []struct {
		name string
		// validity of the current certificate as the time already passed and
		// the time left, with no certificate if both are zero
		passed, left time.Duration
		force        bool
		wantLogin    bool
	}{
		{name: "no certificate", wantLogin: true},
		{name: "most of lifetime left", passed: time.Hour, left: 23 * time.Hour},
		{name: "most of lifetime left forced", passed: time.Hour, left: 23 * time.Hour, force: true, wantLogin: true},
		{name: "half of lifetime passed", passed: 12 * time.Hour, left: 12 * time.Hour, wantLogin: true},
		{name: "most of lifetime passed", passed: 20 * time.Hour, left: 4 * time.Hour, wantLogin: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := revokeCA(t, 0)
			store := userStore(t, ca)
			if tt.passed == 0 && tt.left == 0 {
				if err := store.GeneratePrivateKey(); err != nil {
					t.Fatalf("generating key: %v", err)
				}
			} else {
				now := time.Now()
				ca.issueValid(t, store, ssh.UserCert, serial, now.Add(-tt.passed), now.Add(tt.left))
			}

			args := []string{"--config", ca.config, "login", "--skip-agent"}
			if tt.force {
				args = append(args, "--force")
			}

			err := execute(t, args...)
			if login := err != nil; login != tt.wantLogin {
				t.Errorf("login attempted = %v (error %v), want %v", login, err, tt.wantLogin)
			}
			if got := ca.requested(); len(got) != 0 {
				t.Errorf("requests made to the CA: %q", got)
			}

			if tt.wantLogin {
				return
			}
			c, err := store.Certificate()
			if err != nil {
				t.Fatalf("getting certificate: %v", err)
			}
			if c.Serial != serial {
				t.Errorf("certificate serial = %d, want %d", c.Serial, serial)
			}
		})
	}
}
