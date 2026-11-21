//go:build !snap && !windows

package cli_test

import (
	"crypto/rand"
	"errors"
	"os/user"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
	"golang.org/x/crypto/ssh"
)

// TestExecute_Show checks what show writes to stdout for each option, and
// that it fails without writing anything when there is nothing to show
func TestExecute_Show(t *testing.T) {
	// the expected output, built from the store once it is set up
	var (
		public      = func(t *testing.T, s *store.Store) string { return string(bytesOf(t, s.PublicKeyBytes)) + "\n" }
		private     = func(t *testing.T, s *store.Store) string { return string(bytesOf(t, s.PrivateKeyBytes)) }
		certificate = func(t *testing.T, s *store.Store) string { return string(bytesOf(t, s.CertificateBytes)) }
		git         = func(t *testing.T, s *store.Store) string { return "key::" + certificate(t, s) }
	)

	// the stored state before show is run
	const (
		empty = iota
		keyOnly
		validCert
		expiredCert
	)

	tests := []struct {
		name    string
		state   int
		args    []string
		want    func(t *testing.T, s *store.Store) string
		wantErr error
	}{
		{name: "no key", state: empty, wantErr: cli.ErrNoPrivateKey},
		{name: "no key public", state: empty, args: []string{"--public"}, wantErr: cli.ErrNoPrivateKey},
		{name: "no key private", state: empty, args: []string{"--private"}, wantErr: cli.ErrNoPrivateKey},
		{name: "no key certificate", state: empty, args: []string{"--certificate"}, wantErr: cli.ErrNoPrivateKey},
		{name: "no key git", state: empty, args: []string{"--git"}, wantErr: cli.ErrNoPrivateKey},

		{name: "public by default", state: keyOnly, want: public},
		{name: "public", state: keyOnly, args: []string{"--public"}, want: public},
		// --private is deprecated, so this also checks its warning is not
		// written to stdout along with the key
		{name: "private", state: keyOnly, args: []string{"--private"}, want: private},
		{name: "no certificate", state: keyOnly, args: []string{"--certificate"}, wantErr: cert.ErrCertificateNotFound},
		{name: "no certificate git", state: keyOnly, args: []string{"--git"}, wantErr: cert.ErrCertificateNotFound},

		{name: "public with certificate", state: validCert, want: public},
		{name: "private with certificate", state: validCert, args: []string{"--private"}, want: private},
		{name: "certificate", state: validCert, args: []string{"--certificate"}, want: certificate},
		{name: "git", state: validCert, args: []string{"--git"}, want: git},
		{name: "git with certificate", state: validCert, args: []string{"--git", "--certificate"}, want: git},

		// show reports what is stored, even once it has expired
		{name: "expired certificate", state: expiredCert, args: []string{"--certificate"}, want: certificate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := revokeCA(t, 0)
			s := userStore(t, ca)

			now := time.Now()
			switch tt.state {
			case keyOnly:
				if err := s.GeneratePrivateKey(); err != nil {
					t.Fatalf("generating key: %v", err)
				}
			case validCert:
				ca.issueValid(t, s, ssh.UserCert, 1, now.Add(-time.Hour), now.Add(time.Hour))
			case expiredCert:
				saveExpired(t, ca, s, now)
			}

			out, err := executeOutput(t, append([]string{"--config", ca.config, "show"}, tt.args...)...)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Execute() error = %v, want %v", err, tt.wantErr)
				}
				if out != "" {
					t.Errorf("output = %q, want none", out)
				}

				return
			}
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}

			if want := tt.want(t, s); out != want {
				t.Errorf("output = %q, want %q", out, want)
			}
		})
	}
}

// TestExecute_ShowPublicMatchesKey checks the public key show displays is the
// one for the stored private key and the stored certificate
func TestExecute_ShowPublicMatchesKey(t *testing.T) {
	ca := revokeCA(t, 0)
	s := userStore(t, ca)
	now := time.Now()
	ca.issueValid(t, s, ssh.UserCert, 1, now.Add(-time.Hour), now.Add(time.Hour))

	out, err := executeOutput(t, "--config", ca.config, "show")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(out))
	if err != nil {
		t.Fatalf("parsing output %q: %v", out, err)
	}

	signer, err := s.Signer()
	if err != nil {
		t.Fatalf("getting signer: %v", err)
	}
	if got, want := ssh.FingerprintSHA256(pub), ssh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Errorf("public key = %s, want the stored private key's %s", got, want)
	}

	c, err := s.Certificate()
	if err != nil {
		t.Fatalf("getting certificate: %v", err)
	}
	if got, want := ssh.FingerprintSHA256(pub), ssh.FingerprintSHA256(c.Key); got != want {
		t.Errorf("public key = %s, want the certificate's %s", got, want)
	}
}

// saveExpired generates a private key in s and stores an expired certificate
// for it signed by ca. The store refuses to save an expired certificate, so
// it is written to the keyring directly.
func saveExpired(t *testing.T, ca *testRevokeCA, s *store.Store, now time.Time) {
	t.Helper()

	if err := s.GeneratePrivateKey(); err != nil {
		t.Fatalf("generating key: %v", err)
	}
	pub, err := s.PublicKey()
	if err != nil {
		t.Fatalf("getting public key: %v", err)
	}

	c := &ssh.Certificate{
		Key:             pub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(now.Add(-2 * time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(-time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}

	u, err := user.Current()
	if err != nil {
		t.Fatalf("looking up user: %v", err)
	}
	if err := store.NewKeyringBackend(u.Username).Put(store.Cert, ssh.MarshalAuthorizedKey(c)); err != nil {
		t.Fatalf("saving certificate: %v", err)
	}
}

// bytesOf returns the result of get, failing the test on error
func bytesOf(t *testing.T, get func() ([]byte, error)) []byte {
	t.Helper()

	b, err := get()
	if err != nil {
		t.Fatalf("getting expected output: %v", err)
	}

	return b
}
