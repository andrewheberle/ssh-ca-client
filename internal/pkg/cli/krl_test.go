//go:build !snap && !windows

package cli_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
	sshkrl "github.com/forfuncsake/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// krlCA serves KRLs signed by signer and returns a config file that trusts
// trusted
func krlCA(t *testing.T, signer ssh.Signer, trusted ssh.PublicKey, generated uint64) string {
	t.Helper()

	k := &sshkrl.KRL{
		Version:       1,
		GeneratedDate: generated,
		Sections: []sshkrl.KRLSection{
			&sshkrl.KRLCertificateSection{
				CA:       signer.PublicKey(),
				Sections: []sshkrl.KRLCertificateSubsection{&sshkrl.KRLCertificateSerialList{1}},
			},
		},
	}
	b, err := k.Marshal(rand.Reader)
	if err != nil {
		t.Fatalf("marshalling krl: %v", err)
	}

	sig, err := sshsig.Sign(bytes.NewReader(b), signer, sshsig.HashSHA512, krl.Namespace)
	if err != nil {
		t.Fatalf("signing krl: %v", err)
	}

	body, err := json.Marshal(api.KeyRevocationListResponse{Krl: b, Signature: string(sshsig.Armor(sig))})
	if err != nil {
		t.Fatalf("marshalling response: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	config := filepath.Join(t.TempDir(), "config.yml")
	content := fmt.Sprintf(`issuer: http://127.0.0.1:1/
client_id: test-client
scopes: ["openid"]
redirect_url: http://127.0.0.1:1/auth/callback
ca_url: %s/
trusted_ca: %s`, srv.URL, ssh.MarshalAuthorizedKey(trusted))
	if err := os.WriteFile(config, []byte(content), 0600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	return config
}

func newKRLSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	return signer
}

func TestExecute_KRL(t *testing.T) {
	ca := newKRLSigner(t)
	other := newKRLSigner(t)

	const generated = 1_800_000_000

	// existing returns an existing KRL generated at date
	existing := func(t *testing.T, date uint64) []byte {
		t.Helper()

		b, err := (&sshkrl.KRL{Version: 1, GeneratedDate: date}).Marshal(rand.Reader)
		if err != nil {
			t.Fatalf("marshalling existing krl: %v", err)
		}

		return b
	}

	tests := []struct {
		name      string
		signer    ssh.Signer
		existing  []byte
		args      []string
		noOut     bool
		wantErr   bool
		wantWrite bool
	}{
		{"write", ca, nil, nil, false, false, true},
		{"write host", ca, nil, []string{"--host"}, false, false, true},
		{"no output file", ca, nil, nil, true, false, false},
		{"wrong signer", other, nil, nil, false, true, false},
		{"wrong signer with force", other, nil, []string{"--force"}, false, true, false},
		{"replace older", ca, existing(t, generated-1), nil, false, false, true},
		{"replace same", ca, existing(t, generated), nil, false, false, true},
		{"keep newer", ca, existing(t, generated+1), nil, false, true, false},
		{"keep newer with force", ca, existing(t, generated+1), []string{"--force"}, false, true, false},
		{"replace unparseable", ca, []byte("not a krl"), nil, false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := krlCA(t, tt.signer, ca.PublicKey(), generated)
			out := filepath.Join(t.TempDir(), "revocation_list")

			if tt.existing != nil {
				if err := os.WriteFile(out, tt.existing, 0600); err != nil {
					t.Fatalf("writing existing krl: %v", err)
				}
			}

			args := append([]string{"--config", config, "krl"}, tt.args...)
			if !tt.noOut {
				args = append(args, "--out", out)
			}

			err := execute(t, args...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute(%q) error = %v, wantErr %v", args, err, tt.wantErr)
			}

			got, readErr := os.ReadFile(out)
			switch {
			case tt.wantWrite:
				if readErr != nil {
					t.Fatalf("reading output: %v", readErr)
				}
				parsed, err := sshkrl.ParseKRL(got)
				if err != nil {
					t.Fatalf("parsing output: %v", err)
				}
				if parsed.GeneratedDate != generated {
					t.Errorf("output generated date = %d, want %d", parsed.GeneratedDate, generated)
				}
				info, err := os.Stat(out)
				if err != nil {
					t.Fatalf("checking output: %v", err)
				}
				if mode := info.Mode().Perm(); mode != 0440 {
					t.Errorf("output mode = %o, want %o", mode, 0440)
				}
			case tt.existing != nil:
				if !bytes.Equal(got, tt.existing) {
					t.Error("existing krl was changed")
				}
			default:
				if !os.IsNotExist(readErr) {
					t.Errorf("output exists, want no output (read error = %v)", readErr)
				}
			}
		})
	}
}
