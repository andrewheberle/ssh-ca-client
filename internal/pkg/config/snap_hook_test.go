//go:build !windows

package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// snapDir is the directory of the snap's hooks and scripts in the repository
var snapDir = filepath.Join("..", "..", "..", "snap")

// snapctlStub is a snapctl that prints the snap option named by "get <name>"
// from the file of that name in $SNAPCTL_OPTIONS, or nothing if it is unset
const snapctlStub = `#!/bin/sh
[ "$1" = get ] || exit 1
if [ -f "$SNAPCTL_OPTIONS/$2" ]; then
    cat "$SNAPCTL_OPTIONS/$2"
fi
`

// runConfigureHook runs the snap's configure hook with the snap options in
// options, and returns the directory that holds config.yml, which existing is
// written to first unless it is empty
func runConfigureHook(t *testing.T, options map[string]string, existing string) (string, error) {
	t.Helper()

	tmp := t.TempDir()
	snap := filepath.Join(tmp, "snap")
	data := filepath.Join(tmp, "data")
	optionsDir := filepath.Join(tmp, "options")
	stubDir := filepath.Join(tmp, "stub")
	for _, d := range []string{filepath.Join(snap, "bin"), filepath.Join(data, "etc"), optionsDir, stubDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// the hook sources the management script from $SNAP/bin, as packaged
	management, err := os.ReadFile(filepath.Join(snapDir, "scripts", "management"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap, "bin", "management"), management, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stubDir, "snapctl"), []byte(snapctlStub), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range options {
		if err := os.WriteFile(filepath.Join(optionsDir, name), []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if existing != "" {
		if err := os.WriteFile(filepath.Join(data, "etc", "config.yml"), []byte(existing), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command("sh", filepath.Join(snapDir, "hooks", "configure"))
	cmd.Env = append(os.Environ(),
		"SNAP="+snap,
		"SNAP_DATA="+data,
		"SNAPCTL_OPTIONS="+optionsDir,
		"PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("configure hook output: %s", out)
	}

	return filepath.Join(data, "etc"), err
}

// TestSnapConfigureHook runs the snap's configure hook and loads the
// configuration it writes as the client does.
func TestSnapConfigureHook(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not found")
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	ca, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("creating public key: %v", err)
	}
	trusted := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(ca)))

	// required returns the required snap options, with extra added
	required := func(extra map[string]string) map[string]string {
		options := map[string]string{
			"issuer":     "https://idp.example.com/",
			"client-id":  "client",
			"ca-url":     "https://ca.example.com/",
			"trusted-ca": trusted,
		}
		for name, value := range extra {
			options[name] = value
		}
		return options
	}

	// want returns the config loaded from the required options, with mutate
	// applied
	want := func(mutate func(c *ClientConfig)) *ClientConfig {
		c := clientConfigDefaults()
		c.Issuer = "https://idp.example.com/"
		c.ClientID = "client"
		c.CertificateAuthorityURL = "https://ca.example.com/"
		c.TrustedCertificateAuthority = trusted
		if mutate != nil {
			mutate(&c)
		}
		return &c
	}

	handWritten := "# written by hand\nissuer: https://other.example.com/\n"

	tests := []struct {
		name     string
		options  map[string]string
		existing string // config.yml before the hook runs
		want     *ClientConfig
		wantFile string // config.yml after the hook runs, if want is nil
		wantErr  bool
	}{
		{
			// a fresh install with nothing set writes nothing
			name: "nothing set",
		},
		{
			name:    "required options partly set",
			options: map[string]string{"issuer": "https://idp.example.com/", "client-id": "client"},
		},
		{
			// trusted-ca is required too
			name: "trusted-ca unset",
			options: map[string]string{
				"issuer":    "https://idp.example.com/",
				"client-id": "client",
				"ca-url":    "https://ca.example.com/",
			},
		},
		{
			// a refresh must not replace a configuration written by hand
			name:     "hand-written config kept",
			existing: handWritten,
			wantFile: handWritten,
		},
		{
			name:     "hand-written config kept while options are partly set",
			options:  map[string]string{"issuer": "https://idp.example.com/"},
			existing: handWritten,
			wantFile: handWritten,
		},
		{
			// optional options left unset use the client's defaults
			name:    "required options set",
			options: required(nil),
			want:    want(nil),
		},
		{
			name:     "options replace a hand-written config",
			options:  required(nil),
			existing: handWritten,
			want:     want(nil),
		},
		{
			name: "all options set",
			options: required(map[string]string{
				"scopes":       "openid,offline_access",
				"redirect-url": "http://127.0.0.1:8250/callback",
			}),
			want: want(func(c *ClientConfig) {
				c.Scopes = []string{"openid", "offline_access"}
				c.RedirectURL = "http://127.0.0.1:8250/callback"
			}),
		},
		{
			name:    "scopes with spaces and empty entries",
			options: required(map[string]string{"scopes": " openid, email ,,profile, "}),
			want:    want(func(c *ClientConfig) { c.Scopes = []string{"openid", "email", "profile"} }),
		},
		{
			// no scopes left, so the default applies
			name:    "scopes only commas",
			options: required(map[string]string{"scopes": " , ,"}),
			want:    want(nil),
		},
		{
			// YAML would read these as a number, a comment, a mapping or an
			// escape if they weren't quoted
			name: "values YAML would misread",
			options: required(map[string]string{
				"client-id": `12345 # a: "b" \n`,
				"scopes":    `openid,"quoted",back\slash`,
			}),
			want: want(func(c *ClientConfig) {
				c.ClientID = `12345 # a: "b" \n`
				c.Scopes = []string{"openid", `"quoted"`, `back\slash`}
			}),
		},
		{
			name:     "newline rejected",
			options:  required(map[string]string{"client-id": "client\nissuer: https://evil.example.com/"}),
			existing: handWritten,
			wantFile: handWritten,
			wantErr:  true,
		},
		{
			name:     "control character rejected",
			options:  required(map[string]string{"scopes": "openid,\temail"}),
			existing: handWritten,
			wantFile: handWritten,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := runConfigureHook(t, tt.options, tt.existing)
			if (err != nil) != tt.wantErr {
				t.Fatalf("configure hook error = %v, wantErr %v", err, tt.wantErr)
			}

			// no temporary file is left behind
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.Name() != "config.yml" {
					t.Errorf("unexpected file %s left in %s", e.Name(), dir)
				}
			}

			path := filepath.Join(dir, "config.yml")
			if tt.want == nil {
				got, err := os.ReadFile(path)
				switch {
				case tt.wantFile == "" && err == nil:
					t.Errorf("config.yml written:\n%s", got)
				case tt.wantFile != "" && string(got) != tt.wantFile:
					t.Errorf("config.yml = %q, want it left as %q", got, tt.wantFile)
				}
				return
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("config.yml not written: %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0o644 {
				t.Errorf("config.yml mode = %v, want 0644", perm)
			}

			got, err := LoadClientConfig(path)
			if err != nil {
				content, _ := os.ReadFile(path)
				t.Fatalf("LoadClientConfig() error = %v, config.yml:\n%s", err, content)
			}
			got.ca = nil
			if !reflect.DeepEqual(got, tt.want) {
				content, _ := os.ReadFile(path)
				t.Errorf("LoadClientConfig() = %+v, want %+v, config.yml:\n%s", got, tt.want, strings.TrimSpace(string(content)))
			}
		})
	}
}
