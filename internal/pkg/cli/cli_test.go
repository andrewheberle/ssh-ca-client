package cli_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
)

// missingConfig is a config location that is invalid on all platforms: a
// missing file on Linux/BSD/Darwin and not a registry hive on Windows
const missingConfig = "testdata/missing.yml"

// execute runs the CLI with args, discarding any help or usage output
func execute(t *testing.T, args ...string) error {
	t.Helper()

	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("could not open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devnull.Close() }()

	stdout := os.Stdout
	os.Stdout = devnull
	defer func() { os.Stdout = stdout }()

	return cli.Execute(context.Background(), args)
}

// flagTest is a sub-command and flags that must be accepted
type flagTest struct {
	name string
	args []string
}

// runFlagTests checks each set of args is accepted. "--help" is appended so
// all flags are parsed but the command is not run, which avoids any access to
// configuration, keyrings, keys or the network.
func runFlagTests(t *testing.T, tests []flagTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := execute(t, append(tt.args, "--help")...); err != nil {
				t.Errorf("Execute(%q) error = %v, want flags to be accepted", tt.args, err)
			}
		})
	}
}

func TestExecute_Flags(t *testing.T) {
	runFlagTests(t, []flagTest{
		{"global flags", []string{"--config", "location", "--debug", "--json"}},
		{"global flags after sub-command", []string{"login", "--config", "location", "--debug", "--json"}},
		{"generate", []string{"generate", "--force", "--dryrun"}},
		{"generate short flags", []string{"generate", "-n"}},
		{"login", []string{"login", "--add", "--force", "--life", "1h", "--skip-agent"}},
		{"show", []string{"show", "--certificate", "--git"}},
		{"show private", []string{"show", "--private"}},
		{"show public", []string{"show", "--public"}},
		{"krl", []string{"krl", "--host", "--out", "krl.bin", "--force"}},
		{"krl short flags", []string{"krl", "-f", "krl.bin"}},
		{"revoke", []string{"revoke", "--host"}},
		{"version", []string{"version", "--json"}},
		{"host", []string{"host"}},
	})
}

func TestExecute_InvalidFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"unknown sub-command", []string{"status"}},
		{"unknown flag", []string{"login", "--unknown"}},
		{"invalid duration", []string{"login", "--life", "1d"}},
		// flags removed in previous versions must not return unnoticed
		{"removed --user", []string{"--user", "user.yml", "login"}},
		{"removed --keyfile", []string{"--keyfile", "keyfile", "login"}},
		{"removed login --addr", []string{"login", "--addr", "localhost:3000"}},
		{"removed show --status", []string{"show", "--status"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := execute(t, append(tt.args, "--help")...); err == nil {
				t.Errorf("Execute(%q) error = nil, want error", tt.args)
			}
		})
	}
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"no args", []string{}, false},
		{"version", []string{"version"}, false},
		{"version as json", []string{"version", "--json"}, false},
		{"generate with missing config", []string{"--config", missingConfig, "generate", "--dryrun"}, true},
		{"login with missing config", []string{"--config", missingConfig, "login"}, true},
		{"show with missing config", []string{"--config", missingConfig, "show"}, true},
		{"krl with missing config", []string{"--config", missingConfig, "krl"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := execute(t, tt.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute(%q) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			}
		})
	}

	t.Run("revoke not implemented", func(t *testing.T) {
		if err := execute(t, "revoke"); !errors.Is(err, cli.ErrCommandNotImplemented) {
			t.Errorf("Execute() error = %v, want %v", err, cli.ErrCommandNotImplemented)
		}
	})
}
