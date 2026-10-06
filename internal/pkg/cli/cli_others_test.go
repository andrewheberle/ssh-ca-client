//go:build !windows

package cli_test

import (
	"strings"
	"testing"
)

// validConfig is a configuration file that loads successfully
const validConfig = "testdata/config.yml"

func TestExecute_MutuallyExclusiveFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"show private and public", []string{"show", "--private", "--public"}},
		{"show private and certificate", []string{"show", "--private", "--certificate"}},
		{"show public and certificate", []string{"show", "--public", "--certificate"}},
		{"host renew and principals", []string{"host", "--renew", "--principals", "a"}},
		{"host force and renewat", []string{"host", "--force", "--renewat", "0.5"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runMutuallyExclusive(t, append([]string{"--config", validConfig}, tt.args...))
		})
	}
}

func TestExecute_HostFlags(t *testing.T) {
	runFlagTests(t, []flagTest{
		{"host", []string{"host", "--delay", "1s", "--force", "--key", "a", "--key", "b,c", "--life", "1h", "--principals", "a,b"}},
		{"host renew", []string{"host", "--renew", "--renewat", "0.75"}},
	})

	t.Run("removed host --addr", func(t *testing.T) {
		if err := execute(t, "host", "--addr", "localhost:3000", "--help"); err == nil {
			t.Errorf("Execute() error = nil, want error")
		}
	})

	t.Run("host with missing config", func(t *testing.T) {
		if err := execute(t, "--config", missingConfig, "host"); err == nil {
			t.Errorf("Execute() error = nil, want error")
		}
	})
}

// runMutuallyExclusive checks args are rejected as mutually exclusive. Flag
// groups are only checked after the command's PreRun, so args must include a
// config that loads. Nothing is run, so there are no side effects.
func runMutuallyExclusive(t *testing.T, args []string) {
	t.Helper()

	err := execute(t, args...)
	if err == nil || !strings.Contains(err.Error(), "none of the others can be") {
		t.Errorf("Execute(%q) error = %v, want mutually exclusive flags error", args, err)
	}
}
