//go:build !windows && !snap

package cli_test

import "testing"

func TestExecute_HostMutuallyExclusiveFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
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
