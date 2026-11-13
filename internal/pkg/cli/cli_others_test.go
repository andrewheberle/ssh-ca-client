//go:build !windows

package cli_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runMutuallyExclusive(t, append([]string{"--config", validConfig}, tt.args...))
		})
	}
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

func TestExecute_FlagRequires(t *testing.T) {
	runFlagRequires(t, []flagTest{
		{"login add and force", []string{"login", "--add", "--force"}},
		{"login add and life", []string{"login", "--add", "--life", "1h"}},
		{"login add and skip-agent", []string{"login", "--add", "--skip-agent"}},
	})
}

// runFlagRequires checks each of tests is rejected with [cli.ErrInvalidFlags]
// before anything is run. A config that loads is used, so the error cannot
// come from loading it instead.
func runFlagRequires(t *testing.T, tests []flagTest) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"--config", validConfig}, tt.args...)
			if err := execute(t, args...); !errors.Is(err, cli.ErrInvalidFlags) {
				t.Errorf("Execute(%q) error = %v, want %v", args, err, cli.ErrInvalidFlags)
			}
		})
	}
}
