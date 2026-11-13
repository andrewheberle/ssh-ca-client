package cli_test

import (
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
	"github.com/spf13/cobra"
)

// TestCommands_RejectArgs checks that no command accepts positional
// arguments, so a value given without its flag name is an error rather than
// being ignored. The validators are checked directly, so the test cannot pass
// because a command failed for some other reason.
func TestCommands_RejectArgs(t *testing.T) {
	root, err := cli.Command()
	if err != nil {
		t.Fatalf("Command() error = %v", err)
	}

	var check func(cmd *cobra.Command)
	check = func(cmd *cobra.Command) {
		t.Run(cmd.CommandPath(), func(t *testing.T) {
			if cmd.Args == nil {
				t.Fatalf("Args is nil, so positional arguments are not validated")
			}
			if err := cmd.Args(cmd, []string{"999"}); err == nil {
				t.Errorf("Args(%q) error = nil, want error", []string{"999"})
			}
			if err := cmd.Args(cmd, nil); err != nil {
				t.Errorf("Args(nil) error = %v, want nil", err)
			}
		})

		for _, sub := range cmd.Commands() {
			check(sub)
		}
	}
	check(root)
}

// TestRenamedFlags checks that each flag renamed before 1.0 is available
// under its new name, and that the old name still works but is deprecated,
// which also hides it from help and the generated docs.
func TestRenamedFlags(t *testing.T) {
	root, err := cli.Command()
	if err != nil {
		t.Fatalf("Command() error = %v", err)
	}

	tests := []struct {
		command  string
		old, new string
	}{
		{"generate", "dryrun", "dry-run"},
		{"host", "renewat", "renew-at"},
	}
	for _, tt := range tests {
		t.Run(tt.command+" "+tt.old, func(t *testing.T) {
			cmd, _, err := root.Find([]string{tt.command})
			if err != nil || cmd == root {
				t.Skipf("%s is not in this build", tt.command)
			}

			if f := cmd.Flags().Lookup(tt.new); f == nil || f.Hidden {
				t.Errorf("--%s = %v, want a visible flag", tt.new, f)
			}
			f := cmd.Flags().Lookup(tt.old)
			if f == nil {
				t.Fatalf("--%s was removed, want it kept as a deprecated alias", tt.old)
			}
			if f.Deprecated == "" || !f.Hidden {
				t.Errorf("--%s Deprecated = %q, Hidden = %v, want deprecated and hidden", tt.old, f.Deprecated, f.Hidden)
			}
		})
	}

	t.Run("krl -f", func(t *testing.T) {
		cmd, _, err := root.Find([]string{"krl"})
		if err != nil || cmd == root {
			t.Skip("krl is not in this build")
		}

		if f := cmd.Flags().ShorthandLookup("o"); f == nil || f.Name != "out" {
			t.Errorf("-o = %v, want the short form of --out", f)
		}
		f := cmd.Flags().ShorthandLookup("f")
		if f == nil {
			t.Fatalf("-f was removed, want it kept as a deprecated alias")
		}
		if f.ShorthandDeprecated == "" || !f.Hidden {
			t.Errorf("-f ShorthandDeprecated = %q, Hidden = %v, want deprecated and hidden", f.ShorthandDeprecated, f.Hidden)
		}
	})
}
