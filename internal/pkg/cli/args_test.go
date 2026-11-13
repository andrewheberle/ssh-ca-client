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
