//go:build !snap

package cli

import (
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"github.com/spf13/cobra"
)

// with no build tags all sub-commands are included
func commands() []simplecobra.Commander {
	return []simplecobra.Commander{
		&generateCommand{
			Command: simplecommand.New("generate", "Generate a SSH private key",
				simplecommand.WithLong(generateLong),
				simplecommand.WithExample(generateExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
		&hostCommand{
			Command: simplecommand.New("host", "Request or renew host certificates",
				simplecommand.WithLong(hostLong),
				simplecommand.WithExample(hostExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
		&loginCommand{
			Command: simplecommand.New("login", "Login via OIDC and request a certificate from CA",
				simplecommand.WithLong(loginLong),
				simplecommand.WithExample(loginExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
		&showCommand{
			Command: simplecommand.New("show", "Show existing private/public key",
				simplecommand.WithLong(showLong),
				simplecommand.WithExample(showExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
		&krlCommand{
			Command: simplecommand.New("krl", "Download and parse a SSH KRL",
				simplecommand.WithLong(krlLong),
				simplecommand.WithExample(krlExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
		&versionCommand{
			Command: simplecommand.New("version", "Show the current version of the ssh-ca-client-cli",
				simplecommand.WithLong(versionLong),
				simplecommand.WithExample(versionExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
		&revokeCommand{
			Command: simplecommand.New("revoke", "Revoke a certificate",
				simplecommand.WithLong(revokeLong),
				simplecommand.WithExample(revokeExample),
				simplecommand.WithArgs(cobra.NoArgs),
			),
		},
	}
}
