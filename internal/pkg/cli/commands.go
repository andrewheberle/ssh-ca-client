//go:build !snap

package cli

import (
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

// with no build tags all sub-commands are included
func commands() []simplecobra.Commander {
	return []simplecobra.Commander{
		&generateCommand{
			Command: simplecommand.New("generate", "Generate a SSH private key",
				simplecommand.WithLong(generateLong),
				simplecommand.WithExample(generateExample),
			),
		},
		&hostCommand{
			Command: simplecommand.New("host", "Request or renew host certificates",
				simplecommand.WithLong(hostLong),
				simplecommand.WithExample(hostExample),
			),
		},
		&loginCommand{
			Command: simplecommand.New("login", "Login via OIDC and request a certificate from CA",
				simplecommand.WithLong(loginLong),
				simplecommand.WithExample(loginExample),
			),
		},
		&showCommand{
			Command: simplecommand.New("show", "Show existing private/public key",
				simplecommand.WithLong(showLong),
				simplecommand.WithExample(showExample),
			),
		},
		&krlCommand{
			Command: simplecommand.New("krl", "Download and parse a SSH KRL",
				simplecommand.WithLong(krlLong),
				simplecommand.WithExample(krlExample),
			),
		},
		&versionCommand{
			Command: simplecommand.New("version", "Show the current version of the ssh-ca-client-cli",
				simplecommand.WithLong(versionLong),
				simplecommand.WithExample(versionExample),
			),
		},
		&revokeCommand{
			Command: simplecommand.New("revoke", "Revoke a certificate",
				simplecommand.WithLong(revokeLong),
			),
		},
	}
}
