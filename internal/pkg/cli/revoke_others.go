//go:build !snap

package cli

import (
	"github.com/bep/simplecobra"
)

func (c *revokeCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	c.initCommonFlags(cmd)
	cmd.Flags().BoolVar(&c.host, "host", false, "Revoke host certificates instead of the user certificate")
	cmd.Flags().StringSliceVar(&c.keypath, "key", defaultHostKeys, "Path to host private key(s) whose certificates are revoked with --host")

	return nil
}
