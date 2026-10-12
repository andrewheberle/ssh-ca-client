//go:build snap

package cli

import (
	"github.com/bep/simplecobra"
)

func (c *revokeCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	c.initCommonFlags(cd.CobraCommand)

	return nil
}
