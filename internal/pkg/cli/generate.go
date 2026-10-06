package cli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/keyringstore"
	"github.com/bep/simplecobra"
)

type generateCommand struct {
	force  bool
	dryrun bool

	store cert.Storage

	logger *slog.Logger

	*simplecommand.Command
}

func (c *generateCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.force, "force", false, "Force replacing an existing private key")
	cmd.Flags().BoolVarP(&c.dryrun, "dryrun", "n", false, "Show what would be done")

	return nil
}

func (c *generateCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// set up logger
	logger, err := logger(this)
	if err != nil {
		return fmt.Errorf("could not set up logger: %w", err)
	}
	c.logger = logger

	c.logger.Debug("attempting load config", "command", this.CobraCommand.Name())

	// load config
	config, err := loadconfig(this)
	if err != nil {
		return err
	}

	store, err := keyringstore.New(config.CertificateAuthorityPublicKey())
	if err != nil {
		return err
	}
	c.store = store

	return nil
}

func (c *generateCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	if c.store.HasPrivateKey() && !c.force {
		if c.dryrun {
			fmt.Printf("dry run: not overwriting existing private key without force option set")

			return nil
		}

		return fmt.Errorf("not overwriting existing private key without force option set")
	}

	if c.dryrun {
		fmt.Printf("dry run: generating SSH private key")

		return nil
	}

	return c.store.GeneratePrivateKey()
}
