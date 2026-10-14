package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
	"github.com/bep/simplecobra"
)

type krlCommand struct {
	host bool
	out  string

	// force is deprecated and has no effect, as the KRL is always verified
	force bool

	config          *config.ClientConfig
	logger          *slog.Logger
	certificatetype krl.CertificateType

	*simplecommand.Command
}

func (c *krlCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.host, "host", false, "Retrieve host KRL instead of user KRL")
	cmd.Flags().StringVarP(&c.out, "out", "f", "", "Output file for KRL")
	cmd.Flags().BoolVar(&c.force, "force", false, "Force writing to output even if signature was not verified")
	if err := cmd.Flags().MarkDeprecated("force", "the krl is always verified as trusted_ca is required"); err != nil {
		return err
	}

	return nil
}

func (c *krlCommand) PreRun(this, runner *simplecobra.Commandeer) error {
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
	c.config = config

	if c.host {
		c.certificatetype = krl.Host
	} else {
		c.certificatetype = krl.User
	}

	return nil
}

func (c *krlCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// trusted_ca is required by the config, so the KRL is always verified
	verified, err := krl.Fetch(ctx, c.config.CertificateAuthorityURL, c.certificatetype, c.config.CertificateAuthorityPublicKey())
	if err != nil {
		c.logger.Error("could not fetch verified krl", "error", err)
		return err
	}

	c.logger.Info("verified krl",
		"type", c.certificatetype,
		"version", verified.Version(),
		"generated", verified.Generated(),
		"sections", verified.Sections(),
	)

	if c.out == "" {
		return nil
	}

	outcome, err := verified.Install(c.out)
	if err != nil {
		if errors.Is(err, krl.ErrOlderKRL) {
			c.logger.Error("not replacing existing krl with an older krl", "out", c.out, "error", err)
		}
		return err
	}

	switch outcome {
	case krl.Unchanged:
		c.logger.Info("existing krl is unchanged so it was not rewritten", "out", c.out)
	case krl.ReplacedUnparseable:
		c.logger.Warn("existing krl could not be parsed so it was replaced", "out", c.out)
	default:
		c.logger.Info("wrote krl to output file", "out", c.out)
	}

	return nil
}
