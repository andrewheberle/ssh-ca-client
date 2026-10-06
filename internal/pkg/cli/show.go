package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/keyringstore"
	"github.com/bep/simplecobra"
)

type showCommand struct {
	private     bool
	public      bool
	certificate bool
	git         bool

	store  *keyringstore.Storage
	logger *slog.Logger

	*simplecommand.Command
}

type showStatusJson struct {
	PrivateKey  string                     `json:"private_key,omitempty"`
	Certificate *showStatusCertificateJson `json:"certificate,omitempty"`
}

type showStatusCertificateJson struct {
	Status   string        `json:"status"`
	Expiry   time.Time     `json:"valid_until"`
	TimeLeft time.Duration `json:"time_left"`
}

func (c *showCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.private, "private", false, "Display private key")
	cmd.Flags().BoolVar(&c.certificate, "certificate", false, "Display certificate if one exists")
	cmd.Flags().BoolVar(&c.public, "public", false, "Display public key")
	cmd.Flags().BoolVar(&c.git, "git", false, "Output certificate in a format suitable for git signing")
	cmd.MarkFlagsMutuallyExclusive("public", "private", "certificate")
	cmd.MarkFlagsMutuallyExclusive("git", "public")
	cmd.MarkFlagsMutuallyExclusive("git", "private")

	return nil
}

func (c *showCommand) PreRun(this, runner *simplecobra.Commandeer) error {
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

	// if git was set this implies --certificate
	if c.git {
		c.certificate = true
	}

	return nil
}

func (c *showCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	if !c.store.HasPrivateKey() {
		return ErrNoPrivateKey
	}

	switch {
	case c.private:
		pemBytes, err := c.store.PrivateKeyBytes()
		if err != nil {
			return err
		}

		fmt.Printf("%s", pemBytes)
	case c.certificate:
		certBytes, err := c.store.CertificateBytes()
		if err != nil {
			return err
		}

		// add the prefix if using for git
		prefix := ""
		if c.git {
			prefix = "key::"
		}

		fmt.Printf("%s%s", prefix, certBytes)
	default:
		pemBytes, err := c.store.PublicKeyBytes()
		if err != nil {
			return err
		}

		fmt.Printf("%s\n", pemBytes)
	}

	return nil
}
