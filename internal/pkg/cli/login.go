package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth/tokenstore"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/keyringstore"
	"github.com/bep/simplecobra"
)

type loginCommand struct {
	skipAgent bool
	lifetime  time.Duration
	add       bool
	force     bool

	cert  *cert.UserCertificate
	store *keyringstore.Storage

	logger *slog.Logger

	*simplecommand.Command
}

func (c *loginCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.skipAgent, "skip-agent", false, "Skip adding SSH key and certificate to ssh-agent")
	cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	cmd.Flags().BoolVar(&c.add, "add", false, "Add existing certificate to SSH agent")
	cmd.Flags().BoolVar(&c.force, "force", false, "Force renewal even if current certificate has more than 50% validity left")

	return nil
}

func (c *loginCommand) PreRun(this, runner *simplecobra.Commandeer) error {
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

	ts, err := tokenstore.NewKeyringStore()
	if err != nil {
		return err
	}

	// the command context is cancelled on CTRL-C
	ctx := this.CobraCommand.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	auth, err := auth.NewOidcHandler(ctx, auth.OidcConfig{
		ClientID:    config.ClientID,
		Issuer:      config.Issuer,
		RedirectURL: config.RedirectURL,
		Scopes:      config.Scopes,
	}, auth.WithTokenStore(ts), auth.WithLogger(c.logger))
	if err != nil {
		return err
	}

	cert, err := cert.NewUserCertificate(config.CertificateAuthorityURL, c.store)
	if err != nil {
		return err
	}
	cert.AuthHandler = auth
	cert.Lifetime = c.lifetime
	c.cert = cert

	return nil
}

func (c *loginCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// just add if requested
	if c.add {
		c.logger.Info("attempting to add current certificate to ssh-agent")
		return c.store.AddToAgent()
	}

	// check life is not more than 50% done
	if c.store.HasCertificate() {
		existing, err := c.store.Certificate()
		if err != nil {
			c.logger.Error("error getting certificate", "error", err)

			return err
		}

		// check expiry
		if !cert.RenewalDue(existing, 0.5, time.Now()) {
			if !c.force {
				c.logger.Info("skipping renewal as current certificate has more than 50% of its lifetime left")

				return nil

			} else {
				c.logger.Info("renewal forced despite current certificate having more than 50% of its lifetime left")
			}
		}
	}

	// this blocks until any interactive login completes, times out or is
	// cancelled (CTRL-C)
	reqErr := c.cert.RequestContext(ctx)

	if reqErr != nil {
		if ctx.Err() != nil {
			c.logger.Info("login cancelled")
		}

		return reqErr
	}

	c.logger.Info("obtained new certificate")

	if !c.skipAgent {
		c.logger.Info("attempting to add certificate to ssh-agent")
		if err := c.store.AddToAgent(); err != nil {
			return fmt.Errorf("could not add certificate to ssh-agent: %w", err)
		}
	}

	return nil
}
