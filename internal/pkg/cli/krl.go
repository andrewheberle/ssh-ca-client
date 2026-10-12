package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"time"

	"codeberg.org/sdassow/atomic"
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
	// get KRL payload from CA
	res, err := krl.Get(ctx, c.config.CertificateAuthorityURL, c.certificatetype)
	if err != nil {
		return fmt.Errorf("could not retrieve krl: %w", err)
	}

	// trusted_ca is required by the config, so the KRL is always verified
	if err := res.VerifyStrict(c.config.CertificateAuthorityPublicKey()); err != nil {
		c.logger.Error("verification of krl failed", "error", err)
		return err
	}

	parsed, err := res.Parse()
	if err != nil {
		return fmt.Errorf("could not parse krl: %w", err)
	}

	c.logger.Info("verified krl",
		"type", c.certificatetype,
		"version", parsed.Version,
		"generated", time.Unix(int64(parsed.GeneratedDate), 0).UTC(),
		"sections", len(parsed.Sections),
	)

	if c.out != "" {
		unchanged, err := c.checkExisting(res)
		if err != nil {
			return err
		}

		if unchanged {
			c.logger.Info("existing krl is unchanged so it was not rewritten", "out", c.out)
			return nil
		}

		c.logger.Info("writing krl to output file", "out", c.out)
		return atomic.WriteFile(c.out, bytes.NewReader(res.Krl), atomic.FileMode(krlFileMode))
	}

	return nil
}

// krlFileMode is the mode of the KRL output file
const krlFileMode fs.FileMode = 0440

// checkExisting returns an error if the KRL in the output file is newer than
// res, and whether the output file already holds res with the expected mode,
// so does not need to be written. A missing or unparseable output file is
// replaced.
func (c *krlCommand) checkExisting(res *krl.Response) (bool, error) {
	existing, err := os.ReadFile(c.out)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("could not read existing krl: %w", err)
	}

	if bytes.Equal(existing, res.Krl) {
		info, err := os.Stat(c.out)
		if err != nil {
			return false, fmt.Errorf("could not check existing krl: %w", err)
		}

		return info.Mode().Perm() == krlFileMode, nil
	}

	if err := res.CheckNotOlder(existing); err != nil {
		if errors.Is(err, krl.ErrOlderKRL) {
			c.logger.Error("not replacing existing krl with an older krl", "out", c.out, "error", err)
			return false, err
		}

		c.logger.Warn("existing krl could not be parsed so it will be replaced", "out", c.out, "error", err)
	}

	return false, nil
}
