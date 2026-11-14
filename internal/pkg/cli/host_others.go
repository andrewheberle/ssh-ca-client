//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/store"
	"github.com/bep/simplecobra"
	"github.com/spf13/pflag"
)

const (
	// defaultHostDelay is the default delay between requests for multiple keys
	defaultHostDelay = time.Millisecond * 250

	// defaultHostRenewAt is the default fraction of a certificates lifetime
	// after which it is renewed
	defaultHostRenewAt = 0.5
)

type hostCommand struct {
	keypath    []string
	renew      bool
	delay      time.Duration
	lifetime   time.Duration
	force      bool
	principals []string
	renewat    float64
	reloadCmd  string

	// skipUncertified is set when renewing the default keys, as --key was not
	// given, so a key that was never certified is skipped rather than an error
	skipUncertified bool

	certs []hostCert

	logger *slog.Logger

	*simplecommand.Command
}

// hostCert is a host certificate and the path of its private key
type hostCert struct {
	keypath string
	cert    cert.Renewable
}

func (c *hostCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	// add hostname to list by default
	principals := make([]string, 0)
	hostname, err := os.Hostname()
	if err == nil {
		principals = append(principals, strings.ToLower(hostname))
	}

	cmd := cd.CobraCommand
	cmd.Flags().DurationVar(&c.lifetime, "life", cert.DefaultHostCertificateLifetime, "Lifetime of SSH certificate")
	cmd.Flags().DurationVar(&c.delay, "delay", defaultHostDelay, "Delay between requests/renewals (randomised between 50% and 150%, 0 disables)")
	cmd.Flags().StringSliceVar(&c.keypath, "key", defaultHostKeys, "Path to private key(s)")
	cmd.Flags().StringSliceVar(&c.principals, "principals", principals, "Principals to add to the host certificate request")
	cmd.Flags().BoolVar(&c.renew, "renew", false, "Renew existing certificate")
	cmd.MarkFlagsMutuallyExclusive("renew", "principals")
	cmd.Flags().BoolVar(&c.force, "force", false, fmt.Sprintf("Force renewal even if current certificate has more than %0.1f%% validity left", defaultHostRenewAt*100.0))
	cmd.Flags().Float64Var(&c.renewat, "renew-at", defaultHostRenewAt, "Renew once this fraction (0 to 1) of the certificate lifetime has passed")
	cmd.Flags().Float64Var(&c.renewat, "renewat", defaultHostRenewAt, "Renew once this fraction (0 to 1) of the certificate lifetime has passed")
	if err := deprecateRenamed(cmd.Flags(), "renewat", "renew-at"); err != nil {
		return err
	}
	cmd.MarkFlagsMutuallyExclusive("force", "renew-at")
	cmd.MarkFlagsMutuallyExclusive("force", "renewat")
	cmd.MarkFlagsMutuallyExclusive("renew-at", "renewat")
	cmd.Flags().StringVar(&c.reloadCmd, "reload-command", "", reloadCommandUsage)

	return nil
}

func (c *hostCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// set up logger
	logger, err := logger(this)
	if err != nil {
		return fmt.Errorf("could not set up logger: %w", err)
	}
	c.logger = logger

	if c.renewat < 0 || c.renewat > 1 {
		return fmt.Errorf("--renew-at must be between 0 and 1")
	}

	// these only apply to a renewal, so would otherwise be ignored
	if !c.renew {
		for _, name := range []string{"force", "renew-at", "renewat"} {
			if this.CobraCommand.Flags().Changed(name) {
				return fmt.Errorf("%w: --%s requires --renew", ErrInvalidFlags, name)
			}
		}
	}

	c.skipUncertified = renewsDefaultKeys(c.renew, this.CobraCommand.Flags())

	if os.Geteuid() != 0 {
		c.logger.Warn("not running as root", "uid", os.Geteuid())
	}

	c.logger.Debug("attempting load config", "command", this.CobraCommand.Name())

	config, err := loadconfig(this)
	if err != nil {
		return err
	}

	auth, err := auth.NewOidcHandler(auth.OidcConfig{
		ClientID:    config.ClientID,
		Issuer:      config.Issuer,
		RedirectURL: config.RedirectURL,
		Scopes:      config.Scopes,
	}, auth.WithLogger(c.logger))
	if err != nil {
		return err
	}

	certs := make([]hostCert, 0)
	for _, k := range c.keypath {
		store, err := store.NewFile(config.CertificateAuthorityPublicKey(), k)
		if err != nil {
			c.logger.Error("problem setting up store", "error", err)
			continue
		}

		cert, err := cert.NewHostCertificate(config.CertificateAuthorityURL, store)
		if err != nil {
			return err
		}
		cert.AuthHandler = auth
		cert.Lifetime = c.lifetime
		cert.Principals = c.principals

		certs = append(certs, hostCert{keypath: k, cert: cert})
	}
	if len(certs) == 0 {
		return fmt.Errorf("no valid stores found")
	}
	c.certs = certs

	return nil
}

func (c *hostCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	errs := make([]error, 0)

	stores := make(map[string]cert.Storage, len(c.certs))
	for _, hc := range c.certs {
		stores[hc.keypath] = hc.cert.Store()
	}
	reload := newHostReload(c.reloadCmd, stores)

	// work out which certificates need a request to the CA
	todo := c.certs
	if c.renew {
		todo = make([]hostCert, 0, len(c.certs))
		uncertified := 0
		for _, hc := range c.certs {
			due, err := c.renewalDue(c.logger.With("key", hc.keypath), hc.cert)
			if errors.Is(err, errUncertified) {
				uncertified++
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", hc.keypath, err))
				continue
			}
			if due {
				todo = append(todo, hc)
			}
		}

		// with no certificate to renew, the host was never certified
		if uncertified > 0 && uncertified == len(c.certs) {
			errs = append(errs, fmt.Errorf("%w: none of the host keys has a certificate, so request one first", cert.ErrCertificateNotFound))
		}
	}

	for i, hc := range todo {
		logger := c.logger.With("key", hc.keypath)

		// pause between requests so they are not all sent at once
		if i > 0 {
			if err := c.pause(ctx, logger); err != nil {
				errs = append(errs, err)
				break
			}
		}

		if c.renew {
			if err := hc.cert.RenewContext(ctx); err != nil {
				logger.Error("could not renew certificate", "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", hc.keypath, err))
			} else {
				logger.Info("renewed certificate")
			}
		} else {
			// the auth handler runs the interactive login if required, which
			// is only needed once as the tokens are reused for each key
			if err := hc.cert.RequestContext(ctx); err != nil {
				logger.Error("could not request certificate", "error", err)
				errs = append(errs, fmt.Errorf("%s: %w", hc.keypath, err))
			} else {
				logger.Info("obtained new certificate")
			}
		}

		// stop processing further keys on CTRL-C
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
	}

	// sshd is reloaded for any certificate that was written, even if
	// another key failed or the run was interrupted
	if err := reload.run(ctx, c.logger); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// renewsDefaultKeys reports whether this is a renewal of the default host
// keys, as --key was not given. A host may only have certificates for some of
// them, so any that were never certified are skipped. A key given with --key
// must have a certificate to renew.
func renewsDefaultKeys(renew bool, flags *pflag.FlagSet) bool {
	return renew && !flags.Changed("key")
}

// errUncertified is returned by renewalDue for a key that has no certificate
// when c.skipUncertified is set
var errUncertified = errors.New("key has no certificate")

// renewalDue reports whether the certificate should be renewed, which is when
// c.renewat of its lifetime has passed or c.force is set. It returns
// errUncertified for a key that has no certificate when c.skipUncertified is
// set.
func (c *hostCommand) renewalDue(logger *slog.Logger, hc cert.Renewable) (bool, error) {
	existing, err := hc.Store().Certificate()
	if c.skipUncertified && errors.Is(err, store.ErrNotFound) {
		logger.Info("skipping renewal as the key has no certificate")
		return false, errUncertified
	}
	if err != nil {
		logger.Error("could not get existing certificate", "error", err)
		return false, err
	}

	if cert.RenewalDue(existing, c.renewat, time.Now()) {
		return true, nil
	}

	if c.force {
		logger.Info("renewal forced although certificate is not due for renewal")
		return true, nil
	}

	logger.Info("skipping renewal as certificate is not due for renewal",
		"renewat", c.renewat,
		"expires", time.Unix(int64(existing.ValidBefore), 0),
	)

	return false, nil
}

// pause waits for a random duration between 50% and 150% of c.delay, or until
// ctx is done
func (c *hostCommand) pause(ctx context.Context, logger *slog.Logger) error {
	if c.delay <= 0 {
		return nil
	}

	d := jitter(c.delay)
	logger.Debug("pausing before next request", "delay", d)

	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// jitter returns a random duration between 50% and 150% of d
func jitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d+1)
}
