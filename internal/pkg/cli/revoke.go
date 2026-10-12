package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/filestore"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/keyringstore"
	"github.com/bep/simplecobra"
	"github.com/spf13/cobra"
)

var (
	ErrNothingToRevoke        = errors.New("no certificates to revoke")
	ErrRevocationNotConfirmed = errors.New("revocation was not confirmed")
)

type revokeCommand struct {
	host    bool
	keypath []string
	serials []string
	yes     bool

	certs  []revocableCert
	logger *slog.Logger

	*simplecommand.Command
}

// revocableCert is a certificate that can be revoked and a description of
// where it is stored
type revocableCert struct {
	name string
	cert cert.Revocable
}

// revokeTarget is a serial to revoke and the certificate whose key it was
// issued for
type revokeTarget struct {
	revocableCert

	serial uint64
	// keyID is set when serial is the certificate in the store
	keyID string
}

// initCommonFlags adds the flags that are available in all builds
func (c *revokeCommand) initCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&c.serials, "serial", nil, "Revoke these certificate serial numbers instead of the current certificate")
	cmd.Flags().BoolVarP(&c.yes, "yes", "y", false, "Revoke without asking for confirmation")
}

func (c *revokeCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// set up logger
	logger, err := logger(this)
	if err != nil {
		return fmt.Errorf("could not set up logger: %w", err)
	}
	c.logger = logger

	if c.host && runtime.GOOS == "windows" {
		return fmt.Errorf("revoking host certificates is not supported on %s", runtime.GOOS)
	}

	// a serial was issued for a single key
	if c.host && len(c.serials) > 0 && len(c.keypath) != 1 {
		return fmt.Errorf("--serial with --host requires a single --key")
	}

	c.logger.Debug("attempting load config", "command", this.CobraCommand.Name())

	config, err := loadconfig(this)
	if err != nil {
		return err
	}

	// revocation uses proof of possession of the private key, so no
	// authentication is set up
	if !c.host {
		store, err := keyringstore.New(config.CertificateAuthorityPublicKey())
		if err != nil {
			return err
		}

		user, err := cert.NewUserCertificate(config.CertificateAuthorityURL, store)
		if err != nil {
			return err
		}
		c.certs = []revocableCert{{name: "user certificate", cert: user}}

		return nil
	}

	if os.Geteuid() != 0 {
		c.logger.Warn("not running as root", "uid", os.Geteuid())
	}

	for _, k := range c.keypath {
		store, err := filestore.New(config.CertificateAuthorityPublicKey(), k)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}

		host, err := cert.NewHostCertificate(config.CertificateAuthorityURL, store)
		if err != nil {
			return err
		}
		c.certs = append(c.certs, revocableCert{name: k, cert: host})
	}

	return nil
}

func (c *revokeCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	targets, err := c.targets()
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintln(stdout, "The following certificates will be revoked:")
	for _, t := range targets {
		if t.keyID != "" {
			_, _ = fmt.Fprintf(stdout, "  %s: serial %d (key ID %q)\n", t.name, t.serial, t.keyID)
		} else {
			_, _ = fmt.Fprintf(stdout, "  %s: serial %d\n", t.name, t.serial)
		}
	}

	if !c.yes {
		ok, err := confirm(stdin, stdout)
		if err != nil {
			return fmt.Errorf("could not read confirmation: %w", err)
		}
		if !ok {
			return ErrRevocationNotConfirmed
		}
	}

	// the serials that were confirmed are revoked, rather than whatever
	// certificate is in the store by now
	errs := make([]error, 0)
	for _, t := range targets {
		l := c.logger.With("certificate", t.name, "serial", t.serial)

		revokedAt, err := t.cert.RevokeSerialContext(ctx, t.serial)
		switch {
		case err == nil:
			l.Info("certificate revoked", "revoked_at", revokedAt)
		case errors.Is(err, cert.ErrDeletingCertificate):
			l.Error("certificate revoked but could not be deleted", "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", t.name, err))
		case errors.Is(err, cert.ErrRemovingFromAgent):
			l.Warn("certificate revoked but could not be removed from the SSH agent", "error", err)
		case errors.Is(err, cert.ErrAlreadyRevoked):
			l.Info("certificate was already revoked")
		default:
			l.Error("could not revoke certificate", "error", err)
			errs = append(errs, fmt.Errorf("%s: %w", t.name, err))
		}
	}

	return errors.Join(errs...)
}

// targets returns the serials to revoke, which are those from --serial or
// otherwise the current certificate in each store. Stores without a
// certificate are skipped.
func (c *revokeCommand) targets() ([]revokeTarget, error) {
	serials := make([]uint64, 0, len(c.serials))
	for _, s := range c.serials {
		serial, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid serial %q: must be a decimal number", s)
		}
		serials = append(serials, serial)
	}

	targets := make([]revokeTarget, 0)
	for _, rc := range c.certs {
		current, err := rc.cert.Store().Certificate()
		if err != nil {
			current = nil
		}

		if len(serials) > 0 {
			for _, serial := range serials {
				t := revokeTarget{revocableCert: rc, serial: serial}
				if current != nil && current.Serial == serial {
					t.keyID = current.KeyId
				}
				targets = append(targets, t)
			}
			continue
		}

		if current == nil {
			c.logger.Info("skipping as there is no certificate", "certificate", rc.name, "error", err)
			continue
		}
		targets = append(targets, revokeTarget{revocableCert: rc, serial: current.Serial, keyID: current.KeyId})
	}

	if len(targets) == 0 {
		return nil, ErrNothingToRevoke
	}

	return targets, nil
}

// confirm asks for confirmation on w and returns true only if "yes" is read
// from r. Reaching the end of r without an answer, such as when there is no
// terminal, is not confirmation.
func confirm(r io.Reader, w io.Writer) (bool, error) {
	_, _ = fmt.Fprint(w, "Revocation cannot be undone. Type \"yes\" to continue: ")

	answer, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}

	return strings.EqualFold(strings.TrimSpace(answer), "yes"), nil
}
