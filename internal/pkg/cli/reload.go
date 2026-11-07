package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os/exec"
	"slices"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
)

// reloadTimeout is how long the reload command may run
const reloadTimeout = time.Minute

// reloadCommandUsage is the usage of the --reload-command flag
const reloadCommandUsage = "Command run with /bin/sh -c once host certificates have changed, such as to reload sshd"

var ErrReloadFailed = errors.New("reload command failed")

// hostReload runs a command once host certificates have changed, so sshd can
// be reloaded to present them. From OpenSSH 9.8 sshd reads host certificates
// only when it starts or is reloaded, so until then it keeps presenting the
// certificates it read, even once they have been renewed and so revoked.
//
// It records the certificate of each store when it is created, and run
// compares them with the certificates the stores hold by then. A certificate
// that was written or deleted counts as a change whether or not the command
// that changed it succeeded.
type hostReload struct {
	command string
	stores  map[string]cert.Storage
	before  map[string][]byte
}

// newHostReload records the current certificate of each store, by the path of
// its private key. An empty command does not run anything, and run logs that
// sshd should be reloaded instead.
func newHostReload(command string, stores map[string]cert.Storage) *hostReload {
	r := &hostReload{
		command: command,
		stores:  stores,
		before:  make(map[string][]byte, len(stores)),
	}
	for k, s := range stores {
		r.before[k] = certificateBytes(s)
	}

	return r
}

// certificateBytes returns the certificate held by s, or nil when it has none
func certificateBytes(s cert.Storage) []byte {
	b, err := s.CertificateBytes()
	if err != nil {
		return nil
	}

	return b
}

// changed returns the private key paths whose certificate has changed
func (r *hostReload) changed() []string {
	changed := make([]string, 0)
	for _, k := range slices.Sorted(maps.Keys(r.stores)) {
		if !bytes.Equal(r.before[k], certificateBytes(r.stores[k])) {
			changed = append(changed, k)
		}
	}

	return changed
}

// run runs the reload command once if any certificate has changed. It still
// runs once ctx is done, so a run that was interrupted after a certificate
// was written still reloads sshd, but is limited to reloadTimeout.
func (r *hostReload) run(ctx context.Context, logger *slog.Logger) error {
	changed := r.changed()
	if len(changed) == 0 {
		logger.Debug("host certificates have not changed so the reload command is not run")
		return nil
	}

	if r.command == "" {
		logger.Info("host certificates changed, reload sshd (or use --reload-command) so it presents them", "keys", changed)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reloadTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", r.command).CombinedOutput()
	if err != nil {
		logger.Error("reload command failed", "command", r.command, "error", err, "output", string(bytes.TrimSpace(out)))
		return fmt.Errorf("%w: %q: %w", ErrReloadFailed, r.command, err)
	}
	logger.Info("ran reload command as host certificates changed", "command", r.command, "keys", changed)

	return nil
}
