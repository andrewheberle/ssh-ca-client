package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/bep/simplecobra"
	"github.com/spf13/pflag"
)

// defaultHostKeys are the paths of the host private keys used by the host and
// revoke --host sub-commands by default
var defaultHostKeys = []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_rsa_key"}

// deprecateRenamed marks the flag old, which was renamed to new, as deprecated.
// It keeps working, with a warning, and is hidden from help and the generated
// docs. Renamed flags are kept for every 1.x release.
func deprecateRenamed(flags *pflag.FlagSet, old, new string) error {
	return flags.MarkDeprecated(old, "use --"+new+" instead")
}

// loadconfig will load the config from the command line options
func loadconfig(this *simplecobra.Commandeer) (*config.ClientConfig, error) {
	// get config location
	configLocation, err := this.CobraCommand.Flags().GetString("config")
	if err != nil {
		return nil, fmt.Errorf("problem accessing config flag: %w", err)
	}

	return config.LoadClientConfig(configLocation)
}

func logger(this *simplecobra.Commandeer) (*slog.Logger, error) {
	debug, err := this.CobraCommand.Flags().GetBool("debug")
	if err != nil {
		return nil, fmt.Errorf("problem accessing debug flag: %w", err)
	}

	json, err := this.CobraCommand.Flags().GetBool("json")
	if err != nil {
		return nil, fmt.Errorf("problem accessing json flag: %w", err)
	}

	var h slog.Handler

	logLevel := new(slog.LevelVar)
	if json {
		h = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		h = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	logger := slog.New(h)

	if debug {
		logLevel.Set(slog.LevelDebug)
	}

	return logger, nil
}
