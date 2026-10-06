package cli

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/bep/simplecobra"
)

type rootCommand struct {
	configFile string
	debug      bool
	json       bool

	*simplecommand.Command
}

var (
	ErrCommandNotImplemented = errors.New("command not implemented")
	ErrNoPrivateKey          = errors.New("no private key found")

	// to allow output redirection for tests
	stdout io.ReadWriter = os.Stdout
)

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().StringVar(&c.configFile, "config", config.ConfigPath(), "Configuration location")
	cmd.PersistentFlags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.PersistentFlags().BoolVar(&c.json, "json", false, "Enable JSON logging")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	return nil
}

func Execute(ctx context.Context, args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New("ssh-ca-client-cli", "A CLI based client for a serverless SSH CA"),
	}
	rootCmd.SubCommands = commands()

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(ctx, args); err != nil {
		return err
	}

	return nil
}
