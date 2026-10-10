//go:build !snap && !windows

// Command gendocs generates the markdown documentation for ssh-ca-client-cli
// into the docs directory of the repository.
//
// It is run via "go generate ./..." from the root of the repository and must
// be run from the internal/pkg/cli directory, as go generate does.
package main

import (
	"log/slog"
	"os"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if len(os.Args) != 1 {
		logger.Error("gendocs takes no arguments")
		os.Exit(2)
	}

	if err := cli.GenerateDocs(cli.DocsDir); err != nil {
		logger.Error("could not generate docs", "error", err)
		os.Exit(1)
	}
}
