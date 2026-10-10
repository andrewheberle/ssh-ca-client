//go:build !snap && !windows

// Command gendocs generates the markdown documentation for ssh-ca-client-cli
// into the provided directory.
//
// It is run via "go generate ./..." from the root of the repository.
package main

import (
	"log/slog"
	"os"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if len(os.Args) != 2 {
		logger.Error("usage: gendocs <directory>")
		os.Exit(2)
	}

	if err := cli.GenerateDocs(os.Args[1]); err != nil {
		logger.Error("could not generate docs", "error", err)
		os.Exit(1)
	}
}
