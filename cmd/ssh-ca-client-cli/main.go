package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cli"
)

func main() {
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{})
	logger := slog.New(h)

	// cancel the context on CTRL-C so long running commands can stop
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)

	err := cli.Execute(ctx, os.Args[1:])
	stop()

	if err != nil {
		logger.Error("error during execution", "error", err)
		os.Exit(1)
	}
}
