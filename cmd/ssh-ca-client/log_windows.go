package main

import (
	"fmt"
	"os"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/gui"
	"golang.org/x/sys/windows/svc/eventlog"
)

func logFatal(format string, a ...any) {
	logger, err := eventlog.Open(gui.EventLogSource)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = logger.Close()
	}()

	if err := logger.Error(1000, fmt.Sprintf(format, a...)); err != nil {
		panic(err)
	}

	os.Exit(1)
}
