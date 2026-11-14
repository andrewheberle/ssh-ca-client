package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/gui"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:]))
}

// run runs the GUI and returns the exit code. When the GUI exits without
// running, it tells the user why with inform or fail, as on Windows the GUI
// has no console.
func run(ctx context.Context, args []string) int {
	err := gui.Execute(ctx, args)

	var exit *gui.Exit
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		if exit.Code == 0 {
			inform(exit.Message)
		} else {
			fail(exit.Message)
		}
		return exit.Code
	default:
		fail(fmt.Sprintf("%s could not start: %s\n", names.FriendlyAppName, err))
		return 1
	}
}
