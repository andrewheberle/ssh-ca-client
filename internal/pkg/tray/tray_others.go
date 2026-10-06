//go:build !windows && !linux

package tray

import (
	"context"
	"embed"
	"errors"
	"log/slog"
	"runtime"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
)

type Application struct {
	logger *slog.Logger
}

var ErrNotSupported = errors.New("not supported on this platform")

// Certificate is the user certificate managed by the application
type Certificate interface {
	Store() cert.Storage
	RequestContext(ctx context.Context) error
}

func New(title string, fs embed.FS, c Certificate, conf *config.ClientConfig, renewAt time.Duration) (*Application, error) {
	return nil, ErrNotSupported
}

func (app *Application) RunLogged(logger *slog.Logger) {
	logger.Error("this is not supported on this platform", "goos", runtime.GOOS, "goarch", runtime.GOARCH)
}
