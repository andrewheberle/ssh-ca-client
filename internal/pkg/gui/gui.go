package gui

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/allan-simon/go-singleinstance"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/client"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/tray"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
	"github.com/spf13/pflag"
)

//go:embed icons
var resources embed.FS

const EventLogSource = "Serverless SSH CA Client"

func Execute(ctx context.Context, args []string) error {
	// beeep.AppName = config.FriendlyAppName

	// find config dirs
	user, system, err := config.ConfigDirs()
	if err != nil {
		return err
	}

	// get log dir
	logBase, err := config.LogDir()
	if err != nil {
		return err
	}

	var (
		lifetime, renewAt                                                    time.Duration
		listenAddr, logDir, systemConfigFile, userConfigFile                 string
		disableProxy, addOnStart, showVersion, debugLogging, logToFile, json bool
	)

	flags := pflag.NewFlagSet("ssh-ca-client", pflag.ExitOnError)

	flags.DurationVar(&lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	flags.DurationVar(&renewAt, "renew", time.Hour, "Renew once remaining time gets below this value")
	flags.StringVar(&listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	flags.StringVar(&logDir, "log", filepath.Join(logBase, "log"), "Log directory")
	flags.StringVar(&systemConfigFile, "config", filepath.Join(system, "config.yml"), "Path to configuration file")
	flags.StringVar(&userConfigFile, "user", filepath.Join(user, "user.yml"), "Path to user configuration file")
	flags.BoolVar(&showVersion, "version", false, "Show version and exit")
	flags.BoolVar(&json, "json", false, "Enable JSON logging")
	flags.BoolVar(&debugLogging, "debug", false, "Enable debug logging")
	if runtime.GOOS == "windows" {
		// windows specific flags
		flags.BoolVar(&disableProxy, "disable-proxy", false, "Disable proxying of PuTTY Agent (pageant) requests")
		flags.BoolVar(&logToFile, "log.file", false, "Log to file instead of the Windows Event Log")
	} else {
		// always disabled on non-Windows platforms
		disableProxy = true
		// always log to file for non-Windows
		logToFile = true
	}
	flags.BoolVar(&addOnStart, "add-on-start", true, "Add current key and certificate (if valid) to SSH agent on start")
	_ = flags.Parse(args)

	// handle version flag
	if showVersion {
		fmt.Printf("ssh-ca-client %s\n", version.Version())
		os.Exit(0)
	}

	// check renewAt is not larger than lifetime
	if renewAt > lifetime {
		return fmt.Errorf("--renew cannot be larger than --life")
	}

	// make sure user config location exists
	if err := os.MkdirAll(filepath.Dir(userConfigFile), 0755); err != nil {
		return err
	}

	// make sure log dir exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// load config
	c, err := config.LoadConfig(systemConfigFile, userConfigFile)
	if err != nil {
		return err
	}

	// set location to write panics
	crashFile := filepath.Join(logDir, "crash.log")
	crash, err := os.Create(crashFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = crash.Close()
	}()
	_ = debug.SetCrashOutput(crash, debug.CrashOptions{})

	// set options
	opts := []client.LoginHandlerOption{
		client.WithLifetime(lifetime),
		client.AllowWithoutKey(),
	}
	if !disableProxy {
		opts = append(opts, client.WithPageantProxy())
	}

	// set up login client
	lh, err := client.NewLoginHandler(c, opts...)
	if err != nil {
		return err
	}

	// set up tray app
	app, err := tray.New(names.FriendlyAppName, listenAddr, resources, lh, renewAt)
	if err != nil {
		return err
	}

	// set up logger
	level := new(slog.LevelVar)
	if debugLogging {
		level.Set(slog.LevelDebug)
	}
	var logger *slog.Logger
	if logToFile {
		logFile := filepath.Join(logDir, "tray.log")
		log, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer func() {
			_ = log.Close()
		}()

		logger = slog.New(newLogHandler(log, level, json))
		logger.Info("logging to log file", "file", logFile)
	} else {
		logger = slog.New(newLogHandler(nil, level, json))
	}

	// make sure we are only running once
	lockFile, err := singleinstance.CreateLockFile(filepath.Join(user, "tray.lock"))
	if err != nil {
		logger.Error("could not take lock", "error", err)
		return err
	}
	defer func() {
		_ = lockFile.Close()
		_ = os.Remove(lockFile.Name())
	}()

	// start pageant proxy if requested
	if !disableProxy {
		logger.Info("attempting to start pageant proxy process")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := lh.RunPageantProxy(ctx); err != nil {
				// dont log an error if the error indicates the context was cancelled
				if !errors.Is(err, context.Canceled) {
					logger.Error("error from pageant proxy", "error", err)
				}
			}
		}()
	}

	// try to add to agent on start
	if addOnStart {
		logger.Info("attempting to add current certificate to ssh agent")
		if err := lh.AddToAgent(); err != nil {
			logger.Warn("could not add current certificate to ssh agent", "error", err)
		}
	}

	app.RunLogged(logger)

	return nil
}
