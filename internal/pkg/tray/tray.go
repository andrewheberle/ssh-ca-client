//go:build windows || linux

package tray

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
	"github.com/gen2brain/beeep"
	"golang.org/x/crypto/ssh"
)

type appState string

const (
	// states
	stateInit               appState = "Init"
	stateKeyMissing         appState = "KeyMissing"
	stateKeyOK              appState = "KeyOK"
	stateCertificateOK      appState = "CertificateOK"
	stateCertificateMissing appState = "CertificateMissing"
	stateCertificateExpired appState = "CertificateExpired"

	defaultIcon = okIcon

	okIcon      = "ok"
	warningIcon = "warning"
	errorIcon   = "error"
)

// Certificate is the user certificate managed by the application, such as a
// [*cert.UserCertificate]
type Certificate interface {
	Store() cert.Storage
	RequestContext(ctx context.Context) error
}

type Application struct {
	cert    Certificate
	config  *config.ClientConfig
	done    chan bool
	title   string
	renewAt time.Duration

	// ctx is cancelled when the application quits, which aborts any
	// interactive login in progress
	ctx    context.Context
	cancel context.CancelFunc

	trayIcons         map[string][]byte
	notificationIcons map[string][]byte
	state             appState

	mExpiry   *systray.MenuItem
	mGenerate *systray.MenuItem
	mRenew    *systray.MenuItem
	mQuit     *systray.MenuItem

	mu             sync.Mutex
	refreshBackOff int
	refreshFailure int

	logger *slog.Logger
}

var (
	ErrRenewSkipped = errors.New("renew skipped")
	ErrRenewRunning = errors.New("a renew was already in progress")
)

func New(title string, fs embed.FS, c Certificate, conf *config.ClientConfig, renewAt time.Duration) (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		cert:              c,
		config:            conf,
		ctx:               ctx,
		cancel:            cancel,
		done:              make(chan bool),
		logger:            slog.New(slog.DiscardHandler),
		notificationIcons: make(map[string][]byte),
		renewAt:           renewAt,
		state:             stateInit,
		title:             title,
		trayIcons:         make(map[string][]byte),
	}

	// load tray icons
	for name, file := range trayIconFiles() {
		icon, err := fs.ReadFile(file)
		if err != nil {
			return nil, err
		}

		app.trayIcons[name] = icon
	}

	// load notification icons
	nIcons := map[string]string{
		okIcon:      "icons/ok.png",
		errorIcon:   "icons/error.png",
		warningIcon: "icons/warning.png",
	}
	for name, file := range nIcons {
		icon, err := fs.ReadFile(file)
		if err != nil {
			return nil, err
		}

		app.notificationIcons[name] = icon
	}

	return app, nil
}

func (app *Application) prerun() {
	// set app name in beeep
	beeep.AppName = app.title
}

// Sends a desktop notification
func (app *Application) notify(title string, message string, icon string) {
	// grab icon
	b := app.getIcon(icon)

	// set notification
	if err := beeep.Notify(title, message, b); err != nil {
		app.logger.Error("could not send notification", "error", err)
	}
}

func (app *Application) Run() {
	app.prerun()
	systray.Run(app.onReady, app.cancel)
}

func (app *Application) RunLogged(logger *slog.Logger) {
	if logger != nil {
		app.logger = logger
	}
	app.prerun()
	systray.Run(app.onReady, app.cancel)
}

func (app *Application) onReady() {
	// set title and icon
	systray.SetTitle(app.title)

	// build menu
	app.mRenew = systray.AddMenuItem("Renew", "Renew certificate")
	app.mGenerate = systray.AddMenuItem("Generate", "Generate private key")
	systray.AddSeparator()
	app.mExpiry = systray.AddMenuItem("Unknown", "Current expiry unknown")
	app.mExpiry.Disable()
	systray.AddSeparator()
	app.mQuit = systray.AddMenuItem("Quit", "Close application")

	// set initial state
	app.setState()

	// send some status
	app.logger.Info("tray application started",
		"client_id", app.config.ClientID,
		"issuer", app.config.Issuer,
		"redirect_url", app.config.RedirectURL,
		"scopes", app.config.Scopes,
		"ca_url", app.config.CertificateAuthorityURL,
		"trusted_ca", app.config.TrustedCertificateAuthority,
	)

	// handle clicks
	go app.eventloop()
}

// hasPrivateKey reports whether a private key is stored
func (app *Application) hasPrivateKey() bool {
	return app.cert.Store().HasPrivateKey()
}

// hasCertificate reports whether a certificate is stored
func (app *Application) hasCertificate() bool {
	return app.cert.Store().HasCertificate()
}

// certificateExpiry returns when the stored certificate expires, or the zero
// time if there is no certificate
func (app *Application) certificateExpiry() time.Time {
	c, err := app.cert.Store().Certificate()
	if err != nil {
		return time.Time{}
	}

	if c.ValidBefore == ssh.CertTimeInfinity {
		// effectively never expires
		return time.Unix(1<<62, 0)
	}

	return time.Unix(int64(c.ValidBefore), 0)
}

// certificateValid reports whether a certificate is stored that has not
// expired
func (app *Application) certificateValid() bool {
	return app.certificateExpiry().After(time.Now())
}

func (app *Application) setState() {
	switch app.state {
	case stateInit:
		// we are starting up
		app.logger.Info("starting up")
		if app.hasPrivateKey() {
			// have a private key
			app.state = stateKeyOK

			// if we have a certificate but it's expired on start, try to refresh
			if app.hasCertificate() {
				if !app.certificateValid() {
					if err := app.refresh(); err == nil {
						app.state = stateCertificateOK
						app.logger.Info("refresh of certificate succeeded")
						app.notify("Certificate Refreshed", "The current certificate was successfully refreshed", okIcon)
						app.setState()
						break
					} else {
						app.state = stateCertificateExpired
						app.logger.Info("refresh of certificate failed", "error", err)
						app.notify("Certificate Expired", "The current certificate has expired and must be manually renewed", warningIcon)
						app.setState()
						break
					}
				}
			}
		} else {
			// no private key
			app.state = stateKeyMissing
		}

		// re-run to handle change
		app.setState()
	case stateKeyMissing:
		// check a key has not been generated elsewhere, such as by the CLI
		if app.hasPrivateKey() {
			app.logger.Info("private key found")
			app.state = stateKeyOK
			// re-run to handle change
			app.setState()
			// finish now
			break
		}

		app.logger.Info("no private key found")
		app.mGenerate.Enable()
		app.mRenew.Disable()
		app.mExpiry.SetTitle("No certificate")
		app.setTooltip("No private key found")
		systray.SetIcon(app.trayIcons["error"])
	case stateKeyOK:
		// we have a key so check the state of the certificate
		app.logger.Info("private key found")
		app.mGenerate.Disable()
		if !app.hasCertificate() {
			// no certificate
			app.state = stateCertificateMissing
		} else {
			if app.certificateValid() {
				// certificate is valid
				app.state = stateCertificateOK
			} else {
				// expired certficate
				app.state = stateCertificateExpired
			}
		}

		// re-run to handle change
		app.setState()
	case stateCertificateExpired:
		// check we haven't renewed
		if app.certificateValid() {
			app.logger.Info("certificate renewed")
			app.state = stateCertificateOK
			// re-run to handle change
			app.setState()
			// finish now
			break
		}

		app.mRenew.SetTitle("Renew")
		app.mRenew.Enable()
		app.mExpiry.SetTitle("Certificate expired")
		app.setTooltip("Certificate expired")
		systray.SetIcon(app.trayIcons["warning"])
	case stateCertificateMissing:
		// check we haven't renewed
		if app.certificateValid() {
			app.logger.Info("certificate issued")
			app.state = stateCertificateOK
			// re-run to handle change
			app.setState()
			// finish now
			break
		}
		app.mRenew.SetTitle("Request")
		app.mRenew.Enable()
		app.mExpiry.SetTitle("No certificate")
		app.setTooltip("No certificate found")
		systray.SetIcon(app.trayIcons["warning"])
	case stateCertificateOK:
		// check we haven't expired
		if !app.certificateValid() {
			app.logger.Info("current certificate expired")

			// try to refresh
			if err := app.refreshWithBackoff(); err == nil {
				app.logger.Info("refresh of certificate succeeded")
				// send notification
				app.notify("Certificate Refreshed", "The current certificate was successfully refreshed", okIcon)
				// re-run to handle change
				app.setState()
				// finish now
				break
			} else {
				// return if renewal is in progress
				if errors.Is(err, ErrRenewRunning) {
					break
				}

				if errors.Is(err, ErrRenewSkipped) {
					app.logger.Error("expired certificate was not renewed due to recent failures", "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				} else {
					app.logger.Error("could not refresh expired certificate", "error", err, "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				}
			}

			app.state = stateCertificateExpired
			// send notification
			app.notify("Certificate Expired", "The current certificate has expired and must be manually renewed", warningIcon)
			// re-run to handle change
			app.setState()
			// finish now
			break
		}

		// check if the renewAt threshold has been reached
		if time.Until(app.certificateExpiry()) < app.renewAt {
			app.logger.Info("current certificate close to expiry")

			// try to refresh. On success the menu below is updated with the new
			// expiry rather than re-running, so a certificate issued with less
			// than renewAt validity is not refreshed again immediately.
			if err := app.refreshWithBackoff(); err == nil {
				app.logger.Info("refresh of certificate succeeded")
				// send notification
				app.notify("Certificate Refreshed", "The current certificate was successfully refreshed", okIcon)
			} else {
				// return if renewal is in progress
				if errors.Is(err, ErrRenewRunning) {
					break
				}

				// just log error
				if errors.Is(err, ErrRenewSkipped) {
					app.logger.Error("certificate near expiry was not renewed due to recent failures", "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				} else {
					app.logger.Error("could not refresh certificate close to expiry", "error", err, "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				}
			}
		}

		app.mRenew.SetTitle("Renew")
		app.mRenew.Enable()
		app.mExpiry.SetTitle(fmt.Sprintf("%s left", timeLeft(app.certificateExpiry())))
		app.setTooltip("Current certificate valid")
		systray.SetIcon(app.trayIcons[okIcon])
	}
}

func (app *Application) eventloop() {
	t := time.NewTicker(time.Minute * 1)
	defer t.Stop()

	// a renewal can include an interactive login so it is run in the
	// background, with the result received here
	var renewDone chan error

	for {
		app.setState()

		// prevent overlapping renewals
		if renewDone != nil {
			app.mRenew.Disable()
		}

		select {
		case <-t.C:
			// this is a noop
			continue
		case <-app.mRenew.ClickedCh:
			if renewDone != nil {
				// a renewal is already in progress
				continue
			}

			// start by disabling menu item so we aren't overlapping
			app.mRenew.Disable()

			renewDone = make(chan error, 1)
			go func(done chan<- error) {
				done <- app.refreshOrRenew()
			}(renewDone)
		case err := <-renewDone:
			renewDone = nil

			switch {
			case err == nil:
				app.notify("Certificate Issued", "A new certificate was issued and added to the local SSH Authentication Agent", okIcon)
				app.state = stateCertificateOK
			case errors.Is(err, cert.ErrAddingToAgent):
				app.logger.Warn("certificate issued but could not add to agent", "error", err)
				app.notify("Warning", "A new certificate was issued but could not added to the local SSH Authentication Agent", warningIcon)
				app.state = stateCertificateOK
			case errors.Is(err, context.Canceled):
				app.logger.Info("certificate renewal cancelled")
			default:
				app.logger.Error("could not renew certificate", "error", err)
				app.notify("Error", "The certificate renewal failed", errorIcon)
			}
		case <-app.mGenerate.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mGenerate.Disable()

			// do key generation
			if err := app.generate(); err != nil {
				app.logger.Error("could not generate private key", "error", err)
				app.notify("Error", "The generation of a private key failed", errorIcon)
				break
			}

			app.notify("Key Generated", "A private key was successfully generated", okIcon)
			app.state = stateKeyOK
		case <-app.mQuit.ClickedCh:
			app.logger.Info("application shutting down")
			// abort any interactive login in progress
			app.cancel()
			systray.Quit()
			return
		}
	}
}

// refreshOrRenew tries a non-interactive refresh first and falls back to an
// interactive renewal. If the certificate was issued but could not be added to
// the SSH agent, the error wraps [cert.ErrAddingToAgent] and no interactive
// renewal is attempted.
func (app *Application) refreshOrRenew() error {
	err := app.refresh()
	if err == nil || errors.Is(err, cert.ErrAddingToAgent) {
		return err
	}

	app.logger.Warn("could not perform a refresh, running renew", "error", err)

	return app.renew()
}

func (app *Application) refreshWithBackoff() error {
	// try to take lock and error immediately if we cant
	if !app.mu.TryLock() {
		return ErrRenewRunning
	}
	defer app.mu.Unlock()

	if app.refreshBackOff > 0 {
		// reduce our backoff counter
		app.refreshBackOff--

		// exit
		return ErrRenewSkipped
	}

	// we are ok to attempt a refresh
	if err := app.request(auth.NonInteractive(app.ctx)); err != nil {
		// increment our failure count and set a backoff of double our failure count
		app.refreshFailure++
		app.refreshBackOff = app.refreshFailure * 2

		return err
	}

	// reset on success
	app.refreshFailure = 0
	app.refreshBackOff = 0

	return nil
}

// refresh requests a new certificate without an interactive login, so only
// cached tokens or a refresh token are used
func (app *Application) refresh() error {
	// try to take lock and error immediately if we cant
	if !app.mu.TryLock() {
		return ErrRenewRunning
	}
	defer app.mu.Unlock()

	app.logger.Info("attempting a refresh")

	if err := app.request(auth.NonInteractive(app.ctx)); err != nil {
		return err
	}

	// reset on success
	app.refreshFailure = 0
	app.refreshBackOff = 0

	return nil
}

// renew requests a new certificate, running an interactive login if required.
// This is aborted if the application quits.
func (app *Application) renew() error {
	// try to take lock and error immediately if we cant
	if !app.mu.TryLock() {
		return ErrRenewRunning
	}
	defer app.mu.Unlock()

	if err := app.request(app.ctx); err != nil {
		return err
	}

	// reset on success
	app.refreshFailure = 0
	app.refreshBackOff = 0

	return nil
}

// request requests a new certificate and adds it to the SSH agent. If the
// certificate is issued but cannot be added to the agent the returned error
// wraps [cert.ErrAddingToAgent].
func (app *Application) request(ctx context.Context) error {
	if err := app.cert.RequestContext(ctx); err != nil {
		return err
	}

	if err := app.cert.Store().AddToAgent(); err != nil {
		return fmt.Errorf("certificate issued but %w", err)
	}

	return nil
}

func (app *Application) generate() error {
	return app.cert.Store().GeneratePrivateKey()
}

func (app *Application) getIcon(icon string) []byte {
	// grab icon
	b, ok := app.notificationIcons[icon]
	if !ok {
		return app.notificationIcons[defaultIcon]
	}

	return b
}

func timeLeft(t time.Time) string {
	timeLeft := time.Until(t)
	return fmt.Sprintf("%02dh%02dm", int(timeLeft.Hours()), int(timeLeft.Minutes())%60)
}

func (app *Application) setTooltip(message string) {
	// set tooltip
	tooltip := fmt.Sprintf("SSH CA Client (%s) - %s", version.Version(), message)
	systray.SetTooltip(tooltip)
}
