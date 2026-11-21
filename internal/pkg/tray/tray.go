//go:build windows || linux

package tray

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"fyne.io/systray"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/config"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/identity"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
	"github.com/gen2brain/beeep"
	"golang.org/x/crypto/ssh"
)

// appState is what the application shows for the user identity. It is worked
// out from what can be seen each time the event loop runs, by [deriveState],
// rather than changed by transitions, so a key or certificate added or removed
// elsewhere, such as by the CLI, is picked up.
type appState string

const (
	// states
	stateInit               appState = "Init"
	stateKeyMissing         appState = "KeyMissing"
	stateCertificateMissing appState = "CertificateMissing"
	stateCertificateOK      appState = "CertificateOK"
	stateCertificateDue     appState = "CertificateDue"
	stateCertificateExpired appState = "CertificateExpired"

	defaultIcon = okIcon

	okIcon      = "ok"
	warningIcon = "warning"
	errorIcon   = "error"

	// menu item titles
	refreshTitle = "Refresh"
	loginTitle   = "Log in"

	// tickInterval is how often the event loop checks the certificate
	tickInterval = time.Minute

	// maxBackoff is the longest wait between automatic refreshes that fail
	maxBackoff = 30 * time.Minute

	// defaultQuitWait is how long quitting waits for an operation to stop, so
	// a certificate being saved is not cut off
	defaultQuitWait = 5 * time.Second
)

// Identity is the user identity managed by the application, such as a
// [*identity.User]
type Identity interface {
	HasPrivateKey() bool
	GeneratePrivateKey() error
	Certificate() (*ssh.Certificate, error)
	Obtain(ctx context.Context, opts ...identity.ObtainOption) error
}

// menuItem is the part of a [*systray.MenuItem] updated as the state changes
type menuItem interface {
	SetTitle(title string)
	Enable()
	Disable()
}

// opKind is the kind of operation that obtains a certificate
type opKind int

const (
	// opRefresh is an automatic refresh, which never starts a login
	opRefresh opKind = iota

	// opLogin is started from the menu, and is a refresh that falls back to a
	// login
	opLogin
)

// operation is a running request for a certificate. Only one is current at a
// time, see [Application.start].
type operation struct {
	kind   opKind
	cancel context.CancelFunc

	// finished is closed once the request has returned
	finished chan struct{}
}

// opResult is the result of an operation, sent to the event loop
type opResult struct {
	op  *operation
	err error
}

type Application struct {
	identity Identity
	config   *config.ClientConfig
	done     chan bool
	title    string
	renewAt  time.Duration

	// ctx is cancelled when the application quits, which aborts any
	// operation in progress
	ctx    context.Context
	cancel context.CancelFunc

	trayIcons         map[string][]byte
	notificationIcons map[string][]byte

	mExpiry   menuItem
	mGenerate menuItem
	mRefresh  menuItem

	// channels notified when the menu items are clicked
	refreshClicked  <-chan struct{}
	generateClicked <-chan struct{}
	quitClicked     <-chan struct{}

	// these update the system tray, send desktop notifications, quit the
	// system tray and tell the time, which are replaced in tests
	setIcon    func(icon []byte)
	setTooltip func(tooltip string)
	notifier   func(title, message string, icon any) error
	quitTray   func()
	now        func() time.Time

	// quitWait is how long quitting waits for an operation to stop
	quitWait time.Duration

	// opDone receives the result of each operation
	opDone chan opResult

	// The rest is only used by the event loop, which runs a single goroutine,
	// so needs no lock.

	// state is the state shown as of the last update
	state appState

	// op is the current operation, if any
	op *operation

	// failures counts failed automatic refreshes in a row, and nextRefresh is
	// when the next may start
	failures    int
	nextRefresh time.Time

	// loginRequired is set when a refresh failed because a login is needed,
	// and cleared once a certificate is obtained
	loginRequired bool

	// expiredNotified is set once the user is told the certificate expired,
	// until it is no longer expired
	expiredNotified bool

	// loginNotified is set once the user is told a login is needed before
	// the certificate expires, until it is no longer due to be refreshed.
	// While it is set the tray shows a login is needed.
	loginNotified bool

	// lastTick is when the event loop last ticked, to notice a suspend
	lastTick time.Time

	logger *slog.Logger
}

func New(title string, fs embed.FS, id Identity, conf *config.ClientConfig, renewAt time.Duration) (*Application, error) {
	ctx, cancel := context.WithCancel(context.Background())

	app := &Application{
		identity:          id,
		config:            conf,
		ctx:               ctx,
		cancel:            cancel,
		done:              make(chan bool),
		logger:            slog.New(slog.DiscardHandler),
		notificationIcons: make(map[string][]byte),
		notifier:          beeep.Notify,
		now:               time.Now,
		opDone:            make(chan opResult, 2),
		quitTray:          systray.Quit,
		quitWait:          defaultQuitWait,
		renewAt:           renewAt,
		setIcon:           systray.SetIcon,
		setTooltip:        systray.SetTooltip,
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
	if err := app.notifier(title, message, b); err != nil {
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

// onReady builds the menu and starts the event loop. It does nothing that may
// block, as on Linux the menu can't be shown until it returns.
func (app *Application) onReady() {
	// set title and icon
	systray.SetTitle(app.title)

	// build menu
	mRefresh := systray.AddMenuItem(refreshTitle, "Get a new certificate")
	mGenerate := systray.AddMenuItem("Generate", "Generate private key")
	systray.AddSeparator()
	mExpiry := systray.AddMenuItem("Unknown", "Current expiry unknown")
	mExpiry.Disable()
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "Close application")

	app.mRefresh, app.refreshClicked = mRefresh, mRefresh.ClickedCh
	app.mGenerate, app.generateClicked = mGenerate, mGenerate.ClickedCh
	app.mExpiry = mExpiry
	app.quitClicked = mQuit.ClickedCh

	// send some status
	app.logger.Info("tray application started",
		"client_id", app.config.ClientID,
		"issuer", app.config.Issuer,
		"redirect_url", app.config.RedirectURL,
		"scopes", app.config.Scopes,
		"ca_url", app.config.CertificateAuthorityURL,
		"trusted_ca", app.config.TrustedCertificateAuthority,
	)

	// handle clicks, starting with the current state
	go func() {
		t := time.NewTicker(tickInterval)
		defer t.Stop()

		app.eventloop(t.C)
	}()
}

// observation is what the application can see of the user identity
type observation struct {
	hasKey bool

	// cert is nil when there is no certificate
	cert *ssh.Certificate

	now time.Time
}

// observe looks at the user identity
func (app *Application) observe() observation {
	obs := observation{
		hasKey: app.identity.HasPrivateKey(),
		now:    app.now(),
	}

	if c, err := app.identity.Certificate(); err == nil {
		obs.cert = c
	}

	return obs
}

// deriveState works out the state from what is observed
func deriveState(obs observation, renewAt time.Duration) appState {
	switch {
	case !obs.hasKey:
		return stateKeyMissing
	case obs.cert == nil:
		return stateCertificateMissing
	case !obs.now.Before(certificateExpiry(obs.cert)):
		return stateCertificateExpired
	case refreshDue(obs.cert, obs.now, renewAt):
		return stateCertificateDue
	default:
		return stateCertificateOK
	}
}

// certificateExpiry returns when c expires
func certificateExpiry(c *ssh.Certificate) time.Time {
	if c.ValidBefore == ssh.CertTimeInfinity {
		// effectively never expires
		return time.Unix(1<<62, 0)
	}

	return time.Unix(int64(c.ValidBefore), 0)
}

// refreshDue reports whether c should be refreshed at now, which is once less
// than renewAt, or half its lifetime if that is less, remains. Half the
// lifetime is used so that a certificate issued with less than renewAt of
// lifetime, such as when the CA issues a shorter lifetime than requested, is
// not due as soon as it is issued.
func refreshDue(c *ssh.Certificate, now time.Time, renewAt time.Duration) bool {
	if c.ValidBefore == ssh.CertTimeInfinity {
		return false
	}

	expiry := certificateExpiry(c)
	window := renewAt
	if lifetime := expiry.Sub(time.Unix(int64(c.ValidAfter), 0)); lifetime > 0 && lifetime/2 < window {
		window = lifetime / 2
	}

	return expiry.Sub(now) < window
}

// backoffDelay is how long to wait after failures automatic refreshes in a
// row have failed
func backoffDelay(failures int) time.Duration {
	return min(time.Duration(failures)*2*time.Minute, maxBackoff)
}

// suspended reports whether the system was suspended between the ticks at
// last and now, as the wall clock moved on much further than a tick
func suspended(last, now time.Time) bool {
	return now.Round(0).Sub(last.Round(0)) > 3*tickInterval
}

// eventloop runs until Quit is clicked. Everything here, apart from the
// operations it starts, runs on this goroutine and must not block for long,
// as the system tray drops clicks while it is busy.
func (app *Application) eventloop(ticks <-chan time.Time) {
	for {
		app.update()

		select {
		case now := <-ticks:
			app.tick(now)
		case res := <-app.opDone:
			app.finish(res)
		case <-app.refreshClicked:
			app.refreshClick()
		case <-app.generateClicked:
			app.generateClick()
		case <-app.quitClicked:
			app.quit()
			return
		}
	}
}

// update works out the current state, starts an automatic refresh if one is
// due, and shows the state
func (app *Application) update() {
	obs := app.observe()
	state := deriveState(obs, app.renewAt)

	if state != app.state {
		app.logger.Info("state changed", "from", app.state, "to", state)
		app.state = state
	}

	if state != stateCertificateExpired {
		app.expiredNotified = false
	}
	if state != stateCertificateDue {
		app.loginNotified = false
	}

	// refresh in the background, unless another operation is running or
	// recent refreshes failed
	if (state == stateCertificateDue || state == stateCertificateExpired) && app.op == nil && !obs.now.Before(app.nextRefresh) {
		app.logger.Info("attempting a refresh", "state", state)
		app.start(opRefresh)
	}

	// tell the user once, while the certificate is still valid, that it
	// can't be refreshed without a login. Once it has expired they are told
	// that instead
	if state == stateCertificateDue && app.loginRequired && app.op == nil && !app.loginNotified {
		app.loginNotified = true
		app.notify("Login Needed", fmt.Sprintf("The certificate expires in %s and can't be refreshed without logging in. Select \"%s\" from the menu to get a new one.", timeLeft(certificateExpiry(obs.cert), obs.now), app.refreshTitle(state)), warningIcon)
	}

	// tell the user once the certificate expired and no operation is running
	// that may get a new one
	if state == stateCertificateExpired && app.op == nil && !app.expiredNotified {
		app.expiredNotified = true
		app.notify("Certificate Expired", "The current certificate has expired and could not be refreshed. Select \""+app.refreshTitle(state)+"\" from the menu to get a new one.", warningIcon)
	}

	app.render(state, obs)
}

// refreshTitle is the title of the menu item that gets a new certificate,
// which says when a login is needed
func (app *Application) refreshTitle(state appState) string {
	if state == stateCertificateMissing || app.loginRequired {
		return loginTitle
	}

	return refreshTitle
}

// render shows state in the system tray
func (app *Application) render(state appState, obs observation) {
	app.mRefresh.SetTitle(app.refreshTitle(state))

	// a login from the menu is running until it finishes, while an automatic
	// refresh is replaced by a click
	if state == stateKeyMissing || (app.op != nil && app.op.kind == opLogin) {
		app.mRefresh.Disable()
	} else {
		app.mRefresh.Enable()
	}

	if state == stateKeyMissing {
		app.mGenerate.Enable()
	} else {
		app.mGenerate.Disable()
	}

	switch state {
	case stateKeyMissing:
		app.mExpiry.SetTitle("No certificate")
		app.setStatus("No private key found")
		app.setIcon(app.trayIcons[errorIcon])
	case stateCertificateMissing:
		app.mExpiry.SetTitle("No certificate")
		app.setStatus("No certificate found")
		app.setIcon(app.trayIcons[warningIcon])
	case stateCertificateExpired:
		app.mExpiry.SetTitle("Certificate expired")
		app.setStatus("Certificate expired")
		app.setIcon(app.trayIcons[warningIcon])
	case stateCertificateDue:
		app.mExpiry.SetTitle(fmt.Sprintf("%s left", timeLeft(certificateExpiry(obs.cert), obs.now)))
		if app.loginNotified {
			// shown until the certificate expires or a new one is obtained,
			// after the notification is dismissed
			app.setStatus("Login needed")
			app.setIcon(app.trayIcons[warningIcon])
		} else {
			app.setStatus("Current certificate valid")
			app.setIcon(app.trayIcons[okIcon])
		}
	default:
		app.mExpiry.SetTitle(fmt.Sprintf("%s left", timeLeft(certificateExpiry(obs.cert), obs.now)))
		app.setStatus("Current certificate valid")
		app.setIcon(app.trayIcons[okIcon])
	}
}

// tick resets the backoff after a suspend, as the network may have been down
// only until the resume
func (app *Application) tick(now time.Time) {
	if !app.lastTick.IsZero() && suspended(app.lastTick, now) {
		app.logger.Info("resumed after a suspend", "last_tick", app.lastTick, "now", now)
		app.resetBackoff()
	}

	app.lastTick = now
}

// start starts an operation of kind in the background, which replaces any
// running one. The replaced operation is cancelled and the new one waits for
// it to return, so only one request is made at a time.
func (app *Application) start(kind opKind) {
	prev := app.op
	if prev != nil {
		prev.cancel()
	}

	ctx, cancel := context.WithCancel(app.ctx)
	op := &operation{kind: kind, cancel: cancel, finished: make(chan struct{})}
	app.op = op

	go func() {
		defer cancel()

		if prev != nil {
			<-prev.finished
		}

		var err error
		switch kind {
		case opRefresh:
			err = app.identity.Obtain(ctx, identity.WithoutInteractiveLogin)
		case opLogin:
			err = app.refreshOrLogin(ctx)
		}

		close(op.finished)
		app.opDone <- opResult{op: op, err: err}
	}()
}

// finish handles the result of an operation
func (app *Application) finish(res opResult) {
	if res.op != app.op {
		// it was replaced, and its result is not wanted
		return
	}
	app.op = nil

	switch res.op.kind {
	case opRefresh:
		app.refreshDone(res.err)
	case opLogin:
		app.loginDone(res.err)
	}
}

// refreshDone handles the result of an automatic refresh
func (app *Application) refreshDone(err error) {
	switch {
	case errors.Is(err, context.Canceled):
		// quitting
		return
	case !obtained(err):
		if errors.Is(err, auth.ErrInteractiveLoginRequired) {
			app.loginRequired = true
		}
		app.backOff()
		app.logger.Warn("could not refresh certificate", "error", err, "failures", app.failures, "next_attempt", app.nextRefresh)

		return
	case !app.usable():
		app.backOff()

		return
	}

	app.obtainedCertificate()

	if err != nil {
		app.logger.Warn("certificate refreshed but could not be added to the SSH agent", "error", err)
		app.notify("Warning", "The certificate was refreshed but could not be added to the local SSH Authentication Agent", warningIcon)

		return
	}

	app.logger.Info("refresh of certificate succeeded")
	app.notify("Certificate Refreshed", "The current certificate was successfully refreshed", okIcon)
}

// loginDone handles the result of a refresh or login from the menu
func (app *Application) loginDone(err error) {
	switch {
	case errors.Is(err, context.Canceled):
		app.logger.Info("getting a certificate was cancelled")

		return
	case !obtained(err):
		app.logger.Error("could not get a certificate", "error", err)
		app.notify("Error", "Getting a new certificate failed", errorIcon)

		return
	case !app.usable():
		app.backOff()
		app.notify("Warning", "A new certificate was issued but it has expired or is about to. Check the system clock is correct.", warningIcon)

		return
	}

	app.obtainedCertificate()

	if err != nil {
		app.logger.Warn("certificate issued but could not add to agent", "error", err)
		app.notify("Warning", "A new certificate was issued but could not added to the local SSH Authentication Agent", warningIcon)

		return
	}

	app.notify("Certificate Issued", "A new certificate was issued and added to the local SSH Authentication Agent", okIcon)
}

// usable reports whether the certificate just obtained can be used, which it
// can't be if it has expired or a refresh is already due by the local clock,
// such as when the clock is ahead of the CA's. This is logged, and the caller
// treats it as a failure, so it is not refreshed again straight away.
func (app *Application) usable() bool {
	obs := app.observe()
	if state := deriveState(obs, app.renewAt); state == stateCertificateOK {
		return true
	}

	attrs := []any{"now", obs.now}
	if obs.cert != nil {
		attrs = append(attrs,
			"valid_after", time.Unix(int64(obs.cert.ValidAfter), 0),
			"valid_before", certificateExpiry(obs.cert),
		)
	}
	app.logger.Warn("a certificate was issued but has expired or is due to be refreshed by the local clock, which may be wrong", attrs...)

	return false
}

// obtainedCertificate clears the failures once a certificate is obtained
func (app *Application) obtainedCertificate() {
	app.loginRequired = false
	app.resetBackoff()
}

// backOff counts a failure and delays the next automatic refresh
func (app *Application) backOff() {
	app.failures++
	app.nextRefresh = app.now().Add(backoffDelay(app.failures))
}

// resetBackoff clears the failures so the next automatic refresh can start
// straight away
func (app *Application) resetBackoff() {
	app.failures = 0
	app.nextRefresh = time.Time{}
}

// refreshClick starts a refresh or login from the menu, replacing an
// automatic refresh
func (app *Application) refreshClick() {
	if app.state == stateKeyMissing || (app.op != nil && app.op.kind == opLogin) {
		// the menu item was disabled
		return
	}

	app.logger.Info("getting a certificate from the menu")
	app.start(opLogin)
}

// generateClick generates a private key
func (app *Application) generateClick() {
	if app.state != stateKeyMissing {
		// the menu item was disabled
		return
	}

	app.mGenerate.Disable()

	if err := app.identity.GeneratePrivateKey(); err != nil {
		app.logger.Error("could not generate private key", "error", err)
		app.notify("Error", "The generation of a private key failed", errorIcon)

		return
	}

	app.notify("Key Generated", "A private key was successfully generated", okIcon)
}

// quit cancels any operation, waits a short time for it to stop, and quits
// the system tray
func (app *Application) quit() {
	app.logger.Info("application shutting down")
	app.cancel()

	if app.op != nil {
		select {
		case <-app.op.finished:
		case <-time.After(app.quitWait):
			app.logger.Warn("quitting before the current operation stopped")
		}
	}

	app.quitTray()
}

// refreshOrLogin tries a refresh first and falls back to a login. If the
// certificate was issued but could not be added to the SSH agent, the error
// wraps [cert.ErrAddingToAgent] and no login is started.
func (app *Application) refreshOrLogin(ctx context.Context) error {
	err := app.identity.Obtain(ctx, identity.WithoutInteractiveLogin)
	if obtained(err) || errors.Is(err, context.Canceled) {
		return err
	}

	app.logger.Warn("could not perform a refresh, starting a login", "error", err)

	return app.identity.Obtain(ctx)
}

// obtained reports whether err, from obtaining a certificate, means a new
// certificate was issued and saved. One that could not be added to the SSH
// agent was still issued, and the error wraps [cert.ErrAddingToAgent].
func obtained(err error) bool {
	return err == nil || errors.Is(err, cert.ErrAddingToAgent)
}

func (app *Application) getIcon(icon string) []byte {
	// grab icon
	b, ok := app.notificationIcons[icon]
	if !ok {
		return app.notificationIcons[defaultIcon]
	}

	return b
}

func timeLeft(t, now time.Time) string {
	timeLeft := t.Sub(now)
	return fmt.Sprintf("%02dh%02dm", int(timeLeft.Hours()), int(timeLeft.Minutes())%60)
}

// setStatus sets the tray tooltip to show message
func (app *Application) setStatus(message string) {
	tooltip := fmt.Sprintf("SSH CA Client (%s) - %s", version.Version(), message)
	app.setTooltip(tooltip)
}
