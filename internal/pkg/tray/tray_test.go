//go:build windows || linux

package tray

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/identity"
	"golang.org/x/crypto/ssh"
)

// testClock is a clock that only moves when told to
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

// fakeIdentity is an [Identity] that records each request. A request
// without [identity.WithoutInteractiveLogin] fails with interactiveErr,
// otherwise with refreshErr. Successful requests store a certificate valid
// for validFor from now, by a CA clock skew behind the local one, and, unless [identity.WithoutAgent] is given, add it
// to the agent, which fails with agentErr.
type fakeIdentity struct {
	mu             sync.Mutex
	now            func() time.Time
	hasKey         bool
	cert           *ssh.Certificate
	agentErr       error
	agentAdds      int
	generated      int
	genErr         error
	refreshErr     error
	interactiveErr error
	validFor       time.Duration
	skew           time.Duration
	block          bool // block interactive requests until ctx is done
	requests       []bool
}

func (c *fakeIdentity) HasPrivateKey() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.hasKey
}

func (c *fakeIdentity) Certificate() (*ssh.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cert == nil {
		return nil, cert.ErrCertificateNotFound
	}

	return c.cert, nil
}

func (c *fakeIdentity) GeneratePrivateKey() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.generated++
	if c.genErr != nil {
		return c.genErr
	}
	c.hasKey = true
	c.cert = nil

	return nil
}

func (c *fakeIdentity) Obtain(ctx context.Context, opts ...identity.ObtainOption) error {
	nonInteractive := slices.Contains(opts, identity.WithoutInteractiveLogin)

	c.mu.Lock()
	c.requests = append(c.requests, nonInteractive)
	err, block := c.interactiveErr, c.block
	if nonInteractive {
		err, block = c.refreshErr, false
	}
	c.mu.Unlock()

	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now().Add(-c.skew)
	c.cert = &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(c.validFor).Unix())}

	if slices.Contains(opts, identity.WithoutAgent) {
		return nil
	}

	c.agentAdds++
	if c.agentErr != nil {
		return fmt.Errorf("certificate issued but %w", c.agentErr)
	}

	return nil
}

// set changes the fake while operations may be running
func (c *fakeIdentity) set(f func(c *fakeIdentity)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	f(c)
}

// requestKinds returns whether each request was non-interactive
func (c *fakeIdentity) requestKinds() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]bool(nil), c.requests...)
}

// fakeMenuItem is a [menuItem] that records its current title and whether it
// is enabled
type fakeMenuItem struct {
	title   string
	enabled bool
}

func (m *fakeMenuItem) SetTitle(title string) { m.title = title }
func (m *fakeMenuItem) Enable()               { m.enabled = true }
func (m *fakeMenuItem) Disable()              { m.enabled = false }

// fakeTray records what the application shows in the system tray and the
// desktop notifications it sends. Each icon is its own name so the current
// icon can be compared by name.
type fakeTray struct {
	refresh, generate, expiry fakeMenuItem

	icon          string
	tooltip       string
	notifications []string
	quit          bool
}

// newTestApp returns an Application using a fake identity, system tray and
// clock
func newTestApp(t *testing.T) (*Application, *fakeIdentity, *fakeTray, *testClock) {
	t.Helper()

	clock := &testClock{t: time.Now()}
	c := &fakeIdentity{hasKey: true, validFor: 24 * time.Hour, now: clock.now}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	icons := map[string][]byte{
		okIcon:      []byte(okIcon),
		warningIcon: []byte(warningIcon),
		errorIcon:   []byte(errorIcon),
	}

	tray := &fakeTray{}
	app := &Application{
		identity:          c,
		ctx:               ctx,
		cancel:            cancel,
		logger:            slog.New(slog.DiscardHandler),
		now:               clock.now,
		opDone:            make(chan opResult, 2),
		quitWait:          defaultQuitWait,
		renewAt:           time.Hour,
		state:             stateInit,
		trayIcons:         icons,
		notificationIcons: icons,
		mRefresh:          &tray.refresh,
		mGenerate:         &tray.generate,
		mExpiry:           &tray.expiry,
		setIcon:           func(icon []byte) { tray.icon = string(icon) },
		setTooltip:        func(tooltip string) { tray.tooltip = tooltip },
		quitTray:          func() { tray.quit = true },
		notifier: func(title, message string, icon any) error {
			tray.notifications = append(tray.notifications, title)
			return nil
		},
	}

	return app, c, tray, clock
}

// settle runs the event loop's work without its goroutine: it updates, and
// handles the result of each operation started, until no operation runs
func settle(t *testing.T, app *Application) {
	t.Helper()

	for range 10 {
		app.update()
		if app.op == nil {
			return
		}
		wait(t, app)
	}

	t.Fatal("operations were still being started after 10 updates")
}

// wait handles the result of the current operation
func wait(t *testing.T, app *Application) {
	t.Helper()

	select {
	case res := <-app.opDone:
		app.finish(res)
	case <-time.After(5 * time.Second):
		t.Fatal("the operation did not finish")
	}
}

// expiresIn returns a certificate issued a day before it expires after d
func expiresIn(d time.Duration) *ssh.Certificate {
	return issued(24*time.Hour, d)
}

// issued returns a certificate with a lifetime of life that expires after d
func issued(life, d time.Duration) *ssh.Certificate {
	expiry := time.Now().Add(d)

	return &ssh.Certificate{
		ValidAfter:  uint64(expiry.Add(-life).Unix()),
		ValidBefore: uint64(expiry.Unix()),
	}
}

func TestCertificateExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		cert *ssh.Certificate
		want time.Time
	}{
		{"expires", &ssh.Certificate{ValidBefore: uint64(now.Unix())}, time.Unix(now.Unix(), 0)},
		{"never expires", &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}, time.Unix(1<<62, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certificateExpiry(tt.cert); !got.Equal(tt.want) {
				t.Errorf("certificateExpiry() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRefreshDue(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		cert    *ssh.Certificate
		renewAt time.Duration
		want    bool
	}{
		{"most of lifetime left", issued(24*time.Hour, 23*time.Hour), time.Hour, false},
		{"less than renewAt left", issued(24*time.Hour, 30*time.Minute), time.Hour, true},
		{"expired", issued(24*time.Hour, -time.Minute), time.Hour, true},
		{"lifetime shorter than renewAt, more than half left", issued(30*time.Minute, 25*time.Minute), time.Hour, false},
		{"lifetime shorter than renewAt, less than half left", issued(30*time.Minute, 10*time.Minute), time.Hour, true},
		{"lifetime equal to renewAt, just issued", issued(time.Hour, 59*time.Minute), time.Hour, false},
		{"never expires", &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}, time.Hour, false},
		{"no valid after", &ssh.Certificate{ValidBefore: uint64(now.Add(30 * time.Minute).Unix())}, time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refreshDue(tt.cert, now, tt.renewAt); got != tt.want {
				t.Errorf("refreshDue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeriveState(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name string
		obs  observation
		want appState
	}{
		{"no key", observation{now: now}, stateKeyMissing},
		{"no key with a certificate", observation{cert: expiresIn(time.Hour), now: now}, stateKeyMissing},
		{"no certificate", observation{hasKey: true, now: now}, stateCertificateMissing},
		{"valid", observation{hasKey: true, cert: expiresIn(23 * time.Hour), now: now}, stateCertificateOK},
		{"never expires", observation{hasKey: true, cert: &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}, now: now}, stateCertificateOK},
		{"due", observation{hasKey: true, cert: expiresIn(30 * time.Minute), now: now}, stateCertificateDue},
		{"expired", observation{hasKey: true, cert: expiresIn(-time.Minute), now: now}, stateCertificateExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveState(tt.obs, time.Hour); got != tt.want {
				t.Errorf("deriveState() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{0, 0},
		{1, 2 * time.Minute},
		{2, 4 * time.Minute},
		{15, 30 * time.Minute},
		{100, 30 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.failures), func(t *testing.T) {
			if got := backoffDelay(tt.failures); got != tt.want {
				t.Errorf("backoffDelay(%d) = %v, want %v", tt.failures, got, tt.want)
			}
		})
	}
}

func TestSuspended(t *testing.T) {
	last := time.Now()

	tests := []struct {
		name  string
		after time.Duration
		want  bool
	}{
		{"one tick", time.Minute, false},
		{"a late tick", 2 * time.Minute, false},
		{"suspended", 10 * time.Minute, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := suspended(last, last.Add(tt.after)); got != tt.want {
				t.Errorf("suspended() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplication_update(t *testing.T) {
	refreshErr := errors.New("refresh failed")

	tests := []struct {
		name string

		// starting conditions
		noKey      bool
		cert       *ssh.Certificate
		refreshErr error
		validFor   time.Duration // validity of an issued certificate

		wantState         appState
		wantRequests      int
		wantNotifications []string
		wantIcon          string
		wantRefresh       fakeMenuItem
		wantGenerate      bool
		wantExpiry        string // suffix of the expiry menu item title
		wantTooltip       string // suffix of the tooltip
	}{
		{
			name:         "no private key",
			noKey:        true,
			wantState:    stateKeyMissing,
			wantIcon:     errorIcon,
			wantRefresh:  fakeMenuItem{refreshTitle, false},
			wantGenerate: true,
			wantExpiry:   "No certificate",
			wantTooltip:  "No private key found",
		},
		{
			name:        "no certificate",
			wantState:   stateCertificateMissing,
			wantIcon:    warningIcon,
			wantRefresh: fakeMenuItem{loginTitle, true},
			wantExpiry:  "No certificate",
			wantTooltip: "No certificate found",
		},
		{
			name:        "valid certificate",
			cert:        expiresIn(23 * time.Hour),
			wantState:   stateCertificateOK,
			wantIcon:    okIcon,
			wantRefresh: fakeMenuItem{refreshTitle, true},
			wantExpiry:  " left",
			wantTooltip: "Current certificate valid",
		},
		{
			name:              "expired is refreshed",
			cert:              expiresIn(-time.Hour),
			wantState:         stateCertificateOK,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Refreshed"},
			wantIcon:          okIcon,
			wantRefresh:       fakeMenuItem{refreshTitle, true},
			wantExpiry:        " left",
			wantTooltip:       "Current certificate valid",
		},
		{
			name:              "expired and refresh fails",
			cert:              expiresIn(-time.Hour),
			refreshErr:        refreshErr,
			wantState:         stateCertificateExpired,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Expired"},
			wantIcon:          warningIcon,
			wantRefresh:       fakeMenuItem{refreshTitle, true},
			wantExpiry:        "Certificate expired",
			wantTooltip:       "Certificate expired",
		},
		{
			name:              "expired and login required",
			cert:              expiresIn(-time.Hour),
			refreshErr:        fmt.Errorf("%w: no refresh token available", auth.ErrInteractiveLoginRequired),
			wantState:         stateCertificateExpired,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Expired"},
			wantIcon:          warningIcon,
			wantRefresh:       fakeMenuItem{loginTitle, true},
			wantExpiry:        "Certificate expired",
			wantTooltip:       "Certificate expired",
		},
		{
			name:              "close to expiry is refreshed",
			cert:              expiresIn(30 * time.Minute),
			wantState:         stateCertificateOK,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Refreshed"},
			wantIcon:          okIcon,
			wantRefresh:       fakeMenuItem{refreshTitle, true},
			wantExpiry:        " left",
			wantTooltip:       "Current certificate valid",
		},
		{
			name:         "close to expiry and refresh fails",
			cert:         expiresIn(30 * time.Minute),
			refreshErr:   refreshErr,
			wantState:    stateCertificateDue,
			wantRequests: 1,
			wantIcon:     okIcon,
			wantRefresh:  fakeMenuItem{refreshTitle, true},
			wantExpiry:   " left",
			wantTooltip:  "Current certificate valid",
		},
		{
			name:         "close to expiry and login required",
			cert:         expiresIn(30 * time.Minute),
			refreshErr:   fmt.Errorf("%w: no refresh token available", auth.ErrInteractiveLoginRequired),
			wantState:    stateCertificateDue,
			wantRequests: 1,
			wantIcon:     okIcon,
			wantRefresh:  fakeMenuItem{loginTitle, true},
			wantExpiry:   " left",
			wantTooltip:  "Current certificate valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray, _ := newTestApp(t)
			c.hasKey = !tt.noKey
			c.cert = tt.cert
			c.refreshErr = tt.refreshErr
			if tt.validFor != 0 {
				c.validFor = tt.validFor
			}

			settle(t, app)

			if app.state != tt.wantState {
				t.Errorf("state = %s, want %s", app.state, tt.wantState)
			}

			// automatic requests run unattended so must never start a login
			requests := c.requestKinds()
			if len(requests) != tt.wantRequests {
				t.Errorf("%d requests made, want %d", len(requests), tt.wantRequests)
			}
			for i, nonInteractive := range requests {
				if !nonInteractive {
					t.Errorf("request %d was interactive", i)
				}
			}

			if fmt.Sprint(tray.notifications) != fmt.Sprint(tt.wantNotifications) {
				t.Errorf("notifications = %q, want %q", tray.notifications, tt.wantNotifications)
			}
			if tray.icon != tt.wantIcon {
				t.Errorf("icon = %q, want %q", tray.icon, tt.wantIcon)
			}
			if tray.refresh != tt.wantRefresh {
				t.Errorf("refresh menu item = %+v, want %+v", tray.refresh, tt.wantRefresh)
			}
			if tray.generate.enabled != tt.wantGenerate {
				t.Errorf("generate menu item enabled = %v, want %v", tray.generate.enabled, tt.wantGenerate)
			}
			if !strings.HasSuffix(tray.expiry.title, tt.wantExpiry) {
				t.Errorf("expiry menu item = %q, want suffix %q", tray.expiry.title, tt.wantExpiry)
			}
			if !strings.HasSuffix(tray.tooltip, tt.wantTooltip) {
				t.Errorf("tooltip = %q, want suffix %q", tray.tooltip, tt.wantTooltip)
			}
		})
	}
}

// TestApplication_update_changedElsewhere checks that a key or certificate
// added or removed elsewhere, such as by the CLI, is picked up
func TestApplication_update_changedElsewhere(t *testing.T) {
	tests := []struct {
		name   string
		before func(c *fakeIdentity)
		after  func(c *fakeIdentity)
		want   appState
	}{
		{"key generated", func(c *fakeIdentity) { c.hasKey = false }, func(c *fakeIdentity) { c.hasKey = true }, stateCertificateMissing},
		{"key removed", func(c *fakeIdentity) { c.cert = expiresIn(23 * time.Hour) }, func(c *fakeIdentity) { c.hasKey = false }, stateKeyMissing},
		{"certificate issued", func(c *fakeIdentity) {}, func(c *fakeIdentity) { c.cert = expiresIn(23 * time.Hour) }, stateCertificateOK},
		{"certificate removed", func(c *fakeIdentity) { c.cert = expiresIn(23 * time.Hour) }, func(c *fakeIdentity) { c.cert = nil }, stateCertificateMissing},
		{"expired certificate renewed", func(c *fakeIdentity) {
			c.cert = expiresIn(-time.Hour)
			c.refreshErr = errors.New("refresh failed")
		}, func(c *fakeIdentity) { c.cert = expiresIn(23 * time.Hour) }, stateCertificateOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, _, _ := newTestApp(t)
			tt.before(c)
			settle(t, app)

			tt.after(c)
			settle(t, app)

			if app.state != tt.want {
				t.Errorf("state = %s, want %s", app.state, tt.want)
			}
		})
	}
}

// limitedIdentity fails every request after the first max, so a test of a
// loop that keeps requesting certificates ends
type limitedIdentity struct {
	*fakeIdentity
	max int
}

func (l *limitedIdentity) Obtain(ctx context.Context, opts ...identity.ObtainOption) error {
	if len(l.requestKinds()) >= l.max {
		l.mu.Lock()
		l.requests = append(l.requests, slices.Contains(opts, identity.WithoutInteractiveLogin))
		l.mu.Unlock()

		return errors.New("request limit reached")
	}

	return l.fakeIdentity.Obtain(ctx, opts...)
}

// TestApplication_refreshNotUsable checks that a refresh which issues a
// certificate that is already expired or due by the local clock, such as when
// the clock is ahead of the CA, is treated as a failure rather than refreshed
// again straight away, which looped, sending a request and a notification
// each time
func TestApplication_refreshNotUsable(t *testing.T) {
	tests := []struct {
		name string
		cert *ssh.Certificate
		skew time.Duration // how far the local clock is ahead of the CA's
	}{
		{"expired, issued expired", expiresIn(-time.Hour), 25 * time.Hour},
		{"expired, issued due", expiresIn(-time.Hour), 23*time.Hour + 30*time.Minute},
		{"due, issued expired", expiresIn(30 * time.Minute), 25 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray, _ := newTestApp(t)
			app.identity = &limitedIdentity{c, 20}
			c.cert = tt.cert
			c.skew = tt.skew

			settle(t, app)
			settle(t, app)

			if got := len(c.requestKinds()); got != 1 {
				t.Errorf("%d requests made, want 1", got)
			}
			if slices.Contains(tray.notifications, "Certificate Refreshed") {
				t.Errorf("notifications = %q, want no %q", tray.notifications, "Certificate Refreshed")
			}
			if app.failures != 1 {
				t.Errorf("failures = %d, want 1", app.failures)
			}
		})
	}
}

// TestApplication_refreshShortLifetime checks that a certificate with less
// than renewAt of lifetime, such as when --life equals --refresh-before or the
// CA issues a shorter lifetime than requested, is not refreshed again as soon
// as it is issued, which refreshed it on every tick
func TestApplication_refreshShortLifetime(t *testing.T) {
	t.Run("refreshed once from expired", func(t *testing.T) {
		app, c, tray, _ := newTestApp(t)
		c.cert = expiresIn(-time.Hour)
		c.validFor = 30 * time.Minute

		settle(t, app)

		if got := len(c.requestKinds()); got != 1 {
			t.Errorf("%d requests made, want 1", got)
		}
		if want := []string{"Certificate Refreshed"}; !slices.Equal(tray.notifications, want) {
			t.Errorf("notifications = %q, want %q", tray.notifications, want)
		}
	})

	t.Run("not refreshed every tick", func(t *testing.T) {
		app, c, _, clock := newTestApp(t)
		c.cert = issued(30*time.Minute, 25*time.Minute)
		c.validFor = 30 * time.Minute

		for range 5 {
			settle(t, app)
			clock.add(time.Minute)
		}

		if got := len(c.requestKinds()); got != 0 {
			t.Errorf("%d requests made, want 0", got)
		}
	})
}

// TestApplication_backoff checks that failed automatic refreshes wait twice
// the number of failures in minutes before the next
func TestApplication_backoff(t *testing.T) {
	app, c, _, clock := newTestApp(t)
	c.cert = expiresIn(30 * time.Minute)
	c.refreshErr = errors.New("refresh failed")

	// minutes from the start, and the requests made by then
	steps := []struct {
		at   time.Duration
		want int
	}{
		{0, 1},
		{time.Minute, 1},
		{2 * time.Minute, 2},
		{5 * time.Minute, 2},
		{6 * time.Minute, 3},
		{11 * time.Minute, 3},
		{12 * time.Minute, 4},
	}
	start := clock.now()
	for _, step := range steps {
		clock.add(start.Add(step.at).Sub(clock.now()))
		settle(t, app)

		if got := len(c.requestKinds()); got != step.want {
			t.Fatalf("after %v: %d requests made, want %d", step.at, got, step.want)
		}
		if app.state != stateCertificateDue {
			t.Fatalf("after %v: state = %s, want %s", step.at, app.state, stateCertificateDue)
		}
	}

	// clicks and other updates don't use up the wait
	for range 10 {
		settle(t, app)
	}
	if got := len(c.requestKinds()); got != 4 {
		t.Errorf("%d requests made by updates during the wait, want 4", got)
	}
}

// TestApplication_resume checks that a suspend found by the ticks resets the
// backoff, as the network may only have been down until the resume (#223)
func TestApplication_resume(t *testing.T) {
	tests := []struct {
		name      string
		gap       time.Duration
		wantReset bool
	}{
		{"next tick", tickInterval, false},
		{"after a suspend", time.Hour, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, _, clock := newTestApp(t)
			c.cert = expiresIn(-time.Hour)
			c.refreshErr = errors.New("dial tcp: network is unreachable")
			for range 5 {
				app.backOff()
			}

			now := clock.now()
			app.tick(now)
			c.set(func(c *fakeIdentity) { c.refreshErr = nil })
			app.tick(now.Add(tt.gap))
			settle(t, app)

			if got := len(c.requestKinds()) == 1; got != tt.wantReset {
				t.Errorf("refreshed = %v, want %v", got, tt.wantReset)
			}
		})
	}
}

// TestApplication_expiredRetry checks that an expired certificate is
// refreshed once a refresh works again, such as when the network comes up
// after a resume or at logon, rather than staying expired until the user
// gets one from the menu (#223)
func TestApplication_expiredRetry(t *testing.T) {
	app, c, tray, clock := newTestApp(t)
	c.cert = expiresIn(-time.Minute)
	c.refreshErr = errors.New("dial tcp: network is unreachable")

	settle(t, app)
	if app.state != stateCertificateExpired {
		t.Fatalf("state after failed refresh = %s, want %s", app.state, stateCertificateExpired)
	}

	// the network comes back and the refresh token still works
	c.refreshErr = nil
	for range 10 {
		clock.add(time.Minute)
		settle(t, app)
	}

	if app.state != stateCertificateOK {
		t.Fatalf("state = %s, want %s", app.state, stateCertificateOK)
	}
	for _, nonInteractive := range c.requestKinds() {
		if !nonInteractive {
			t.Errorf("requests = %v, want only refreshes, which need no login", c.requestKinds())
			break
		}
	}
	// the user is told it expired once, and then that it was refreshed
	want := []string{"Certificate Expired", "Certificate Refreshed"}
	if !slices.Equal(tray.notifications, want) {
		t.Errorf("notifications = %q, want %q", tray.notifications, want)
	}
}

// TestApplication_expiredNotifiedOnce checks that refreshes of an expired
// certificate that keep failing only tell the user once that it expired
func TestApplication_expiredNotifiedOnce(t *testing.T) {
	app, c, tray, clock := newTestApp(t)
	c.cert = expiresIn(-time.Minute)
	c.refreshErr = errors.New("refresh failed")

	for range 30 {
		settle(t, app)
		clock.add(time.Minute)
	}

	if got := len(c.requestKinds()); got < 3 {
		t.Errorf("%d requests made, want at least 3", got)
	}
	if want := []string{"Certificate Expired"}; !slices.Equal(tray.notifications, want) {
		t.Errorf("notifications = %q, want %q", tray.notifications, want)
	}
}

// TestApplication_refreshAgentError checks that an automatic refresh that
// issues a certificate but can't add it to the SSH agent counts as a refresh:
// the user is warned about the agent rather than told the certificate
// expired, and no failure is counted towards the backoff (#222)
func TestApplication_refreshAgentError(t *testing.T) {
	tests := []struct {
		name string
		cert *ssh.Certificate
	}{
		{"expired", expiresIn(-time.Minute)},
		{"close to expiry", expiresIn(30 * time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray, _ := newTestApp(t)
			c.cert = tt.cert
			c.agentErr = cert.ErrAddingToAgent
			app.backOff()
			app.nextRefresh = time.Time{}

			settle(t, app)

			if app.state != stateCertificateOK {
				t.Errorf("state = %s, want %s", app.state, stateCertificateOK)
			}
			if want := []string{"Warning"}; !slices.Equal(tray.notifications, want) {
				t.Errorf("notifications = %q, want %q", tray.notifications, want)
			}
			if app.failures != 0 || !app.nextRefresh.IsZero() {
				t.Errorf("failures = %d, next refresh = %v, want 0 and zero", app.failures, app.nextRefresh)
			}
			if got := len(c.requestKinds()); got != 1 {
				t.Errorf("%d requests made, want 1", got)
			}
		})
	}
}

func TestApplication_refreshOrLogin(t *testing.T) {
	loginErr := errors.New("login failed")

	tests := []struct {
		name         string
		refreshErr   error
		agentErr     error
		loginErr     error
		wantErr      error
		wantRequests []bool
	}{
		{
			name:         "refresh succeeds",
			wantRequests: []bool{true},
		},
		{
			name:         "falls back to login",
			refreshErr:   auth.ErrInteractiveLoginRequired,
			wantRequests: []bool{true, false},
		},
		{
			name:         "login fails",
			refreshErr:   auth.ErrInteractiveLoginRequired,
			loginErr:     loginErr,
			wantErr:      loginErr,
			wantRequests: []bool{true, false},
		},
		{
			name:         "no login when only adding to agent failed",
			agentErr:     cert.ErrAddingToAgent,
			wantErr:      cert.ErrAddingToAgent,
			wantRequests: []bool{true},
		},
		{
			name:         "no login when cancelled",
			refreshErr:   context.Canceled,
			wantErr:      context.Canceled,
			wantRequests: []bool{true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, _, _ := newTestApp(t)
			c.refreshErr, c.interactiveErr, c.agentErr = tt.refreshErr, tt.loginErr, tt.agentErr

			err := app.refreshOrLogin(context.Background())
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("refreshOrLogin() error = %v, want %v", err, tt.wantErr)
			}

			got := c.requestKinds()
			if fmt.Sprint(got) != fmt.Sprint(tt.wantRequests) {
				t.Errorf("requests (non-interactive) = %v, want %v", got, tt.wantRequests)
			}
		})
	}
}

// TestApplication_login checks the result of getting a certificate from the
// menu
func TestApplication_login(t *testing.T) {
	loginErr := errors.New("login failed")

	tests := []struct {
		name          string
		refreshErr    error
		loginErr      error
		agentErr      error
		skew          time.Duration
		loginRequired bool

		wantNotifications []string
		wantFailures      int
		wantLoginRequired bool
		wantRefreshTitle  string
	}{
		{
			name:              "issued",
			refreshErr:        auth.ErrInteractiveLoginRequired,
			loginRequired:     true,
			wantNotifications: []string{"Certificate Issued"},
			wantRefreshTitle:  refreshTitle,
		},
		{
			name:              "issued but not added to agent",
			agentErr:          cert.ErrAddingToAgent,
			wantNotifications: []string{"Warning"},
			wantRefreshTitle:  refreshTitle,
		},
		{
			name:              "fails",
			refreshErr:        auth.ErrInteractiveLoginRequired,
			loginErr:          loginErr,
			loginRequired:     true,
			wantNotifications: []string{"Error"},
			wantLoginRequired: true,
			wantRefreshTitle:  loginTitle,
		},
		{
			name:              "issued expired by the local clock",
			skew:              25 * time.Hour,
			wantNotifications: []string{"Warning", "Certificate Expired"},
			wantFailures:      1,
			wantRefreshTitle:  refreshTitle,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray, _ := newTestApp(t)
			c.cert = expiresIn(23 * time.Hour)
			c.refreshErr, c.interactiveErr, c.agentErr = tt.refreshErr, tt.loginErr, tt.agentErr
			c.skew = tt.skew
			app.loginRequired = tt.loginRequired
			settle(t, app)

			app.refreshClick()
			app.update()
			if tray.refresh.enabled {
				t.Error("refresh menu item enabled while getting a certificate from the menu")
			}
			wait(t, app)
			settle(t, app)

			if !slices.Equal(tray.notifications, tt.wantNotifications) {
				t.Errorf("notifications = %q, want %q", tray.notifications, tt.wantNotifications)
			}
			if app.failures != tt.wantFailures {
				t.Errorf("failures = %d, want %d", app.failures, tt.wantFailures)
			}
			if app.loginRequired != tt.wantLoginRequired {
				t.Errorf("loginRequired = %v, want %v", app.loginRequired, tt.wantLoginRequired)
			}
			if tray.refresh.title != tt.wantRefreshTitle {
				t.Errorf("refresh menu item title = %q, want %q", tray.refresh.title, tt.wantRefreshTitle)
			}
		})
	}
}

func TestApplication_generateClick(t *testing.T) {
	tests := []struct {
		name              string
		hasKey            bool
		genErr            error
		wantGenerated     int
		wantNotifications []string
		wantState         appState
	}{
		{"generated", false, nil, 1, []string{"Key Generated"}, stateCertificateMissing},
		{"fails", false, errors.New("keyring locked"), 1, []string{"Error"}, stateKeyMissing},
		{"key already present", true, nil, 0, nil, stateCertificateMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray, _ := newTestApp(t)
			c.hasKey = tt.hasKey
			c.genErr = tt.genErr
			settle(t, app)

			app.generateClick()
			settle(t, app)

			if c.generated != tt.wantGenerated {
				t.Errorf("GeneratePrivateKey() called %d times, want %d", c.generated, tt.wantGenerated)
			}
			if !slices.Equal(tray.notifications, tt.wantNotifications) {
				t.Errorf("notifications = %q, want %q", tray.notifications, tt.wantNotifications)
			}
			if app.state != tt.wantState {
				t.Errorf("state = %s, want %s", app.state, tt.wantState)
			}
		})
	}
}

// slowIdentity makes a refresh take as long as a network round trip, as a
// real one does
type slowIdentity struct {
	*fakeIdentity
	delay time.Duration
}

func (s *slowIdentity) Obtain(ctx context.Context, opts ...identity.ObtainOption) error {
	if slices.Contains(opts, identity.WithoutInteractiveLogin) {
		time.Sleep(s.delay)
	}

	return s.fakeIdentity.Obtain(ctx, opts...)
}

// TestApplication_eventloop_refreshNearExpiry checks that clicking Refresh
// while the certificate is close to expiry gets a new one. The automatic
// refresh that runs after the click used to take the lock first, so the
// request from the menu failed (#224).
func TestApplication_eventloop_refreshNearExpiry(t *testing.T) {
	for i := range 30 {
		app, c, _, _ := newTestApp(t)
		app.identity = &slowIdentity{c, 20 * time.Millisecond}
		c.cert = expiresIn(2 * time.Hour)
		// background refreshes fail, so the click falls back to a login
		c.refreshErr = errors.New("refresh token expired")

		refresh := make(chan struct{})
		app.refreshClicked = refresh

		// the first update of the event loop has finished once the tooltip
		// is set
		ready := make(chan struct{}, 1)
		app.setTooltip = func(string) {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
		result := make(chan string, 8)
		app.notifier = func(title, message string, icon any) error {
			result <- title
			return nil
		}

		// the event loop is left running until the test ends
		go app.eventloop(nil)
		<-ready

		// the certificate is now within renewAt, so an automatic refresh
		// is due
		c.set(func(c *fakeIdentity) { c.cert = expiresIn(30 * time.Minute) })
		refresh <- struct{}{}

		select {
		case got := <-result:
			if got != "Certificate Issued" {
				t.Fatalf("run %d: notification = %q, want %q", i+1, got, "Certificate Issued")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("run %d: getting a certificate did not finish", i+1)
		}
	}
}

// blockingIdentity blocks the first refresh until ctx is done, as one does
// while a network that is down times out
type blockingIdentity struct {
	*fakeIdentity
	started chan struct{}
	once    sync.Once
}

func (b *blockingIdentity) Obtain(ctx context.Context, opts ...identity.ObtainOption) error {
	first := false
	if slices.Contains(opts, identity.WithoutInteractiveLogin) {
		b.once.Do(func() { first = true })
	}
	if !first {
		return b.fakeIdentity.Obtain(ctx, opts...)
	}

	b.started <- struct{}{}
	<-ctx.Done()

	return ctx.Err()
}

// click sends a click to ch the way the system tray does, which drops it if
// the event loop is not waiting for it. The user clicks again a few times.
func click(ch chan<- struct{}) bool {
	for range 50 {
		select {
		case ch <- struct{}{}:
			return true
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	return false
}

// TestApplication_eventloop_clickDuringRefresh checks that a click is not lost
// while an automatic refresh is waiting on the network, which used to run on
// the event loop
func TestApplication_eventloop_clickDuringRefresh(t *testing.T) {
	app, c, _, _ := newTestApp(t)
	started := make(chan struct{}, 1)
	app.identity = &blockingIdentity{fakeIdentity: c, started: started}
	c.cert = expiresIn(30 * time.Minute)

	quit := make(chan struct{})
	app.quitClicked = quit

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.eventloop(nil)
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no automatic refresh was started")
	}

	if !click(quit) {
		t.Fatal("click on Quit was dropped while an automatic refresh was running")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the event loop did not stop after Quit was clicked")
	}
}

// TestApplication_eventloop_clickReplacesRefresh checks that clicking Refresh
// while an automatic refresh waits on the network cancels it and gets a
// certificate straight away
func TestApplication_eventloop_clickReplacesRefresh(t *testing.T) {
	app, c, _, _ := newTestApp(t)
	started := make(chan struct{}, 1)
	app.identity = &blockingIdentity{fakeIdentity: c, started: started}
	c.cert = expiresIn(30 * time.Minute)
	c.refreshErr = auth.ErrInteractiveLoginRequired

	refresh := make(chan struct{})
	app.refreshClicked = refresh
	result := make(chan string, 8)
	app.notifier = func(title, message string, icon any) error {
		result <- title
		return nil
	}

	go app.eventloop(nil)

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no automatic refresh was started")
	}

	if !click(refresh) {
		t.Fatal("click on Refresh was dropped")
	}

	select {
	case got := <-result:
		if got != "Certificate Issued" {
			t.Fatalf("notification = %q, want %q", got, "Certificate Issued")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("getting a certificate did not finish")
	}

	// the blocked refresh is not recorded by the fake, then the click
	// refreshes and falls back to a login
	if got, want := c.requestKinds(), []bool{true, false}; !slices.Equal(got, want) {
		t.Errorf("requests (non-interactive) = %v, want %v", got, want)
	}
}

// stoppingIdentity takes stop to return from a request once it is cancelled,
// as saving a certificate does
type stoppingIdentity struct {
	*fakeIdentity
	started  chan struct{}
	stop     time.Duration
	returned chan struct{}
}

func (s *stoppingIdentity) Obtain(ctx context.Context, opts ...identity.ObtainOption) error {
	s.started <- struct{}{}
	<-ctx.Done()
	time.Sleep(s.stop)
	close(s.returned)

	return ctx.Err()
}

// TestApplication_eventloop_quit checks that quitting cancels the current
// operation and waits a short time for it to return
func TestApplication_eventloop_quit(t *testing.T) {
	tests := []struct {
		name         string
		stop         time.Duration
		wantReturned bool
	}{
		{"waits for the operation", 100 * time.Millisecond, true},
		{"gives up waiting", time.Second, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, _, _ := newTestApp(t)
			id := &stoppingIdentity{c, make(chan struct{}, 1), tt.stop, make(chan struct{})}
			app.identity = id
			app.quitWait = 500 * time.Millisecond
			c.cert = expiresIn(30 * time.Minute)

			quit := make(chan struct{})
			app.quitClicked = quit
			quitTray := make(chan bool, 1)
			app.quitTray = func() {
				select {
				case <-id.returned:
					quitTray <- true
				default:
					quitTray <- false
				}
			}

			go app.eventloop(nil)

			select {
			case <-id.started:
			case <-time.After(5 * time.Second):
				t.Fatal("no automatic refresh was started")
			}

			quit <- struct{}{}

			select {
			case returned := <-quitTray:
				if returned != tt.wantReturned {
					t.Errorf("operation returned before the system tray quit = %v, want %v", returned, tt.wantReturned)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the system tray was not quit")
			}

			// let the operation finish before the next test
			<-id.returned
		})
	}
}
