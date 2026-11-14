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

// fakeIdentity is an [Identity] that records each request. A request
// without [identity.WithoutInteractiveLogin] fails with interactiveErr,
// otherwise with refreshErr. Successful requests store a certificate valid
// for validFor and, unless [identity.WithoutAgent] is given, add it to the
// agent, which fails with agentErr.
type fakeIdentity struct {
	mu             sync.Mutex
	hasKey         bool
	cert           *ssh.Certificate
	agentErr       error
	agentAdds      int
	generated      int
	genErr         error
	refreshErr     error
	interactiveErr error
	validFor       time.Duration
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

	c.cert = &ssh.Certificate{ValidBefore: uint64(time.Now().Add(c.validFor).Unix())}

	if slices.Contains(opts, identity.WithoutAgent) {
		return nil
	}

	c.agentAdds++
	if c.agentErr != nil {
		return fmt.Errorf("certificate issued but %w", c.agentErr)
	}

	return nil
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
	renew, generate, expiry fakeMenuItem

	icon          string
	tooltip       string
	notifications []string
}

// newTestApp returns an Application using a fake identity and system tray
func newTestApp(t *testing.T) (*Application, *fakeIdentity, *fakeTray) {
	t.Helper()

	c := &fakeIdentity{hasKey: true, validFor: 24 * time.Hour}
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
		renewAt:           time.Hour,
		state:             stateInit,
		trayIcons:         icons,
		notificationIcons: icons,
		mRenew:            &tray.renew,
		mGenerate:         &tray.generate,
		mExpiry:           &tray.expiry,
		setIcon:           func(icon []byte) { tray.icon = string(icon) },
		setTooltip:        func(tooltip string) { tray.tooltip = tooltip },
		notifier: func(title, message string, icon any) error {
			tray.notifications = append(tray.notifications, title)
			return nil
		},
	}

	return app, c, tray
}

func TestApplication_certificateExpiry(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		cert      *ssh.Certificate
		wantValid bool
		wantZero  bool
	}{
		{"no certificate", nil, false, true},
		{"valid", &ssh.Certificate{ValidBefore: uint64(now.Add(time.Hour).Unix())}, true, false},
		{"expired", &ssh.Certificate{ValidBefore: uint64(now.Add(-time.Hour).Unix())}, false, false},
		{"never expires", &ssh.Certificate{ValidBefore: ssh.CertTimeInfinity}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, _ := newTestApp(t)
			c.cert = tt.cert

			if got := app.certificateValid(); got != tt.wantValid {
				t.Errorf("certificateValid() = %v, want %v", got, tt.wantValid)
			}
			if got := app.certificateExpiry().IsZero(); got != tt.wantZero {
				t.Errorf("certificateExpiry().IsZero() = %v, want %v", got, tt.wantZero)
			}
			if got := app.hasCertificate(); got != (tt.cert != nil) {
				t.Errorf("hasCertificate() = %v, want %v", got, tt.cert != nil)
			}
		})
	}

	t.Run("expiry matches certificate", func(t *testing.T) {
		app, c, _ := newTestApp(t)
		want := time.Unix(now.Add(time.Hour).Unix(), 0)
		c.cert = &ssh.Certificate{ValidBefore: uint64(want.Unix())}

		if got := app.certificateExpiry(); !got.Equal(want) {
			t.Errorf("certificateExpiry() = %v, want %v", got, want)
		}
	})
}

func TestApplication_refresh(t *testing.T) {
	t.Run("is non-interactive", func(t *testing.T) {
		app, c, _ := newTestApp(t)

		if err := app.refresh(); err != nil {
			t.Fatalf("refresh() error = %v", err)
		}
		if got := c.requestKinds(); len(got) != 1 || !got[0] {
			t.Errorf("requests (non-interactive) = %v, want [true]", got)
		}
	})

	t.Run("resets backoff on success", func(t *testing.T) {
		app, _, _ := newTestApp(t)
		app.refreshFailure.Store(3)
		app.refreshBackOff.Store(6)

		if err := app.refresh(); err != nil {
			t.Fatalf("refresh() error = %v", err)
		}
		if app.refreshFailure.Load() != 0 || app.refreshBackOff.Load() != 0 {
			t.Errorf("failures = %d, backoff = %d, want 0 and 0", app.refreshFailure.Load(), app.refreshBackOff.Load())
		}
	})

	t.Run("already running", func(t *testing.T) {
		app, c, _ := newTestApp(t)
		app.mu.Lock()
		defer app.mu.Unlock()

		if err := app.refresh(); !errors.Is(err, ErrRenewRunning) {
			t.Errorf("refresh() error = %v, want %v", err, ErrRenewRunning)
		}
		if len(c.requestKinds()) != 0 {
			t.Errorf("request made while a renewal was running")
		}
	})
}

func TestApplication_renew(t *testing.T) {
	t.Run("is interactive", func(t *testing.T) {
		app, c, _ := newTestApp(t)

		if err := app.renew(); err != nil {
			t.Fatalf("renew() error = %v", err)
		}
		if got := c.requestKinds(); len(got) != 1 || got[0] {
			t.Errorf("requests (non-interactive) = %v, want [false]", got)
		}
	})

	t.Run("aborted when application quits", func(t *testing.T) {
		app, c, _ := newTestApp(t)
		c.block = true

		done := make(chan error, 1)
		go func() { done <- app.renew() }()

		app.cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("renew() error = %v, want %v", err, context.Canceled)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("renew() did not return after the application quit")
		}
	})
}

func TestApplication_refreshOrRenew(t *testing.T) {
	interactiveErr := errors.New("login failed")

	tests := []struct {
		name         string
		refreshErr   error
		agentErr     error
		renewErr     error
		wantErr      error
		wantRequests []bool
	}{
		{
			name:         "refresh succeeds",
			wantRequests: []bool{true},
		},
		{
			name:         "falls back to interactive renewal",
			refreshErr:   auth.ErrInteractiveLoginRequired,
			wantRequests: []bool{true, false},
		},
		{
			name:         "interactive renewal fails",
			refreshErr:   auth.ErrInteractiveLoginRequired,
			renewErr:     interactiveErr,
			wantErr:      interactiveErr,
			wantRequests: []bool{true, false},
		},
		{
			name:         "no interactive renewal when only adding to agent failed",
			agentErr:     cert.ErrAddingToAgent,
			wantErr:      cert.ErrAddingToAgent,
			wantRequests: []bool{true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, _ := newTestApp(t)
			c.refreshErr, c.interactiveErr, c.agentErr = tt.refreshErr, tt.renewErr, tt.agentErr

			err := app.refreshOrRenew()
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("refreshOrRenew() error = %v, want %v", err, tt.wantErr)
			}

			got := c.requestKinds()
			if fmt.Sprint(got) != fmt.Sprint(tt.wantRequests) {
				t.Errorf("requests (non-interactive) = %v, want %v", got, tt.wantRequests)
			}
		})
	}
}

func TestApplication_refreshWithBackoff(t *testing.T) {
	app, c, _ := newTestApp(t)
	c.refreshErr = auth.ErrInteractiveLoginRequired

	// first failure sets a backoff of two attempts
	if err := app.refreshWithBackoff(); !errors.Is(err, auth.ErrInteractiveLoginRequired) {
		t.Fatalf("refreshWithBackoff() error = %v, want %v", err, auth.ErrInteractiveLoginRequired)
	}
	if app.refreshFailure.Load() != 1 || app.refreshBackOff.Load() != 2 {
		t.Fatalf("failures = %d, backoff = %d, want 1 and 2", app.refreshFailure.Load(), app.refreshBackOff.Load())
	}

	// the next two attempts are skipped without a request
	for range 2 {
		if err := app.refreshWithBackoff(); !errors.Is(err, ErrRenewSkipped) {
			t.Fatalf("refreshWithBackoff() error = %v, want %v", err, ErrRenewSkipped)
		}
	}
	if got := len(c.requestKinds()); got != 1 {
		t.Errorf("%d requests made during backoff, want 1", got)
	}

	// a failure after the backoff doubles it
	if err := app.refreshWithBackoff(); err == nil {
		t.Fatalf("refreshWithBackoff() error = nil, want error")
	}
	if app.refreshFailure.Load() != 2 || app.refreshBackOff.Load() != 4 {
		t.Errorf("failures = %d, backoff = %d, want 2 and 4", app.refreshFailure.Load(), app.refreshBackOff.Load())
	}

	// every request was non-interactive
	for i, nonInteractive := range c.requestKinds() {
		if !nonInteractive {
			t.Errorf("request %d was interactive", i)
		}
	}

	// success resets the failures and backoff
	c.mu.Lock()
	c.refreshErr = nil
	c.mu.Unlock()
	app.refreshBackOff.Store(0)
	if err := app.refreshWithBackoff(); err != nil {
		t.Fatalf("refreshWithBackoff() error = %v", err)
	}
	if app.refreshFailure.Load() != 0 || app.refreshBackOff.Load() != 0 {
		t.Errorf("failures = %d, backoff = %d, want 0 and 0", app.refreshFailure.Load(), app.refreshBackOff.Load())
	}
}

func TestApplication_generate(t *testing.T) {
	app, c, _ := newTestApp(t)
	c.hasKey = false

	if err := app.generate(); err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	if c.generated != 1 || !app.hasPrivateKey() {
		t.Errorf("GeneratePrivateKey() called %d times, hasPrivateKey() = %v", c.generated, app.hasPrivateKey())
	}
}

// expiresIn returns a certificate that expires after d
func expiresIn(d time.Duration) *ssh.Certificate {
	return &ssh.Certificate{ValidBefore: uint64(time.Now().Add(d).Unix())}
}

func TestApplication_setState(t *testing.T) {
	refreshErr := errors.New("refresh failed")

	tests := []struct {
		name string

		// starting conditions
		state      appState
		noKey      bool
		cert       *ssh.Certificate
		refreshErr error
		validFor   time.Duration // validity of an issued certificate
		renewing   bool          // a renewal is already in progress

		wantState         appState
		wantRequests      int
		wantNotifications []string
		wantIcon          string
		wantRenew         fakeMenuItem
		wantGenerate      bool
		wantExpiry        string // suffix of the expiry menu item title
		wantTooltip       string // suffix of the tooltip
	}{
		{
			name:         "no private key",
			noKey:        true,
			wantState:    stateKeyMissing,
			wantIcon:     errorIcon,
			wantGenerate: true,
			wantExpiry:   "No certificate",
			wantTooltip:  "No private key found",
		},
		{
			name:        "no certificate",
			wantState:   stateCertificateMissing,
			wantIcon:    warningIcon,
			wantRenew:   fakeMenuItem{"Request", true},
			wantExpiry:  "No certificate",
			wantTooltip: "No certificate found",
		},
		{
			name:        "valid certificate",
			cert:        expiresIn(24 * time.Hour),
			wantState:   stateCertificateOK,
			wantIcon:    okIcon,
			wantRenew:   fakeMenuItem{"Renew", true},
			wantExpiry:  " left",
			wantTooltip: "Current certificate valid",
		},
		{
			name:              "expired on start is refreshed",
			cert:              expiresIn(-time.Hour),
			wantState:         stateCertificateOK,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Refreshed"},
			wantIcon:          okIcon,
			wantRenew:         fakeMenuItem{"Renew", true},
			wantExpiry:        " left",
			wantTooltip:       "Current certificate valid",
		},
		{
			name:              "expired on start and refresh fails",
			cert:              expiresIn(-time.Hour),
			refreshErr:        refreshErr,
			wantState:         stateCertificateExpired,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Expired"},
			wantIcon:          warningIcon,
			wantRenew:         fakeMenuItem{"Renew", true},
			wantExpiry:        "Certificate expired",
			wantTooltip:       "Certificate expired",
		},
		{
			// the new certificate is also within renewAt, which must not
			// cause another refresh straight away
			name:              "close to expiry is refreshed once",
			cert:              expiresIn(30 * time.Minute),
			validFor:          30 * time.Minute,
			wantState:         stateCertificateOK,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Refreshed"},
			wantIcon:          okIcon,
			wantRenew:         fakeMenuItem{"Renew", true},
			wantExpiry:        " left",
			wantTooltip:       "Current certificate valid",
		},
		{
			name:         "close to expiry and refresh fails",
			cert:         expiresIn(30 * time.Minute),
			refreshErr:   refreshErr,
			wantState:    stateCertificateOK,
			wantRequests: 1,
			wantIcon:     okIcon,
			wantRenew:    fakeMenuItem{"Renew", true},
			wantExpiry:   " left",
			wantTooltip:  "Current certificate valid",
		},
		{
			name:              "expires while running is refreshed",
			state:             stateCertificateOK,
			cert:              expiresIn(-time.Minute),
			wantState:         stateCertificateOK,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Refreshed"},
			wantIcon:          okIcon,
			wantRenew:         fakeMenuItem{"Renew", true},
			wantExpiry:        " left",
			wantTooltip:       "Current certificate valid",
		},
		{
			name:              "expires while running and refresh fails",
			state:             stateCertificateOK,
			cert:              expiresIn(-time.Minute),
			refreshErr:        refreshErr,
			wantState:         stateCertificateExpired,
			wantRequests:      1,
			wantNotifications: []string{"Certificate Expired"},
			wantIcon:          warningIcon,
			wantRenew:         fakeMenuItem{"Renew", true},
			wantExpiry:        "Certificate expired",
			wantTooltip:       "Certificate expired",
		},
		{
			// the running renewal updates the state once it completes
			name:      "expires while a renewal is running",
			state:     stateCertificateOK,
			cert:      expiresIn(-time.Minute),
			renewing:  true,
			wantState: stateCertificateOK,
		},
		{
			name:        "key generated elsewhere",
			state:       stateKeyMissing,
			wantState:   stateCertificateMissing,
			wantIcon:    warningIcon,
			wantRenew:   fakeMenuItem{"Request", true},
			wantExpiry:  "No certificate",
			wantTooltip: "No certificate found",
		},
		{
			name:        "issued elsewhere while missing",
			state:       stateCertificateMissing,
			cert:        expiresIn(24 * time.Hour),
			wantState:   stateCertificateOK,
			wantIcon:    okIcon,
			wantRenew:   fakeMenuItem{"Renew", true},
			wantExpiry:  " left",
			wantTooltip: "Current certificate valid",
		},
		{
			name:        "renewed elsewhere while expired",
			state:       stateCertificateExpired,
			cert:        expiresIn(24 * time.Hour),
			wantState:   stateCertificateOK,
			wantIcon:    okIcon,
			wantRenew:   fakeMenuItem{"Renew", true},
			wantExpiry:  " left",
			wantTooltip: "Current certificate valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray := newTestApp(t)
			if tt.state != "" {
				app.state = tt.state
			}
			c.hasKey = !tt.noKey
			c.cert = tt.cert
			c.refreshErr = tt.refreshErr
			if tt.validFor != 0 {
				c.validFor = tt.validFor
			}
			if tt.renewing {
				app.mu.Lock()
				defer app.mu.Unlock()
			}

			app.setState()

			if app.state != tt.wantState {
				t.Errorf("state = %s, want %s", app.state, tt.wantState)
			}

			// requests made while changing state run unattended so must never
			// start an interactive login
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
			if tray.renew != tt.wantRenew {
				t.Errorf("renew menu item = %+v, want %+v", tray.renew, tt.wantRenew)
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

// TestApplication_setState_backoff checks a failed refresh of a certificate
// close to expiry is not retried on every tick of the event loop
func TestApplication_setState_backoff(t *testing.T) {
	app, c, _ := newTestApp(t)
	c.cert = expiresIn(30 * time.Minute)
	c.refreshErr = errors.New("refresh failed")

	// the first failure backs off for two ticks
	wantRequests := []int{1, 1, 1, 2}
	for i, want := range wantRequests {
		app.setState()

		if got := len(c.requestKinds()); got != want {
			t.Fatalf("tick %d: %d requests made, want %d", i+1, got, want)
		}
		if app.state != stateCertificateOK {
			t.Fatalf("tick %d: state = %s, want %s", i+1, app.state, stateCertificateOK)
		}
	}
}

// TestApplication_setState_expiredRetry checks that an expired certificate is
// refreshed once a refresh works again, such as when the network comes up
// after a resume or at logon, rather than staying expired until the user
// renews it from the menu (#223)
func TestApplication_setState_expiredRetry(t *testing.T) {
	for _, start := range []appState{stateInit, stateCertificateOK} {
		t.Run(string(start), func(t *testing.T) {
			app, c, tray := newTestApp(t)
			app.state = start
			c.cert = expiresIn(-time.Minute)
			c.refreshErr = errors.New("dial tcp: network is unreachable")

			app.setState()
			if app.state != stateCertificateExpired {
				t.Fatalf("state after failed refresh = %s, want %s", app.state, stateCertificateExpired)
			}

			// the network comes back and the refresh token still works
			c.refreshErr = nil
			for range 10 {
				app.setState()
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
		})
	}
}

// TestApplication_setState_expiredBackoff checks that refreshes of an expired
// certificate that keep failing are backed off, counting the failure at
// start-up, and that the user is only told once that it expired
func TestApplication_setState_expiredBackoff(t *testing.T) {
	app, c, tray := newTestApp(t)
	c.cert = expiresIn(-time.Minute)
	c.refreshErr = errors.New("refresh failed")

	// each failure backs off for twice the number of failures so far
	wantRequests := []int{1, 1, 2, 2, 2, 2, 2, 3}
	for i, want := range wantRequests {
		app.setState()

		if got := len(c.requestKinds()); got != want {
			t.Fatalf("tick %d: %d requests made, want %d", i+1, got, want)
		}
		if app.state != stateCertificateExpired {
			t.Fatalf("tick %d: state = %s, want %s", i+1, app.state, stateCertificateExpired)
		}
	}

	if want := []string{"Certificate Expired"}; !slices.Equal(tray.notifications, want) {
		t.Errorf("notifications = %q, want %q", tray.notifications, want)
	}
}

// TestApplication_setState_expiredWhileRenewing checks that an expired
// certificate is not refreshed while a renewal from the menu is running, as
// both need the lock and the renewal from the menu would fail (#224)
func TestApplication_setState_expiredWhileRenewing(t *testing.T) {
	app, c, _ := newTestApp(t)
	app.state = stateCertificateExpired
	c.cert = expiresIn(-time.Minute)
	app.renewing = true

	app.setState()

	if got := c.requestKinds(); len(got) != 0 {
		t.Errorf("requests = %v, want none while a renewal from the menu is running", got)
	}
	if app.state != stateCertificateExpired {
		t.Errorf("state = %s, want %s", app.state, stateCertificateExpired)
	}

	// once it has finished, the refresh is tried again
	app.renewing = false
	app.setState()

	if got := len(c.requestKinds()); got != 1 {
		t.Errorf("%d requests after the renewal finished, want 1", got)
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

// TestApplication_eventloop_renewNearExpiry checks that clicking Renew while
// the certificate is close to expiry renews it. The automatic refresh that
// runs after the click used to take the lock first, so the renewal from the
// menu failed with "The certificate renewal failed" (#224).
func TestApplication_eventloop_renewNearExpiry(t *testing.T) {
	for i := range 30 {
		app, c, _ := newTestApp(t)
		app.identity = &slowIdentity{c, 20 * time.Millisecond}
		app.state = stateCertificateOK
		c.cert = expiresIn(2 * time.Hour)
		// background refreshes fail, so the renewal falls back to a login
		c.refreshErr = errors.New("refresh token expired")

		renew := make(chan struct{})
		app.renewClicked = renew

		// the first setState of the event loop has finished once the
		// tooltip is set
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

		// the event loop only stops when the application quits, which needs
		// a running system tray, so it is left running until the test ends
		go app.eventloop()
		<-ready

		// the certificate is now within renewAt, so every setState tries an
		// automatic refresh
		c.mu.Lock()
		c.cert = expiresIn(30 * time.Minute)
		c.mu.Unlock()
		renew <- struct{}{}

		select {
		case got := <-result:
			if got != "Certificate Issued" {
				t.Fatalf("run %d: notification = %q, want %q", i+1, got, "Certificate Issued")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("run %d: the renewal did not finish", i+1)
		}
	}
}

// TestApplication_backoffConcurrent runs a renewal alongside setState, which
// logs the backoff counters, so `go test -race` reports them if they are not
// synchronised (#224)
func TestApplication_backoffConcurrent(t *testing.T) {
	app, c, _ := newTestApp(t)
	c.cert = expiresIn(30 * time.Minute)
	c.refreshErr = errors.New("refresh failed")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_ = app.renew()
		}
	}()

	for range 200 {
		app.setState()
	}
	<-done
}

// TestApplication_setState_refreshAgentError checks that an automatic refresh
// that issues a certificate but can't add it to the SSH agent counts as a
// refresh: the user is warned about the agent rather than told the
// certificate expired, and no failure is counted towards the backoff (#222)
func TestApplication_setState_refreshAgentError(t *testing.T) {
	tests := []struct {
		name  string
		state appState
		cert  *ssh.Certificate
	}{
		{"expired on start", stateInit, expiresIn(-time.Minute)},
		{"expires while running", stateCertificateOK, expiresIn(-time.Minute)},
		{"close to expiry", stateCertificateOK, expiresIn(30 * time.Minute)},
		{"still expired", stateCertificateExpired, expiresIn(-time.Minute)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, c, tray := newTestApp(t)
			app.state = tt.state
			c.cert = tt.cert
			c.agentErr = cert.ErrAddingToAgent

			app.setState()

			if app.state != stateCertificateOK {
				t.Errorf("state = %s, want %s", app.state, stateCertificateOK)
			}
			if want := []string{"Warning"}; !slices.Equal(tray.notifications, want) {
				t.Errorf("notifications = %q, want %q", tray.notifications, want)
			}
			if f, b := app.refreshFailure.Load(), app.refreshBackOff.Load(); f != 0 || b != 0 {
				t.Errorf("failures = %d, backoff = %d, want 0 and 0", f, b)
			}
			if got := len(c.requestKinds()); got != 1 {
				t.Errorf("%d requests made, want 1", got)
			}
		})
	}
}

// TestApplication_refreshAgentError checks that a refresh from the menu that
// issues a certificate but can't add it to the SSH agent clears the backoff,
// as a certificate was obtained (#222)
func TestApplication_refreshAgentError(t *testing.T) {
	for name, obtain := range map[string]func(*Application) error{
		"refresh": (*Application).refresh,
		"renew":   (*Application).renew,
	} {
		t.Run(name, func(t *testing.T) {
			app, c, _ := newTestApp(t)
			c.agentErr = cert.ErrAddingToAgent
			app.refreshFailure.Store(3)
			app.refreshBackOff.Store(6)

			if err := obtain(app); !errors.Is(err, cert.ErrAddingToAgent) {
				t.Fatalf("%s() error = %v, want %v", name, err, cert.ErrAddingToAgent)
			}
			if f, b := app.refreshFailure.Load(), app.refreshBackOff.Load(); f != 0 || b != 0 {
				t.Errorf("failures = %d, backoff = %d, want 0 and 0", f, b)
			}
		})
	}
}
