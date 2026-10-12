//go:build windows || linux

package tray

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"golang.org/x/crypto/ssh"
)

// fakeStore is a [cert.Storage] with results controlled by the test. Methods
// not implemented here are not used by the application.
type fakeStore struct {
	cert.Storage

	mu        sync.Mutex
	hasKey    bool
	cert      *ssh.Certificate
	agentErr  error
	agentAdds int
	generated int
	genErr    error
}

func (s *fakeStore) HasPrivateKey() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.hasKey
}

func (s *fakeStore) HasCertificate() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.cert != nil
}

func (s *fakeStore) Certificate() (*ssh.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cert == nil {
		return nil, cert.ErrCertificateNotFound
	}

	return s.cert, nil
}

func (s *fakeStore) AddToAgent() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.agentAdds++

	return s.agentErr
}

func (s *fakeStore) GeneratePrivateKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.generated++
	if s.genErr != nil {
		return s.genErr
	}
	s.hasKey = true

	return nil
}

// fakeCertificate is a [Certificate] that records each request. A request
// without a NonInteractive context fails with interactiveErr, otherwise with
// refreshErr. Successful requests store a certificate valid for validFor.
type fakeCertificate struct {
	store *fakeStore

	mu             sync.Mutex
	refreshErr     error
	interactiveErr error
	validFor       time.Duration
	block          bool // block interactive requests until ctx is done
	requests       []bool
}

func (c *fakeCertificate) Store() cert.Storage {
	return c.store
}

func (c *fakeCertificate) RequestContext(ctx context.Context) error {
	nonInteractive := auth.IsNonInteractive(ctx)

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

	c.store.mu.Lock()
	c.store.cert = &ssh.Certificate{ValidBefore: uint64(time.Now().Add(c.validFor).Unix())}
	c.store.mu.Unlock()

	return nil
}

// requestKinds returns whether each request was non-interactive
func (c *fakeCertificate) requestKinds() []bool {
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

// newTestApp returns an Application using a fake certificate, store and
// system tray
func newTestApp(t *testing.T) (*Application, *fakeCertificate, *fakeTray) {
	t.Helper()

	c := &fakeCertificate{store: &fakeStore{hasKey: true}, validFor: 24 * time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	icons := map[string][]byte{
		okIcon:      []byte(okIcon),
		warningIcon: []byte(warningIcon),
		errorIcon:   []byte(errorIcon),
	}

	tray := &fakeTray{}
	app := &Application{
		cert:              c,
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
			c.store.cert = tt.cert

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
		c.store.cert = &ssh.Certificate{ValidBefore: uint64(want.Unix())}

		if got := app.certificateExpiry(); !got.Equal(want) {
			t.Errorf("certificateExpiry() = %v, want %v", got, want)
		}
	})
}

func TestApplication_request(t *testing.T) {
	requestErr := errors.New("request failed")
	agentErr := fmt.Errorf("%w: agent unavailable", cert.ErrAddingToAgent)

	t.Run("adds certificate to agent", func(t *testing.T) {
		app, c, _ := newTestApp(t)

		if err := app.request(context.Background()); err != nil {
			t.Fatalf("request() error = %v", err)
		}
		if c.store.agentAdds != 1 {
			t.Errorf("AddToAgent() called %d times, want 1", c.store.agentAdds)
		}
	})

	t.Run("request failure does not add to agent", func(t *testing.T) {
		app, c, _ := newTestApp(t)
		c.interactiveErr = requestErr

		if err := app.request(context.Background()); !errors.Is(err, requestErr) {
			t.Errorf("request() error = %v, want %v", err, requestErr)
		}
		if c.store.agentAdds != 0 {
			t.Errorf("AddToAgent() called %d times, want 0", c.store.agentAdds)
		}
	})

	t.Run("agent failure", func(t *testing.T) {
		app, c, _ := newTestApp(t)
		c.store.agentErr = agentErr

		if err := app.request(context.Background()); !errors.Is(err, cert.ErrAddingToAgent) {
			t.Errorf("request() error = %v, want %v", err, cert.ErrAddingToAgent)
		}
		if !app.certificateValid() {
			t.Errorf("certificate not stored although it was issued")
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
		app.refreshFailure, app.refreshBackOff = 3, 6

		if err := app.refresh(); err != nil {
			t.Fatalf("refresh() error = %v", err)
		}
		if app.refreshFailure != 0 || app.refreshBackOff != 0 {
			t.Errorf("failures = %d, backoff = %d, want 0 and 0", app.refreshFailure, app.refreshBackOff)
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
			c.refreshErr, c.interactiveErr, c.store.agentErr = tt.refreshErr, tt.renewErr, tt.agentErr

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
	if app.refreshFailure != 1 || app.refreshBackOff != 2 {
		t.Fatalf("failures = %d, backoff = %d, want 1 and 2", app.refreshFailure, app.refreshBackOff)
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
	if app.refreshFailure != 2 || app.refreshBackOff != 4 {
		t.Errorf("failures = %d, backoff = %d, want 2 and 4", app.refreshFailure, app.refreshBackOff)
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
	app.refreshBackOff = 0
	if err := app.refreshWithBackoff(); err != nil {
		t.Fatalf("refreshWithBackoff() error = %v", err)
	}
	if app.refreshFailure != 0 || app.refreshBackOff != 0 {
		t.Errorf("failures = %d, backoff = %d, want 0 and 0", app.refreshFailure, app.refreshBackOff)
	}
}

func TestApplication_generate(t *testing.T) {
	app, c, _ := newTestApp(t)
	c.store.hasKey = false

	if err := app.generate(); err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	if c.store.generated != 1 || !app.hasPrivateKey() {
		t.Errorf("GeneratePrivateKey() called %d times, hasPrivateKey() = %v", c.store.generated, app.hasPrivateKey())
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
			c.store.hasKey = !tt.noKey
			c.store.cert = tt.cert
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
	c.store.cert = expiresIn(30 * time.Minute)
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
