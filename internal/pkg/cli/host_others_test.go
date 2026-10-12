//go:build !windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"golang.org/x/crypto/ssh"
)

func TestJitter(t *testing.T) {
	for _, d := range []time.Duration{time.Nanosecond, time.Millisecond, 250 * time.Millisecond, time.Minute} {
		min, max := d/2, d/2+d
		for range 1000 {
			if got := jitter(d); got < min || got > max {
				t.Fatalf("jitter(%v) = %v, want between %v and %v", d, got, min, max)
			}
		}
	}
}

func TestHostCommand_pause(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	t.Run("no delay", func(t *testing.T) {
		for _, d := range []time.Duration{0, -time.Second} {
			c := &hostCommand{delay: d}

			start := time.Now()
			if err := c.pause(context.Background(), logger); err != nil {
				t.Errorf("pause() error = %v", err)
			}
			if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
				t.Errorf("pause() with delay %v took %v, want immediate", d, elapsed)
			}
		}
	})

	t.Run("waits", func(t *testing.T) {
		c := &hostCommand{delay: 20 * time.Millisecond}

		start := time.Now()
		if err := c.pause(context.Background(), logger); err != nil {
			t.Errorf("pause() error = %v", err)
		}
		if elapsed := time.Since(start); elapsed < 10*time.Millisecond {
			t.Errorf("pause() took %v, want at least %v", elapsed, 10*time.Millisecond)
		}
	})

	t.Run("cancelled", func(t *testing.T) {
		c := &hostCommand{delay: time.Hour}

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		start := time.Now()
		if err := c.pause(ctx, logger); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("pause() error = %v, want %v", err, context.DeadlineExceeded)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("pause() took %v after cancellation, want prompt return", elapsed)
		}
	})
}

// fakeHostStore is a [cert.Storage] holding cert. Methods not implemented here
// are not used by the host command.
type fakeHostStore struct {
	cert.Storage

	cert *ssh.Certificate
}

func (s *fakeHostStore) Certificate() (*ssh.Certificate, error) {
	if s.cert == nil {
		return nil, cert.ErrCertificateNotFound
	}

	return s.cert, nil
}

// fakeHostCert is a [cert.Renewable] that records each call as "request" or
// "renew" in calls, which is shared between certificates to show the order.
// If cancel is set it is called during the request or renewal.
type fakeHostCert struct {
	store  *fakeHostStore
	err    error
	cancel context.CancelFunc
	calls  *[]string
	name   string
}

func (f *fakeHostCert) Store() cert.Storage { return f.store }
func (f *fakeHostCert) Request() error      { return f.RequestContext(context.Background()) }
func (f *fakeHostCert) Renew() error        { return f.RenewContext(context.Background()) }

func (f *fakeHostCert) RequestContext(ctx context.Context) error {
	return f.call("request")
}

func (f *fakeHostCert) RenewContext(ctx context.Context) error {
	return f.call("renew")
}

func (f *fakeHostCert) call(kind string) error {
	*f.calls = append(*f.calls, kind+" "+f.name)
	if f.cancel != nil {
		f.cancel()
	}

	return f.err
}

// issuedFor returns a certificate with lifetime of which elapsed has passed
func issuedFor(lifetime, elapsed time.Duration) *ssh.Certificate {
	now := time.Now()

	return &ssh.Certificate{
		ValidAfter:  uint64(now.Add(-elapsed).Unix()),
		ValidBefore: uint64(now.Add(lifetime - elapsed).Unix()),
	}
}

func TestHostCommand_Run(t *testing.T) {
	var (
		due    = issuedFor(24*time.Hour, 20*time.Hour)
		notDue = issuedFor(24*time.Hour, time.Hour)
		failed = errors.New("CA unavailable")
	)

	// key describes a host key, its stored certificate and the result of a
	// request or renewal for it
	type key struct {
		cert   *ssh.Certificate
		err    error
		cancel bool
	}

	tests := []struct {
		name      string
		renew     bool
		force     bool
		keys      []key
		wantCalls []string
		wantErrs  []string // keys that must be named in the error
		wantErr   error
	}{
		{
			name:      "request for every key",
			keys:      []key{{}, {cert: notDue}},
			wantCalls: []string{"request key0", "request key1"},
		},
		{
			name:      "renew only keys that are due",
			renew:     true,
			keys:      []key{{cert: notDue}, {cert: due}, {cert: notDue}},
			wantCalls: []string{"renew key1"},
		},
		{
			name:      "renew forced",
			renew:     true,
			force:     true,
			keys:      []key{{cert: notDue}, {cert: due}},
			wantCalls: []string{"renew key0", "renew key1"},
		},
		{
			name:      "renew with a missing certificate continues",
			renew:     true,
			keys:      []key{{}, {cert: due}},
			wantCalls: []string{"renew key1"},
			wantErrs:  []string{"key0"},
			wantErr:   cert.ErrCertificateNotFound,
		},
		{
			name:      "failed request continues",
			keys:      []key{{err: failed}, {}},
			wantCalls: []string{"request key0", "request key1"},
			wantErrs:  []string{"key0"},
			wantErr:   failed,
		},
		{
			name:      "failed renewals are all returned",
			renew:     true,
			keys:      []key{{cert: due, err: failed}, {cert: due, err: failed}},
			wantCalls: []string{"renew key0", "renew key1"},
			wantErrs:  []string{"key0", "key1"},
			wantErr:   failed,
		},
		{
			name:      "cancelled stops further keys",
			keys:      []key{{cancel: true}, {}},
			wantCalls: []string{"request key0"},
			wantErr:   context.Canceled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			var calls []string
			c := &hostCommand{
				renew:   tt.renew,
				force:   tt.force,
				renewat: defaultHostRenewAt,
				logger:  slog.New(slog.DiscardHandler),
			}
			for i, k := range tt.keys {
				fc := &fakeHostCert{
					store: &fakeHostStore{cert: k.cert},
					err:   k.err,
					calls: &calls,
					name:  fmt.Sprintf("key%d", i),
				}
				if k.cancel {
					fc.cancel = cancel
				}
				c.certs = append(c.certs, hostCert{keypath: fc.name, cert: fc})
			}

			err := c.Run(ctx, nil, nil)

			if fmt.Sprint(calls) != fmt.Sprint(tt.wantCalls) {
				t.Errorf("calls = %q, want %q", calls, tt.wantCalls)
			}
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Run() error = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Run() error = %v, want %v", err, tt.wantErr)
			}
			for _, name := range tt.wantErrs {
				if !strings.Contains(err.Error(), name+":") {
					t.Errorf("Run() error = %v, want it to name %s", err, name)
				}
			}
		})
	}
}
