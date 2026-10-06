//go:build !windows

package cli

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
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
