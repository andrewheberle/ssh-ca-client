package pageant

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		running bool // another Pageant is already running
		stops   bool // the proxy returns straight away
		cancel  bool // ctx is cancelled once the proxy is running
		wantRun bool
		wantErr error
	}{
		{name: "another Pageant running", running: true, wantErr: ErrPageantRunning},
		{name: "proxy stops", stops: true, wantRun: true, wantErr: ErrStopped},
		{name: "cancelled", cancel: true, wantRun: true, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origRunning, origRun := pageantRunning, runProxy
			t.Cleanup(func() { pageantRunning, runProxy = origRunning, origRun })

			// started is closed when the proxy runs, which then blocks until
			// the test ends unless it stops straight away
			started := make(chan struct{})
			done := make(chan struct{})
			defer close(done)
			pageantRunning = func() bool { return tt.running }
			runProxy = func() {
				close(started)
				if !tt.stops {
					<-done
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				go func() {
					<-started
					cancel()
				}()
			}

			errc := make(chan error, 1)
			go func() { errc <- Run(ctx) }()

			select {
			case err := <-errc:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Run() error = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run() did not return")
			}

			ran := false
			select {
			case <-started:
				ran = true
			default:
			}
			if ran != tt.wantRun {
				t.Errorf("proxy run = %v, want %v", ran, tt.wantRun)
			}
		})
	}
}
