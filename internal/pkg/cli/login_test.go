package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/identity"
	"golang.org/x/crypto/ssh"
)

// fakeLoginIdentity is a [loginIdentity] whose current certificate is valid
// from passed ago until left from now, or missing if both are zero
type fakeLoginIdentity struct {
	passed, left time.Duration
	obtainErr    error
	agentErr     error

	obtained [][]identity.ObtainOption
	added    int
}

func (f *fakeLoginIdentity) Obtain(ctx context.Context, opts ...identity.ObtainOption) error {
	f.obtained = append(f.obtained, opts)
	if f.obtainErr != nil {
		return f.obtainErr
	}

	return ctx.Err()
}

func (f *fakeLoginIdentity) AddToAgent() error {
	f.added++

	return f.agentErr
}

func (f *fakeLoginIdentity) Certificate() (*ssh.Certificate, error) {
	if f.passed == 0 && f.left == 0 {
		return nil, cert.ErrCertificateNotFound
	}

	now := time.Now()

	return &ssh.Certificate{
		ValidAfter:  uint64(now.Add(-f.passed).Unix()),
		ValidBefore: uint64(now.Add(f.left).Unix()),
	}, nil
}

func TestLoginCommand_Run(t *testing.T) {
	obtainErr := errors.New("login failed")
	agentErr := fmt.Errorf("%w: agent unavailable", cert.ErrAddingToAgent)

	tests := []struct {
		name         string
		identity     fakeLoginIdentity
		add          bool
		force        bool
		skipAgent    bool
		cancelled    bool
		wantErr      error
		wantObtained bool
		wantAdded    int
	}{
		{name: "no certificate", wantObtained: true, wantAdded: 1},
		{name: "most of lifetime left", identity: fakeLoginIdentity{passed: time.Hour, left: 23 * time.Hour}},
		{name: "most of lifetime left forced", identity: fakeLoginIdentity{passed: time.Hour, left: 23 * time.Hour}, force: true, wantObtained: true, wantAdded: 1},
		{name: "half of lifetime passed", identity: fakeLoginIdentity{passed: 12 * time.Hour, left: 12 * time.Hour}, wantObtained: true, wantAdded: 1},
		{name: "expired", identity: fakeLoginIdentity{passed: 25 * time.Hour, left: -time.Hour}, wantObtained: true, wantAdded: 1},
		{name: "skip agent", skipAgent: true, wantObtained: true},
		{name: "add only", identity: fakeLoginIdentity{passed: time.Hour, left: 23 * time.Hour}, add: true, wantAdded: 1},
		{name: "add only fails", add: true, identity: fakeLoginIdentity{agentErr: agentErr}, wantErr: cert.ErrAddingToAgent, wantAdded: 1},
		{name: "login fails", identity: fakeLoginIdentity{obtainErr: obtainErr}, wantErr: obtainErr, wantObtained: true},
		{name: "login cancelled", cancelled: true, wantErr: context.Canceled, wantObtained: true},
		{name: "agent fails", identity: fakeLoginIdentity{agentErr: agentErr}, wantErr: cert.ErrAddingToAgent, wantObtained: true, wantAdded: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := tt.identity
			c := &loginCommand{
				add:       tt.add,
				force:     tt.force,
				skipAgent: tt.skipAgent,
				identity:  &id,
				logger:    slog.New(slog.DiscardHandler),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelled {
				cancel()
			}

			err := c.Run(ctx, nil, nil)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run() error = %v, want %v", err, tt.wantErr)
			}

			if obtained := len(id.obtained) > 0; obtained != tt.wantObtained {
				t.Errorf("certificate obtained = %v, want %v", obtained, tt.wantObtained)
			}
			for _, opts := range id.obtained {
				// login adds the certificate to the agent itself
				if !slices.Contains(opts, identity.WithoutAgent) {
					t.Errorf("Obtain() options = %v, want %v", opts, identity.WithoutAgent)
				}
				// login is run by a person, so may log in interactively
				if slices.Contains(opts, identity.WithoutInteractiveLogin) {
					t.Errorf("Obtain() options = %v, do not want %v", opts, identity.WithoutInteractiveLogin)
				}
			}
			if id.added != tt.wantAdded {
				t.Errorf("AddToAgent() called %d times, want %d", id.added, tt.wantAdded)
			}
		})
	}
}
