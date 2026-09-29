package agentonly

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
)

type UserCertificate struct {
	// options
	curve elliptic.Curve

	// internal state
	mu     sync.RWMutex
	key    *ecdsa.PrivateKey
	ticker *time.Ticker
	ch     chan error
}

var _ cert.RequestableWaiter = &UserCertificate{}

var (
	ErrNotRunning = errors.New("renewal ticker not running")
)

func (c *UserCertificate) Request() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return nil
}

func (c *UserCertificate) Wait() error {
	if c.ticker == nil {
		return ErrNotRunning
	}

	for {
		select {
		case <-c.ticker.C:
			if err := c.Request(); err != nil {
				return fmt.Errorf("could not request certificate: %w", err)
			}
		case err := <-c.ch:
			return err
		}
	}
}

func (c *UserCertificate) Stop() {
	if c.ticker == nil {
		c.ch <- nil

		return
	}

	// stop the ticker and return nil
	c.ticker.Stop()
	c.ch <- nil

	return
}

func New(comment string, opts ...Option) (*UserCertificate, error) {
	// set up defaults
	c := &UserCertificate{
		curve: elliptic.P256(),
	}

	for _, o := range opts {
		o(c)
	}

	// generate ECDSA key
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not generate private key: %w", err)
	}

	c.key = key

	return c, nil
}

type Option func(*UserCertificate)

func WithCurve(curve elliptic.Curve) Option {
	return func(c *UserCertificate) {
		c.curve = curve
	}
}
