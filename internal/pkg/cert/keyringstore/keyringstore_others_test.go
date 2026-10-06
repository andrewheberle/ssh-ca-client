//go:build !windows

package keyringstore

import (
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// newDefaultStorage returns a *Storage backed by a freshly initialised mock
// keyring that connects to the agent from the environment
func newDefaultStorage(t *testing.T, ca ssh.Signer) *Storage {
	t.Helper()

	keyring.MockInit()

	s, err := New(ca.PublicKey())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return s
}

// testAgent is an in-memory SSH agent served on a unix socket that counts
// client connections
type testAgent struct {
	agent.Agent

	ln     net.Listener
	opened atomic.Int32
	active atomic.Int32
}

// serveAgentAt starts an in-memory SSH agent listening on socket. The agent
// is stopped when the test finishes or Stop is called.
func serveAgentAt(t *testing.T, socket string) *testAgent {
	t.Helper()

	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("could not listen on agent socket: %v", err)
	}

	a := &testAgent{Agent: agent.NewKeyring(), ln: ln}
	t.Cleanup(a.Stop)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			a.opened.Add(1)
			a.active.Add(1)
			go func() {
				defer a.active.Add(-1)
				defer conn.Close()
				_ = agent.ServeAgent(a.Agent, conn)
			}()
		}
	}()

	return a
}

// serveAgent starts an in-memory SSH agent and points SSH_AUTH_SOCK at it
func serveAgent(t *testing.T) *testAgent {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "agent.sock")
	t.Setenv("SSH_AUTH_SOCK", socket)

	return serveAgentAt(t, socket)
}

// Stop stops the agent listening for new connections
func (a *testAgent) Stop() {
	_ = a.ln.Close()
}

// waitClosed waits for all client connections to the agent to be closed
func (a *testAgent) waitClosed(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for a.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Errorf("%d agent connections still open, want 0", a.active.Load())
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestStorage_AddToAgent_DefaultAgent(t *testing.T) {
	ca := newCA(t)

	// saveValidCert saves a valid certificate to s and returns it
	saveValidCert := func(t *testing.T, s *Storage) *ssh.Certificate {
		t.Helper()

		c := validCert(t, s, ca)
		if err := s.SaveCertificate(c); err != nil {
			t.Fatalf("SaveCertificate() error = %v", err)
		}

		return c
	}

	t.Run("connects to agent from environment", func(t *testing.T) {
		a := serveAgent(t)
		s := newDefaultStorage(t, ca)
		c := saveValidCert(t, s)

		if got := a.opened.Load(); got != 0 {
			t.Errorf("New() opened %d agent connections, want 0", got)
		}

		if err := s.AddToAgent(); err != nil {
			t.Fatalf("AddToAgent() error = %v", err)
		}

		assertCertInAgent(t, a.Agent, c)
		if got := a.opened.Load(); got != 1 {
			t.Errorf("AddToAgent() opened %d agent connections, want 1", got)
		}
		a.waitClosed(t)
	})

	t.Run("new connection for each call", func(t *testing.T) {
		a := serveAgent(t)
		s := newDefaultStorage(t, ca)
		saveValidCert(t, s)

		for range 3 {
			if err := s.AddToAgent(); err != nil {
				t.Fatalf("AddToAgent() error = %v", err)
			}
		}

		if got := a.opened.Load(); got != 3 {
			t.Errorf("AddToAgent() opened %d agent connections, want 3", got)
		}
		a.waitClosed(t)
	})

	t.Run("agent not available", func(t *testing.T) {
		t.Setenv("SSH_AUTH_SOCK", filepath.Join(t.TempDir(), "missing.sock"))

		// the agent is not needed until AddToAgent is called
		s := newDefaultStorage(t, ca)
		saveValidCert(t, s)

		err := s.AddToAgent()
		if !errors.Is(err, ErrAddingToAgent) {
			t.Errorf("AddToAgent() error = %v, want %v", err, ErrAddingToAgent)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			t.Errorf("AddToAgent() error = %v, want *net.OpError", err)
		}
	})

	t.Run("agent started after New", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "agent.sock")
		t.Setenv("SSH_AUTH_SOCK", socket)

		s := newDefaultStorage(t, ca)
		c := saveValidCert(t, s)

		a := serveAgentAt(t, socket)
		if err := s.AddToAgent(); err != nil {
			t.Fatalf("AddToAgent() error = %v", err)
		}
		assertCertInAgent(t, a.Agent, c)
	})

	t.Run("agent restarted", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "agent.sock")
		t.Setenv("SSH_AUTH_SOCK", socket)

		s := newDefaultStorage(t, ca)
		c := saveValidCert(t, s)

		first := serveAgentAt(t, socket)
		if err := s.AddToAgent(); err != nil {
			t.Fatalf("AddToAgent() error = %v", err)
		}
		first.Stop()

		second := serveAgentAt(t, socket)
		if err := s.AddToAgent(); err != nil {
			t.Fatalf("AddToAgent() after agent restart error = %v", err)
		}
		assertCertInAgent(t, second.Agent, c)
	})

	t.Run("no key or certificate does not connect", func(t *testing.T) {
		a := serveAgent(t)
		s := newDefaultStorage(t, ca)

		if err := s.AddToAgent(); !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("AddToAgent() error = %v, want %v", err, ErrKeyNotFound)
		}

		generatePrivateKey(t, s)
		if err := s.AddToAgent(); !errors.Is(err, ErrCertificateNotFound) {
			t.Errorf("AddToAgent() error = %v, want %v", err, ErrCertificateNotFound)
		}

		if got := a.opened.Load(); got != 0 {
			t.Errorf("AddToAgent() opened %d agent connections, want 0", got)
		}
	})
}
