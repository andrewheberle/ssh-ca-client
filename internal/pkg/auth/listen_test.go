package auth

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

// unassigned is an address from TEST-NET-1 (RFC 5737), which is never
// assigned to the machine running the tests, so listening on it fails as
// unavailable
var unassigned = net.ParseIP("192.0.2.1")

// secondLoopback returns 127.0.0.2, skipping the test where it can't be
// listened on, such as macOS, where only 127.0.0.1 is assigned by default
func secondLoopback(t *testing.T) net.IP {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	_ = l.Close()

	return net.ParseIP("127.0.0.2")
}

// portOf returns the port that l listens on
func portOf(t *testing.T, l net.Listener) string {
	t.Helper()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q) error = %v", l.Addr(), err)
	}

	return port
}

// acceptFrom dials address and returns the IP address of the local end of the
// connection that l accepts
func acceptFrom(t *testing.T, l net.Listener, address string) string {
	t.Helper()

	c, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial(%q) error = %v", address, err)
	}
	defer func() { _ = c.Close() }()

	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	defer func() { _ = conn.Close() }()

	host, _, _ := net.SplitHostPort(conn.LocalAddr().String())

	return host
}

func TestListen(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "localhost:0"} {
		t.Run(addr, func(t *testing.T) {
			l, err := listen(context.Background(), addr)
			if err != nil {
				t.Fatalf("listen(%q) error = %v", addr, err)
			}
			defer func() { _ = l.Close() }()

			acceptFrom(t, l, net.JoinHostPort("127.0.0.1", portOf(t, l)))
		})
	}

	t.Run("unresolvable name", func(t *testing.T) {
		if _, err := listen(context.Background(), "host.invalid:0"); err == nil {
			t.Errorf("listen() error = nil, want error")
		}
	})

	t.Run("no port", func(t *testing.T) {
		if _, err := listen(context.Background(), "localhost"); err == nil {
			t.Errorf("listen() error = nil, want error")
		}
	})
}

func TestListenAll(t *testing.T) {
	ctx := context.Background()
	loopback := net.ParseIP("127.0.0.1")

	t.Run("every address", func(t *testing.T) {
		second := secondLoopback(t)

		l, err := listenAll(ctx, []net.IP{loopback, second}, "0")
		if err != nil {
			t.Fatalf("listenAll() error = %v", err)
		}
		defer func() { _ = l.Close() }()

		// one port is used on every address, so one URL reaches all of them
		port := portOf(t, l)
		got := []string{
			acceptFrom(t, l, net.JoinHostPort(loopback.String(), port)),
			acceptFrom(t, l, net.JoinHostPort(second.String(), port)),
		}
		slices.Sort(got)
		if want := []string{"127.0.0.1", "127.0.0.2"}; !slices.Equal(got, want) {
			t.Errorf("accepted connections on %q, want %q", got, want)
		}
	})

	t.Run("address in use", func(t *testing.T) {
		second := secondLoopback(t)

		// another user already listens on one of the addresses
		other, err := net.Listen("tcp", net.JoinHostPort(second.String(), "0"))
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}
		defer func() { _ = other.Close() }()
		port := portOf(t, other)

		if l, err := listenAll(ctx, []net.IP{loopback, second}, port); err == nil {
			_ = l.Close()
			t.Fatalf("listenAll() error = nil, want error as %s:%s is in use", second, port)
		}

		// the address that was listened on before the failure is released
		l, err := net.Listen("tcp", net.JoinHostPort(loopback.String(), port))
		if err != nil {
			t.Fatalf("Listen() on %s:%s after the failure error = %v, want it released", loopback, port, err)
		}
		_ = l.Close()
	})

	t.Run("unavailable address skipped", func(t *testing.T) {
		l, err := listenAll(ctx, []net.IP{unassigned, loopback}, "0")
		if err != nil {
			t.Fatalf("listenAll() error = %v", err)
		}
		defer func() { _ = l.Close() }()

		if got := acceptFrom(t, l, net.JoinHostPort(loopback.String(), portOf(t, l))); got != "127.0.0.1" {
			t.Errorf("accepted connection on %q, want 127.0.0.1", got)
		}
	})

	t.Run("no available address", func(t *testing.T) {
		if l, err := listenAll(ctx, []net.IP{unassigned}, "0"); err == nil {
			_ = l.Close()
			t.Errorf("listenAll() error = nil, want error")
		}
	})

	t.Run("duplicate address", func(t *testing.T) {
		l, err := listenAll(ctx, []net.IP{loopback, loopback}, "0")
		if err != nil {
			t.Fatalf("listenAll() error = %v", err)
		}
		_ = l.Close()
	})
}

func TestMultiListener_Close(t *testing.T) {
	second := secondLoopback(t)

	l, err := listenAll(context.Background(), []net.IP{net.ParseIP("127.0.0.1"), second}, "0")
	if err != nil {
		t.Fatalf("listenAll() error = %v", err)
	}
	port := portOf(t, l)

	accepted := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		accepted <- err
	}()

	if err := l.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("second Close() error = %v, want the same result", err)
	}

	// a pending Accept returns, as http.Server.Shutdown needs
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept() error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept() did not return after Close()")
	}

	// both addresses are released
	for _, ip := range []string{"127.0.0.1", second.String()} {
		l, err := net.Listen("tcp", net.JoinHostPort(ip, port))
		if err != nil {
			t.Errorf("Listen() on %s:%s after Close() error = %v, want it released", ip, port, err)
			continue
		}
		_ = l.Close()
	}
}
