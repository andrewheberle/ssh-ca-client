package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
)

// listen listens on addr for the login HTTP server.
//
// When the host of addr is a name, such as localhost, it listens on every
// address the name resolves to. A browser may connect to any of them: for
// localhost most try [::1] before 127.0.0.1. If only one were listened on,
// another local user could listen on the other and receive the login, then
// redeem its code for the user's tokens.
//
// An address that can't be used on this machine, such as [::1] with IPv6
// disabled, is skipped, as no one else can listen on it either. Any other
// error, such as an address already being in use, fails.
func listen(ctx context.Context, addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return listenAll(ctx, []net.IP{ip}, port)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", host, err)
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}

	return listenAll(ctx, ips, port)
}

// listenAll listens on port on every address in ips, skipping any that
// can't be used on this machine. With port 0 the port chosen for the first
// address is used for the others, so one URL reaches all of them.
func listenAll(ctx context.Context, ips []net.IP, port string) (net.Listener, error) {
	var lc net.ListenConfig

	listeners := make([]net.Listener, 0, len(ips))
	closeAll := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}

	seen := make([]string, 0, len(ips))
	var skipped error
	for _, ip := range ips {
		address := ip.String()
		if slices.Contains(seen, address) {
			continue
		}
		seen = append(seen, address)

		l, err := lc.Listen(ctx, "tcp", net.JoinHostPort(address, port))
		if err != nil {
			if addressUnavailable(err) {
				skipped = errors.Join(skipped, err)
				continue
			}

			closeAll()
			return nil, err
		}

		if port == "0" {
			_, port, _ = net.SplitHostPort(l.Addr().String())
		}
		listeners = append(listeners, l)
	}

	switch len(listeners) {
	case 0:
		return nil, fmt.Errorf("no address could be listened on: %w", skipped)
	case 1:
		return listeners[0], nil
	default:
		return newMultiListener(listeners), nil
	}
}

// multiListener accepts connections from several listeners as one
// [net.Listener]. Addr is the address of the first.
type multiListener struct {
	listeners []net.Listener
	accepted  chan accepted
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

type accepted struct {
	conn net.Conn
	err  error
}

func newMultiListener(listeners []net.Listener) *multiListener {
	m := &multiListener{
		listeners: listeners,
		accepted:  make(chan accepted),
		done:      make(chan struct{}),
	}

	for _, l := range listeners {
		go m.accept(l)
	}

	return m
}

// accept passes the connections accepted by l, and any errors other than l
// being closed, to Accept until the multiListener is closed
func (m *multiListener) accept(l net.Listener) {
	for {
		conn, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}

		select {
		case m.accepted <- accepted{conn, err}:
		case <-m.done:
			if conn != nil {
				_ = conn.Close()
			}
			return
		}
	}
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case a := <-m.accepted:
		return a.conn, a.err
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	m.closeOnce.Do(func() {
		close(m.done)

		errs := make([]error, 0, len(m.listeners))
		for _, l := range m.listeners {
			errs = append(errs, l.Close())
		}
		m.closeErr = errors.Join(errs...)
	})

	return m.closeErr
}

func (m *multiListener) Addr() net.Addr {
	return m.listeners[0].Addr()
}
