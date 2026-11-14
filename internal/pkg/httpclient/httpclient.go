// Package httpclient provides the [*http.Client] used for requests to the
// Serverless SSH CA.
package httpclient

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
)

const (
	// UserAgent is the product name sent in the User-Agent header
	UserAgent = "Serverless-SSH-CA-Client"

	// Timeout is the timeout for requests made by the client. A request may
	// need the CA to start, query its database, fetch the identity
	// provider's keys and sign a certificate, so it allows for a slow
	// response rather than failing a request that would succeed.
	Timeout = time.Second * 15

	// MaxResponseSize is the largest response body read from the CA. Its
	// responses, including a revocation list, are far smaller, so this only
	// stops a misbehaving CA or a man in the middle using up memory.
	MaxResponseSize = 4 << 20
)

// ErrResponseTooLarge is returned when reading a response body larger than
// [MaxResponseSize]
var ErrResponseTooLarge = errors.New("response from the CA is too large")

// New returns a [*http.Client] that sets the User-Agent header on all
// requests, has a timeout of [Timeout], and fails to read a response body
// larger than [MaxResponseSize].
func New() *http.Client {
	return &http.Client{
		Timeout: Timeout,
		Transport: &limitTransport{
			Max: MaxResponseSize,
			Transport: &headerTransport{
				Headers: map[string]string{
					"User-Agent": GenerateUserAgent(UserAgent),
				},
			},
		},
	}
}

// limitTransport fails to read a response body larger than Max, rather than
// cutting it short, so a partial certificate or revocation list is never
// used
type limitTransport struct {
	Transport http.RoundTripper
	Max       int64
}

func (t *limitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	res.Body = &limitedBody{rc: res.Body, remaining: t.Max}

	return res, nil
}

// limitedBody reads from rc until more than remaining bytes have been read,
// and then returns [ErrResponseTooLarge]
type limitedBody struct {
	rc        io.ReadCloser
	remaining int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return 0, ErrResponseTooLarge
	}
	// read one byte more than allowed, to tell a body of exactly the limit
	// from a larger one
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.rc.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n + int(b.remaining), ErrResponseTooLarge
	}

	return n, err
}

func (b *limitedBody) Close() error {
	return b.rc.Close()
}

// GenerateUserAgent returns a User-Agent header value for name that includes
// the version, OS and architecture.
func GenerateUserAgent(name string) string {
	return fmt.Sprintf("%s/%s (%s-%s)", name, version.Version(), runtime.GOOS, runtime.GOARCH)
}

// headerTransport sets the provided headers on each request
type headerTransport struct {
	Transport http.RoundTripper
	Headers   map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	newReq := req.Clone(req.Context())
	if newReq.Header == nil {
		newReq.Header = make(http.Header)
	}
	for key, value := range t.Headers {
		newReq.Header.Set(key, value)
	}

	// Use the underlying transport to execute the request
	return t.transport().RoundTrip(newReq)
}

func (t *headerTransport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	return http.DefaultTransport
}
