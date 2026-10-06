// Package httpclient provides the [*http.Client] used for requests to the
// Serverless SSH CA.
package httpclient

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
)

const (
	// UserAgent is the product name sent in the User-Agent header
	UserAgent = "Serverless-SSH-CA-Client"

	// Timeout is the timeout for requests made by the client
	Timeout = time.Second * 3
)

// New returns a [*http.Client] that sets the User-Agent header on all
// requests and has a timeout of [Timeout].
func New() *http.Client {
	return &http.Client{
		Timeout: Timeout,
		Transport: &headerTransport{
			Headers: map[string]string{
				"User-Agent": GenerateUserAgent(UserAgent),
			},
		},
	}
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
