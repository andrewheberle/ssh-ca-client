package httpclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
)

func TestGenerateUserAgent(t *testing.T) {
	want := fmt.Sprintf("%s/%s (%s-%s)", UserAgent, version.Version(), runtime.GOOS, runtime.GOARCH)

	if got := GenerateUserAgent(UserAgent); got != want {
		t.Errorf("GenerateUserAgent() = %q, want %q", got, want)
	}
}

func TestNew(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
	}))
	defer srv.Close()

	c := New()
	if c.Timeout != Timeout {
		t.Errorf("Timeout = %v, want %v", c.Timeout, Timeout)
	}

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("User-Agent", "overridden")

	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = res.Body.Close()

	if want := GenerateUserAgent(UserAgent); got != want {
		t.Errorf("User-Agent = %q, want %q", got, want)
	}
	if req.Header.Get("User-Agent") != "overridden" {
		t.Errorf("original request was modified")
	}
}
