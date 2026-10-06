package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// checkResultPage checks a response is a result page with the wanted title
// served with the expected headers
func checkResultPage(t *testing.T, header http.Header, body, wantTitle string) {
	t.Helper()

	wantHeaders := map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Content-Security-Policy": resultCSP,
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
	}
	for k, want := range wantHeaders {
		if got := header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	if !strings.Contains(body, "<title>"+wantTitle+"</title>") {
		t.Errorf("body does not have title %q:\n%s", wantTitle, body)
	}
}

func TestWriteResult(t *testing.T) {
	tests := []struct {
		name         string
		code         int
		page         resultPage
		wantContains []string
		wantMissing  []string
	}{
		{
			name:         "success",
			code:         http.StatusOK,
			page:         successPage,
			wantContains: []string{"<h1>Login complete</h1>", "You can close this window."},
			wantMissing:  []string{`class="error"`},
		},
		{
			name:         "error",
			code:         http.StatusBadRequest,
			page:         errorPage("State mismatch"),
			wantContains: []string{`<body class="error">`, "<h1>Login failed</h1>", "<p>State mismatch.</p>", "try logging in again"},
		},
		{
			name:         "message is escaped",
			code:         http.StatusInternalServerError,
			page:         errorPage(`<script>alert("x")</script>`),
			wantContains: []string{"&lt;script&gt;"},
			wantMissing:  []string{"<script>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()

			if err := writeResult(rec, tt.code, tt.page); err != nil {
				t.Fatalf("writeResult() error = %v", err)
			}
			if rec.Code != tt.code {
				t.Errorf("status = %d, want %d", rec.Code, tt.code)
			}

			body := rec.Body.String()
			checkResultPage(t, rec.Header(), body, tt.page.Title)
			for _, s := range tt.wantContains {
				if !strings.Contains(body, s) {
					t.Errorf("body does not contain %q", s)
				}
			}
			for _, s := range tt.wantMissing {
				if strings.Contains(body, s) {
					t.Errorf("body contains %q", s)
				}
			}
		})
	}
}
