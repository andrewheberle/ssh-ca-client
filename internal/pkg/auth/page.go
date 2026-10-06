package auth

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/result.html
var templates embed.FS

var resultTemplate = template.Must(template.ParseFS(templates, "templates/result.html"))

// resultCSP only allows the inline styles of the result page. The page makes
// no other requests.
const resultCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// resultPage is the data for the result page shown in the browser at the end
// of the login flow
type resultPage struct {
	Title    string
	Messages []string
	Error    bool
}

// writeResult renders page to w with the provided status code. If the page
// cannot be rendered a plain text response is written instead.
func writeResult(w http.ResponseWriter, code int, page resultPage) error {
	var buf bytes.Buffer
	if err := resultTemplate.Execute(&buf, page); err != nil {
		http.Error(w, page.Title, code)
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", resultCSP)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, err := w.Write(buf.Bytes())

	return err
}

// successPage is shown when the login flow completes
var successPage = resultPage{
	Title:    "Login complete",
	Messages: []string{"Your SSH certificate request will continue in the background. You can close this window."},
}

// errorPage returns the page shown when the login flow fails with msg
func errorPage(msg string) resultPage {
	return resultPage{
		Title:    "Login failed",
		Messages: []string{msg + ".", "Close this window and try logging in again."},
		Error:    true,
	}
}
