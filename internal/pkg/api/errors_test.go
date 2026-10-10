package api_test

import (
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
)

func TestStatusError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		want       string
	}{
		{"one message", 500, `{"success":false,"errors":[{"code":1,"message":"krl unavailable"}]}`, "bad status code: 500: krl unavailable"},
		{"several messages", 500, `{"success":false,"errors":[{"code":1,"message":"krl unavailable"},{"code":2,"message":"try again"}]}`, "bad status code: 500: krl unavailable; try again"},
		{"validation error with path", 422, `{"success":false,"errors":[{"code":1,"message":"invalid principals","path":["principals"]}]}`, "bad status code: 422: invalid principals"},
		{"empty message skipped", 403, `{"success":false,"errors":[{"code":1,"message":""},{"code":2,"message":"forbidden"}]}`, "bad status code: 403: forbidden"},
		{"no messages", 500, `{"success":false,"errors":[]}`, "bad status code: 500"},
		{"no errors field", 401, `{"success":false}`, "bad status code: 401"},
		{"not json", 502, "<html>bad gateway</html>", "bad status code: 502"},
		{"empty body", 404, "", "bad status code: 404"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := api.StatusError(tt.statusCode, []byte(tt.body)).Error(); got != tt.want {
				t.Errorf("StatusError() = %q, want %q", got, tt.want)
			}
		})
	}
}
