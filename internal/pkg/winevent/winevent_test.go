//go:build windows

package winevent

import (
	"errors"
	"log/slog"
	"testing"
	"time"
)

func TestHandler_format(t *testing.T) {
	tests := []struct {
		name    string
		handler func(h *Handler) *Handler
		msg     string
		attrs   []slog.Attr
		want    string
	}{
		{
			name:  "attributes on their own lines",
			msg:   "certificate refreshed",
			attrs: []slog.Attr{slog.Int("failures", 2), slog.String("state", "ok")},
			want:  "certificate refreshed\nfailures: 2\nstate: ok",
		},
		{
			name:  "line feed in a value",
			msg:   "could not refresh certificate",
			attrs: []slog.Attr{slog.Any("error", errors.New("token exchange failed\nfailures: 0"))},
			want:  "could not refresh certificate\nerror: token exchange failed\\nfailures: 0",
		},
		{
			name:  "carriage return and line feed in a value",
			msg:   "login failed",
			attrs: []slog.Attr{slog.String("response", "400 Bad Request\r\nResponse: {}")},
			want:  "login failed\nresponse: 400 Bad Request\\r\\nResponse: {}",
		},
		{
			name: "line feed in the message",
			msg:  "first line\nsecond line",
			want: "first line\\nsecond line",
		},
		{
			name:  "line feed in a key",
			msg:   "message",
			attrs: []slog.Attr{slog.String("bad\nkey", "value")},
			want:  "message\nbad\\nkey: value",
		},
		{
			name:  "line feed in a group",
			msg:   "message",
			attrs: []slog.Attr{slog.Group("request", slog.String("path", "/callback\nstate: ok"))},
			want:  "message\nrequest.path: /callback\\nstate: ok",
		},
		{
			name: "line feed in an attribute from WithAttrs",
			handler: func(h *Handler) *Handler {
				return h.WithGroup("auth").WithAttrs([]slog.Attr{slog.String("issuer", "https://idp\nfake: line")}).(*Handler)
			},
			msg:  "message",
			want: "message\nauth.issuer: https://idp\\nfake: line",
		},
		{
			name:  "backslashes left alone",
			msg:   "log directory",
			attrs: []slog.Attr{slog.String("path", `C:\Users\user\AppData\Local`)},
			want:  `log directory` + "\n" + `path: C:\Users\user\AppData\Local`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{eventID: 1}
			if tt.handler != nil {
				h = tt.handler(h)
			}

			r := slog.NewRecord(time.Time{}, slog.LevelInfo, tt.msg, 0)
			r.AddAttrs(tt.attrs...)

			if got := h.format(r); got != tt.want {
				t.Errorf("format() = %q, want %q", got, tt.want)
			}
		})
	}
}
