package main

import (
	"context"
	"strings"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/version"
)

// TestRun checks what the user is told, and the exit code, when the GUI exits
// without running. These all return before the GUI writes anything.
func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantInform string // inform is called with a message containing this
		wantFail   string // fail is called with a message containing this
	}{
		{name: "version", args: []string{"--version"}, wantInform: "ssh-ca-client " + version.Version()},
		{name: "help", args: []string{"--help"}, wantInform: "--refresh-before"},
		{name: "unknown flag", args: []string{"--bogus"}, wantCode: 2, wantFail: "unknown flag: --bogus"},
		{name: "bad flag value", args: []string{"--life", "soon"}, wantCode: 2, wantFail: "--life"},
		{
			name:     "start-up error",
			args:     []string{"--life", "1h", "--refresh-before", "2h"},
			wantCode: 1,
			wantFail: "could not start: --refresh-before cannot be larger than --life",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origInform, origFail := inform, fail
			t.Cleanup(func() { inform, fail = origInform, origFail })

			var informed, failed []string
			inform = func(msg string) { informed = append(informed, msg) }
			fail = func(msg string) { failed = append(failed, msg) }

			if code := run(context.Background(), tt.args); code != tt.wantCode {
				t.Errorf("run() = %d, want %d", code, tt.wantCode)
			}

			check := func(kind string, got []string, want string) {
				t.Helper()
				switch {
				case want == "" && len(got) > 0:
					t.Errorf("%s called with %q, want no call", kind, got)
				case want != "" && (len(got) != 1 || !strings.Contains(got[0], want)):
					t.Errorf("%s called with %q, want one message containing %q", kind, got, want)
				}
			}
			check("inform", informed, tt.wantInform)
			check("fail", failed, tt.wantFail)
		})
	}
}
