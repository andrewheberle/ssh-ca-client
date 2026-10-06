package cli_test

import "testing"

func TestExecute_Host(t *testing.T) {
	// the host sub-command exists but is not supported on Windows
	if err := execute(t, "host"); err == nil {
		t.Errorf("Execute() error = nil, want not supported error")
	}
}
