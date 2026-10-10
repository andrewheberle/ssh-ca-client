//go:build snap

package cli_test

import "testing"

// the host and krl sub-commands and the revoke --host flag must not be
// included when building as a snap
func TestExecute_SnapExcluded(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"host", []string{"host"}},
		{"krl", []string{"krl"}},
		{"revoke --host", []string{"revoke", "--host"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := execute(t, append(tt.args, "--help")...); err == nil {
				t.Errorf("Execute(%q) error = nil, want error", tt.args)
			}
		})
	}
}
