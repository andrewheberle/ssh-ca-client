//go:build !snap

package cli_test

import "testing"

// the host and krl sub-commands and the revoke --host flag are not included
// when building as a snap
func TestExecute_NoSnapFlags(t *testing.T) {
	runFlagTests(t, []flagTest{
		{"krl", []string{"krl", "--host", "--out", "krl.bin", "--force"}},
		{"krl short flags", []string{"krl", "-f", "krl.bin"}},
		{"revoke", []string{"revoke", "--host"}},
		{"host", []string{"host"}},
	})

	t.Run("krl with missing config", func(t *testing.T) {
		if err := execute(t, "--config", missingConfig, "krl"); err == nil {
			t.Errorf("Execute() error = nil, want error")
		}
	})
}
