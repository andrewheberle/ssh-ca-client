//go:build !windows

package tokenstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileStorePermissions(t *testing.T) {
	tests := []struct {
		name     string
		existing bool // a token file with wider permissions already exists
	}{
		{"new file", false},
		{"existing file", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "dir")
			path := filepath.Join(dir, "token")
			if tt.existing {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
					t.Fatal(err)
				}
				// WriteFile is subject to the umask
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}

			s, err := NewFileStore(path)
			if err != nil {
				t.Fatalf("NewFileStore() error = %v", err)
			}
			if err := s.Set("refresh-token"); err != nil {
				t.Fatalf("Set() error = %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Errorf("token file mode = %o, want 600", got)
			}

			if !tt.existing {
				info, err := os.Stat(dir)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.Mode().Perm(); got != 0700 {
					t.Errorf("token directory mode = %o, want 700", got)
				}
			}
		})
	}
}
