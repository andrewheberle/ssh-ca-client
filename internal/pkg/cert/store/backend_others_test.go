//go:build !windows

package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileBackend_Permissions(t *testing.T) {
	keypath := filepath.Join(t.TempDir(), "id_ecdsa")
	b := NewFileBackend(keypath)

	if err := b.Put(Key, []byte("key")); err != nil {
		t.Fatalf("Put(Key) error = %v", err)
	}
	if err := b.Put(Cert, []byte("cert")); err != nil {
		t.Fatalf("Put(Cert) error = %v", err)
	}

	tests := []struct {
		name string
		path string
		want os.FileMode
	}{
		{"private key", keypath, 0600},
		{"certificate", keypath + "-cert.pub", 0644},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("Stat() error = %v", err)
			}
			if got := fi.Mode().Perm(); got != tt.want {
				t.Errorf("mode = %v, want %v", got, tt.want)
			}
		})
	}
}
