//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCAPackageSpec(t *testing.T) {
	dir := t.TempDir()
	tarball := filepath.Join(dir, "ca.tgz")
	if err := os.WriteFile(tarball, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, tarball)
	if err != nil {
		t.Skipf("tarball not reachable by a relative path: %v", err)
	}

	tests := []struct {
		name string
		spec string
		want string
	}{
		{"unset", "", ""},
		{"version", "0.18.2", "0.18.2"},
		{"registry spec", caPackage + "@next", caPackage + "@next"},
		{"absolute path", tarball, tarball},
		{"relative path", rel, tarball},
		{"directory", dir, dir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := caPackageSpec(tt.spec)
			if err != nil {
				t.Fatalf("caPackageSpec(%q) error = %v", tt.spec, err)
			}
			if got != tt.want {
				t.Errorf("caPackageSpec(%q) = %q, want %q", tt.spec, got, tt.want)
			}
		})
	}
}

func TestDependenciesStale(t *testing.T) {
	old := time.Now().Add(-time.Hour)
	now := time.Now()

	tests := []struct {
		name      string
		installed *time.Time
		marker    bool
		want      bool
	}{
		{"not installed", nil, false, true},
		{"older than lock", &old, false, true},
		{"up to date", &now, false, false},
		{"up to date with override", &now, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			touch(t, filepath.Join(dir, "package-lock.json"), now.Add(-time.Minute))
			if tt.installed != nil {
				touch(t, filepath.Join(dir, "node_modules", ".package-lock.json"), *tt.installed)
			}
			if tt.marker {
				touch(t, filepath.Join(dir, "node_modules", overrideMarker), now)
			}

			got, err := dependenciesStale(dir)
			if err != nil {
				t.Fatalf("dependenciesStale() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("dependenciesStale() = %v, want %v", got, tt.want)
			}
		})
	}
}

func touch(t *testing.T, name string, mtime time.Time) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}
