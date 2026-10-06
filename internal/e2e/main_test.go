//go:build e2e

package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// harnessDir is the directory containing the Node.js CA harness
const harnessDir = "testdata/ca"

var (
	// nodePath is the path to the node executable
	nodePath string

	// serverPath is the path to the bundled CA harness
	serverPath string
)

func TestMain(m *testing.M) {
	if err := buildHarness(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: could not build CA harness: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// buildHarness installs the npm dependencies of the CA harness when they are
// missing or out of date and then bundles it.
func buildHarness() error {
	var err error

	nodePath, err = exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("node is required: %w", err)
	}

	dir, err := filepath.Abs(harnessDir)
	if err != nil {
		return err
	}

	stale, err := dependenciesStale(dir)
	if err != nil {
		return err
	}

	if stale {
		npm, err := exec.LookPath("npm")
		if err != nil {
			return fmt.Errorf("npm is required: %w", err)
		}

		if err := run(dir, npm, "ci", "--no-audit", "--no-fund"); err != nil {
			return fmt.Errorf("installing dependencies: %w", err)
		}
	}

	if err := run(dir, nodePath, "build.mjs"); err != nil {
		return fmt.Errorf("bundling: %w", err)
	}

	serverPath = filepath.Join(dir, "dist", "server.mjs")

	return nil
}

// dependenciesStale reports whether the installed npm dependencies are
// missing or older than package-lock.json
func dependenciesStale(dir string) (bool, error) {
	lock, err := os.Stat(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return false, err
	}

	// npm writes this file on every install
	installed, err := os.Stat(filepath.Join(dir, "node_modules", ".package-lock.json"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	} else if err != nil {
		return false, err
	}

	return installed.ModTime().Before(lock.ModTime()), nil
}

func run(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", cmd, err, out)
	}

	return nil
}
