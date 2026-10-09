//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	// harnessDir is the directory containing the CA harness
	harnessDir = "testdata/ca"

	// caPackage is the npm package name of the CA
	caPackage = "@andrewheberle/serverless-ssh-ca"

	// caPackageEnv is the environment variable that selects a CA package to
	// test against in place of the version pinned in package-lock.json
	caPackageEnv = "E2E_CA_PACKAGE"

	// overrideMarker is written to node_modules once the CA package has been
	// replaced, so a later run without caPackageEnv reinstalls the pinned
	// version
	overrideMarker = ".e2e-ca-override"

	// caRuntimeEnv is the environment variable that selects the runtime the
	// CA is run under
	caRuntimeEnv = "E2E_CA_RUNTIME"
)

// harnessScripts are the harness scripts that run the CA under each runtime
var harnessScripts = map[string]string{
	"node":    "server.mjs",
	"workerd": "workerd.mjs",
}

var (
	// nodePath is the path to the node executable
	nodePath string

	// serverPath is the path to the CA harness script
	serverPath string
)

func TestMain(m *testing.M) {
	if err := setupHarness(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: could not set up CA harness: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// setupHarness installs the npm dependencies of the CA harness when they are
// missing or out of date, then replaces the CA package with the one named by
// caPackageEnv if it is set.
func setupHarness() error {
	var err error

	nodePath, err = exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("node is required: %w", err)
	}

	runtime, script, err := harnessScript(os.Getenv(caRuntimeEnv))
	if err != nil {
		return err
	}

	dir, err := filepath.Abs(harnessDir)
	if err != nil {
		return err
	}

	stale, err := dependenciesStale(dir)
	if err != nil {
		return err
	}

	spec, err := caPackageSpec(os.Getenv(caPackageEnv))
	if err != nil {
		return err
	}

	if stale || spec != "" {
		npm, err := exec.LookPath("npm")
		if err != nil {
			return fmt.Errorf("npm is required: %w", err)
		}

		if stale {
			if err := run(dir, npm, "ci", "--no-audit", "--no-fund"); err != nil {
				return fmt.Errorf("installing dependencies: %w", err)
			}
		}

		if spec != "" {
			// mark the override before installing so a failed install is
			// also cleaned up by the next run
			if err := os.WriteFile(filepath.Join(dir, "node_modules", overrideMarker), []byte(spec+"\n"), 0o644); err != nil {
				return fmt.Errorf("writing override marker: %w", err)
			}

			if err := run(dir, npm, "install", "--no-save", "--no-audit", "--no-fund", spec); err != nil {
				return fmt.Errorf("installing %s from %s: %w", caPackage, spec, err)
			}
		}
	}

	version, err := installedVersion(dir)
	if err != nil {
		return err
	}
	if spec != "" {
		fmt.Fprintf(os.Stderr, "e2e: testing against %s %s from %s under %s\n", caPackage, version, spec, runtime)
	} else {
		fmt.Fprintf(os.Stderr, "e2e: testing against %s %s under %s\n", caPackage, version, runtime)
	}

	serverPath = filepath.Join(dir, script)

	return nil
}

// harnessScript returns the runtime named by caRuntimeEnv, which defaults to
// Node.js, and the harness script that runs the CA under it.
func harnessScript(runtime string) (string, string, error) {
	if runtime == "" {
		runtime = "node"
	}

	script, ok := harnessScripts[runtime]
	if !ok {
		return "", "", fmt.Errorf("%s must be \"node\" or \"workerd\", not %q", caRuntimeEnv, runtime)
	}

	return runtime, script, nil
}

// caPackageSpec returns the npm install spec to use in place of the pinned CA
// package, or an empty string to use the pinned version. A spec naming an
// existing file or directory is made absolute because npm runs in the harness
// directory, while anything else (such as a version) is passed to npm as is.
func caPackageSpec(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}

	if _, err := os.Stat(spec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return spec, nil
		}
		return "", fmt.Errorf("checking %s: %w", caPackageEnv, err)
	}

	abs, err := filepath.Abs(spec)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", caPackageEnv, err)
	}

	return abs, nil
}

// dependenciesStale reports whether the installed npm dependencies are
// missing, older than package-lock.json or include a replaced CA package
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

	if _, err := os.Stat(filepath.Join(dir, "node_modules", overrideMarker)); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}

	return installed.ModTime().Before(lock.ModTime()), nil
}

// installedVersion returns the version of the installed CA package
func installedVersion(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "node_modules", filepath.FromSlash(caPackage), "package.json"))
	if err != nil {
		return "", fmt.Errorf("reading installed %s: %w", caPackage, err)
	}

	var pkg struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &pkg); err != nil {
		return "", fmt.Errorf("parsing installed %s: %w", caPackage, err)
	}

	return pkg.Version, nil
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
