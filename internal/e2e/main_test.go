//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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

	// testingPackage is the npm package name of the CA test server, which is
	// released with the CA
	testingPackage = "@andrewheberle/serverless-ssh-ca-testing"

	// testingPackageEnv is the environment variable that selects a CA test
	// server package to use in place of the version pinned in
	// package-lock.json
	testingPackageEnv = "E2E_CA_TESTING_PACKAGE"

	// overrideMarker is written to node_modules once a package has been
	// replaced, so a later run without caPackageEnv or testingPackageEnv
	// reinstalls the pinned versions
	overrideMarker = ".e2e-ca-override"

	// caRuntimeEnv is the environment variable that selects the runtime the
	// CA is run under
	caRuntimeEnv = "E2E_CA_RUNTIME"
)

// runtimes are the runtimes the test server can run the CA under
var runtimes = []string{"node", "workerd"}

var (
	// nodePath is the path to the node executable
	nodePath string

	// serverPath is the path to the CA test server command
	serverPath string

	// caRuntime is the runtime the CA is run under
	caRuntime string
)

func TestMain(m *testing.M) {
	if err := setupHarness(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: could not set up CA harness: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// setupHarness installs the npm dependencies of the CA harness when they are
// missing or out of date, then replaces the CA and test server packages with
// those named by caPackageEnv and testingPackageEnv if they are set.
func setupHarness() error {
	var err error

	nodePath, err = exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("node is required: %w", err)
	}

	caRuntime, err = harnessRuntime(os.Getenv(caRuntimeEnv))
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

	var specs []string
	for _, env := range []string{caPackageEnv, testingPackageEnv} {
		spec, err := packageSpec(env, os.Getenv(env))
		if err != nil {
			return err
		}
		if spec != "" {
			specs = append(specs, spec)
		}
	}

	if stale || len(specs) > 0 {
		npm, err := exec.LookPath("npm")
		if err != nil {
			return fmt.Errorf("npm is required: %w", err)
		}

		if stale {
			if err := run(dir, npm, "ci", "--no-audit", "--no-fund"); err != nil {
				return fmt.Errorf("installing dependencies: %w", err)
			}
		}

		if len(specs) > 0 {
			// mark the override before installing so a failed install is
			// also cleaned up by the next run
			if err := os.WriteFile(filepath.Join(dir, "node_modules", overrideMarker), []byte(strings.Join(specs, "\n")+"\n"), 0o644); err != nil {
				return fmt.Errorf("writing override marker: %w", err)
			}

			args := append([]string{"install", "--no-save", "--no-audit", "--no-fund"}, specs...)
			if err := run(dir, npm, args...); err != nil {
				return fmt.Errorf("installing %s: %w", strings.Join(specs, ", "), err)
			}
		}
	}

	for _, pkg := range []string{caPackage, testingPackage} {
		version, err := installedVersion(dir, pkg)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "e2e: using %s %s\n", pkg, version)
	}
	if len(specs) > 0 {
		fmt.Fprintf(os.Stderr, "e2e: installed from %s\n", strings.Join(specs, ", "))
	}
	fmt.Fprintf(os.Stderr, "e2e: running the CA under %s\n", caRuntime)

	serverPath = filepath.Join(dir, "node_modules", filepath.FromSlash(testingPackage), "dist", "cli.js")

	return nil
}

// harnessRuntime returns the runtime named by caRuntimeEnv, which defaults to
// Node.js
func harnessRuntime(runtime string) (string, error) {
	if runtime == "" {
		runtime = "node"
	}

	if !slices.Contains(runtimes, runtime) {
		return "", fmt.Errorf("%s must be \"node\" or \"workerd\", not %q", caRuntimeEnv, runtime)
	}

	return runtime, nil
}

// packageSpec returns the npm install spec from the environment variable env
// to use in place of a pinned package, or an empty string to use the pinned
// version. A spec naming an existing file or directory is made absolute
// because npm runs in the harness directory, while anything else (such as a
// version) is passed to npm as is.
func packageSpec(env, spec string) (string, error) {
	if spec == "" {
		return "", nil
	}

	if _, err := os.Stat(spec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return spec, nil
		}
		return "", fmt.Errorf("checking %s: %w", env, err)
	}

	abs, err := filepath.Abs(spec)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", env, err)
	}

	return abs, nil
}

// dependenciesStale reports whether the installed npm dependencies are
// missing, older than package-lock.json or include a replaced package
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

// installedVersion returns the version of the installed npm package pkg
func installedVersion(dir, pkg string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "node_modules", filepath.FromSlash(pkg), "package.json"))
	if err != nil {
		return "", fmt.Errorf("reading installed %s: %w", pkg, err)
	}

	var manifest struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return "", fmt.Errorf("parsing installed %s: %w", pkg, err)
	}

	return manifest.Version, nil
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
