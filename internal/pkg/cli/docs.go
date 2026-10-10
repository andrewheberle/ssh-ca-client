//go:build !snap && !windows

package cli

//go:generate go run ./gendocs ../../../docs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// docsPrefix is the file name prefix of all generated documentation
const docsPrefix = "ssh-ca-client-cli"

// docDefaults overrides flag defaults, by command name then flag name, that
// depend on the system the documentation is generated on
var docDefaults = map[string]map[string]string{
	"host": {"principals": "[<hostname>]"},
}

// GenerateDocs writes markdown documentation for each command to dir,
// replacing any previously generated documentation.
//
// This is only built without the snap tag and on non-Windows platforms, so
// the documentation covers all commands and their flags.
func GenerateDocs(dir string) error {
	root, err := Command()
	if err != nil {
		return fmt.Errorf("building command tree: %w", err)
	}

	// remove previously generated docs so removed commands are not left behind
	existing, err := filepath.Glob(filepath.Join(dir, docsPrefix+"*.md"))
	if err != nil {
		return fmt.Errorf("finding existing docs: %w", err)
	}
	for _, f := range existing {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("removing existing docs: %w", err)
		}
	}

	return generateDocs(root, dir)
}

func generateDocs(cmd *cobra.Command, dir string) (err error) {
	for _, c := range cmd.Commands() {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if err := generateDocs(c, dir); err != nil {
			return err
		}
	}

	for name, value := range docDefaults[cmd.Name()] {
		flag := cmd.Flags().Lookup(name)
		if flag == nil {
			return fmt.Errorf("overriding default of %q: flag %q not found", cmd.CommandPath(), name)
		}
		flag.DefValue = value
	}

	// avoid the generated date in the output so docs only change with the commands
	cmd.DisableAutoGenTag = true

	f, err := os.Create(filepath.Join(dir, docFilename(cmd.CommandPath())))
	if err != nil {
		return fmt.Errorf("creating docs for %q: %w", cmd.CommandPath(), err)
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()

	if err := doc.GenMarkdownCustom(cmd, f, docLink); err != nil {
		return fmt.Errorf("generating docs for %q: %w", cmd.CommandPath(), err)
	}

	return nil
}

// docFilename returns the file name for the docs of the command at path, such
// as "ssh-ca-client-cli-host.md" for "ssh-ca-client-cli host"
func docFilename(path string) string {
	return strings.ReplaceAll(path, " ", "-") + ".md"
}

// docLink converts the link cobra generates, which joins command names with
// "_", to match the names from docFilename
func docLink(name string) string {
	return strings.ReplaceAll(name, "_", "-")
}
