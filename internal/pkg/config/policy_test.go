package config

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// policyDir is the directory of the Group Policy templates in the repository
var policyDir = filepath.Join("..", "..", "..", "policy")

// admx is the part of an ADMX template the checks below need
type admx struct {
	Revision  string `xml:"revision,attr"`
	Namespace struct {
		Target struct {
			Namespace string `xml:"namespace,attr"`
		} `xml:"target"`
	} `xml:"policyNamespaces"`
	Resources struct {
		MinRequiredRevision string `xml:"minRequiredRevision,attr"`
	} `xml:"resources"`
	Policies []struct {
		Name     string `xml:"name,attr"`
		Key      string `xml:"key,attr"`
		Elements struct {
			Items []struct {
				XMLName   xml.Name
				ValueName string `xml:"valueName,attr"`
				Required  string `xml:"required,attr"`
			} `xml:",any"`
		} `xml:"elements"`
	} `xml:"policies>policy"`
}

// TestPolicyTemplates checks the Group Policy templates against the
// configuration, as nothing else loads them in CI.
func TestPolicyTemplates(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(policyDir, "ServerlessSSHCAClient.admx"))
	if err != nil {
		t.Fatalf("reading ADMX: %v", err)
	}
	var tmpl admx
	if err := xml.Unmarshal(data, &tmpl); err != nil {
		t.Fatalf("parsing ADMX: %v", err)
	}

	adml, err := os.ReadFile(filepath.Join(policyDir, "en-US", "ServerlessSSHCAClient.adml"))
	if err != nil {
		t.Fatalf("reading ADML: %v", err)
	}
	var resources struct {
		Revision string `xml:"revision,attr"`
	}
	if err := xml.Unmarshal(adml, &resources); err != nil {
		t.Fatalf("parsing ADML: %v", err)
	}

	// the namespace carries the version of the release that last changed
	// the templates (ADR 0003)
	if ns := tmpl.Namespace.Target.Namespace; !regexp.MustCompile(`^SSHCAClient_v\d+\.\d+\.\d+$`).MatchString(ns) {
		t.Errorf("namespace = %q, want SSHCAClient_v<version>", ns)
	}
	if tmpl.Revision != resources.Revision || tmpl.Resources.MinRequiredRevision != tmpl.Revision {
		t.Errorf("ADMX revision = %q, minRequiredRevision = %q, ADML revision = %q, want them equal",
			tmpl.Revision, tmpl.Resources.MinRequiredRevision, resources.Revision)
	}

	valueNames := make([]string, 0)
	for _, p := range tmpl.Policies {
		if !strings.EqualFold(p.Key, `Software\Policies\Serverless SSH CA Client`) {
			t.Errorf("policy %s key = %q, want the Policy key the client reads", p.Name, p.Key)
		}
		if len(p.Elements.Items) == 0 {
			t.Errorf("policy %s has no elements", p.Name)
		}

		for _, e := range p.Elements.Items {
			valueNames = append(valueNames, e.ValueName)

			// an enabled policy must not be left empty
			if e.Required != "true" {
				t.Errorf("policy %s element %s required = %q, want true", p.Name, e.XMLName.Local, e.Required)
			}
		}
	}

	// every setting has a policy, and every policy is a setting
	slices.Sort(valueNames)
	want := slices.Clone(configKeys)
	slices.Sort(want)
	if !slices.Equal(valueNames, want) {
		t.Errorf("policy value names = %q, want the configuration keys %q", valueNames, want)
	}
}
