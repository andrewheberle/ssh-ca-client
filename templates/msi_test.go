// Package templates holds the WiX sources the MSI is built from. It has no Go
// code, only tests of the sources.
package templates

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

// guidV4 matches a random (version 4, RFC 4122 variant) GUID
var guidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestProductGUIDs checks that the MSI's UpgradeCode and every component GUID
// is a randomly generated GUID used only once. Windows Installer counts
// components by GUID across every product on the machine, so a hand-written
// GUID that another product also uses stops uninstall removing that
// component (#234).
func TestProductGUIDs(t *testing.T) {
	data, err := os.ReadFile("product.wxs")
	if err != nil {
		t.Fatalf("reading product.wxs: %v", err)
	}

	guids := map[string]string{} // GUID to what it identifies

	// the UpgradeCode is set with a preprocessor define
	upgrade := regexp.MustCompile(`<\?define UpgradeCode="([^"]+)"\?>`).FindSubmatch(data)
	if upgrade == nil {
		t.Fatal("no UpgradeCode define in product.wxs")
	}
	guids[strings.ToLower(string(upgrade[1]))] = "UpgradeCode"

	d := xml.NewDecoder(strings.NewReader(string(data)))
	components := 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("parsing product.wxs: %v", err)
		}

		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "Component" {
			continue
		}
		components++

		var id, guid string
		for _, a := range start.Attr {
			switch a.Name.Local {
			case "Id":
				id = a.Value
			case "Guid":
				guid = strings.ToLower(a.Value)
			}
		}
		if guid == "" {
			t.Errorf("component %s has no Guid", id)
			continue
		}
		if other, ok := guids[guid]; ok {
			t.Errorf("component %s has the same Guid as %s: %s", id, other, guid)
		}
		guids[guid] = "component " + id
	}

	if components == 0 {
		t.Fatal("no components found in product.wxs")
	}

	for guid, what := range guids {
		if !guidV4.MatchString(guid) {
			t.Errorf("%s = %s, want a randomly generated (version 4) GUID", what, guid)
		}
	}
}
