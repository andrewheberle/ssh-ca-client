package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// ignoredRegistryValues are values in the config key that are not
// configuration. installed0 is the per-user marker for the Start menu
// shortcut that the MSI writes under HKCU (templates/product.wxs).
var ignoredRegistryValues = []string{"installed0"}

// installerSubkey is the subkey of the HKLM config key where the MSI keeps
// the properties it was installed with, so an upgrade can reuse them
// (templates/product.wxs). Any other subkey is still an unknown key.
const installerSubkey = "installer"

// ignoredRegistrySubkey reports whether name, lower-cased, is a value in the
// installer subkey. The provider names a value in a subkey <subkey>.<value>.
func ignoredRegistrySubkey(name string) bool {
	return strings.HasPrefix(name, installerSubkey+".")
}

// oldPolicyValues are the value names, lower-cased, that the ADMX before
// v0.26.0 wrote to the Policy key and no release has read. Group Policy
// keeps applying them from a GPO until they are removed from it, so they are
// ignored in the Policy key rather than stopping the client from starting
// (docs/adr/0004). Its Issuer and Scopes values lower-case to current names,
// so they are read as before.
var oldPolicyValues = []string{
	"certificateauthorityurl",
	"clientid",
	"redirecturl",
	"trustedcertificateauthority",
}

// registryValues returns the configuration in raw, the values read from one
// registry key, with names lower-cased to match the configuration keys, as
// registry names are case insensitive. Values that are not configuration and
// empty values are left out. For the Policy key, values with the names in
// oldPolicyValues are also left out and their names, as written, returned in
// ignored. Any other value whose name is not a configuration key is an error.
// Names are read in order, so ignored and any error are the same every time.
func registryValues(raw map[string]any, policy bool) (values map[string]any, ignored []string, err error) {
	values = make(map[string]any)
	errs := make([]error, 0)
	for _, name := range slices.Sorted(maps.Keys(raw)) {
		value := raw[name]
		key := strings.ToLower(name)

		// the MSI writes values to the config key that are not
		// configuration, and existing installs keep them, so they are
		// ignored
		if slices.Contains(ignoredRegistryValues, key) || ignoredRegistrySubkey(key) {
			continue
		}

		// reported even when empty, as they are still left in the GPO
		if policy && slices.Contains(oldPolicyValues, key) {
			ignored = append(ignored, name)
			continue
		}

		// an empty value, such as a Policy enabled but left empty, is
		// treated as not set
		if emptyValue(value) {
			continue
		}

		if !slices.Contains(configKeys, key) {
			errs = append(errs, fmt.Errorf("%w: %q", ErrUnknownKey, name))
			continue
		}

		values[key] = value
	}

	if err := errors.Join(errs...); err != nil {
		return nil, nil, err
	}

	return values, ignored, nil
}

// emptyValue reports whether a registry value has no content: a blank string
// (REG_SZ), or a list whose entries are all blank (REG_MULTI_SZ). An empty
// value is treated as not set, so a Policy that is enabled but left empty
// does not replace the local setting, or a default, with nothing.
func emptyValue(value any) bool {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) == ""
	case []string:
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				return false
			}
		}
		return true
	case []any:
		for _, item := range v {
			if !emptyValue(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
