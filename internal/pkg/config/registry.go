package config

import "strings"

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
