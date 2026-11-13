package config

import "testing"

func TestEmptyValue(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"empty string", "", true},
		{"blank string", "  \t", true},
		{"string", "client", false},
		{"no strings", []string{}, true},
		{"nil strings", []string(nil), true},
		{"blank strings", []string{"", " "}, true},
		{"strings", []string{"openid"}, false},
		{"strings with a blank", []string{"", "openid"}, false},
		{"no items", []any{}, true},
		{"blank items", []any{"", " "}, true},
		{"items", []any{"openid"}, false},
		{"number", uint32(0), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := emptyValue(tt.value); got != tt.want {
				t.Errorf("emptyValue(%#v) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
