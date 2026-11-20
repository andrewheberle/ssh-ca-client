package config

import (
	"errors"
	"reflect"
	"slices"
	"testing"
)

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

func TestRegistryValues(t *testing.T) {
	tests := []struct {
		name        string
		raw         map[string]any
		policy      bool
		want        map[string]any
		wantIgnored []string
		wantErr     error
	}{
		{
			name: "names lower-cased",
			raw:  map[string]any{"Client_ID": "client", "ISSUER": "https://idp.example.com/"},
			want: map[string]any{"client_id": "client", "issuer": "https://idp.example.com/"},
		},
		{
			name: "empty values not set",
			raw:  map[string]any{"client_id": "", "scopes": []string{" "}},
			want: map[string]any{},
		},
		{
			name: "installer values ignored",
			raw:  map[string]any{"client_id": "client", "Installed0": uint32(1), "Installer.Version": "1.0.1"},
			want: map[string]any{"client_id": "client"},
		},
		{
			name:    "unknown value",
			raw:     map[string]any{"client_id": "client", "scope": []string{"openid"}},
			wantErr: ErrUnknownKey,
		},
		{
			// as in 1.0.x, an empty value is not set, so its name is
			// not checked
			name: "empty unknown value",
			raw:  map[string]any{"client_id": "client", "": ""},
			want: map[string]any{"client_id": "client"},
		},
		{
			name:    "other subkey",
			raw:     map[string]any{"settings.scopes": []string{"openid"}},
			wantErr: ErrUnknownKey,
		},
		{
			// the ADMX before v0.26.0 wrote these names, which Group
			// Policy keeps applying until they are removed from the GPO
			name: "old policy names ignored in the policy",
			raw: map[string]any{
				"client_id":                   "client",
				"ClientID":                    "old",
				"RedirectURL":                 "http://localhost:3000/auth/callback",
				"CertificateAuthorityURL":     "https://ca.example.com/",
				"TrustedCertificateAuthority": "ssh-ed25519 AAAA",
			},
			policy:      true,
			want:        map[string]any{"client_id": "client"},
			wantIgnored: []string{"CertificateAuthorityURL", "ClientID", "RedirectURL", "TrustedCertificateAuthority"},
		},
		{
			name:        "empty old policy names still reported",
			raw:         map[string]any{"clientid": ""},
			policy:      true,
			want:        map[string]any{},
			wantIgnored: []string{"clientid"},
		},
		{
			// only the old ADMX wrote these, so in the config they are a
			// mistake like any other unknown key
			name:    "old policy names rejected in the config",
			raw:     map[string]any{"ClientID": "old"},
			wantErr: ErrUnknownKey,
		},
		{
			// these lower-case to current names, so they are read as
			// before
			name:   "old policy names that match current names",
			raw:    map[string]any{"Issuer": "https://idp.example.com/", "Scopes": []string{"openid"}},
			policy: true,
			want:   map[string]any{"issuer": "https://idp.example.com/", "scopes": []string{"openid"}},
		},
		{
			name:    "unknown value in the policy",
			raw:     map[string]any{"ClientID": "old", "redirect-url": "http://localhost:8250/cb"},
			policy:  true,
			wantErr: ErrUnknownKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ignored, err := registryValues(tt.raw, tt.policy)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("registryValues() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("registryValues() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("registryValues() = %#v, want %#v", got, tt.want)
			}
			if !slices.Equal(ignored, tt.wantIgnored) {
				t.Errorf("registryValues() ignored = %q, want %q", ignored, tt.wantIgnored)
			}
		})
	}
}
