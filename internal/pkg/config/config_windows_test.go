package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

func TestConfigDirs(t *testing.T) {
	// set variable so we can test result
	if err := os.Setenv("AppData", "C:\\Users\\testuser\\AppData"); err != nil {
		panic(err)
	}

	tests := []struct {
		name    string // description of this test case
		want    string
		want2   string
		wantErr bool
	}{
		{"test results", filepath.Join("C:\\Users\\testuser\\AppData", names.AppName), filepath.Join("C:\\ProgramData", names.AppName), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2, gotErr := ConfigDirs()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ConfigDirs() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ConfigDirs() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("ConfigDirs() = %v, want %v", got, tt.want)
			}
			if got2 != tt.want2 {
				t.Errorf("ConfigDirs() = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func TestLogDir(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"test results", filepath.Join("C:\\Users\\testuser\\AppData", names.AppName), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LogDir()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LogDir() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LogDir() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("LogDir() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mergeConfig(t *testing.T) {
	tests := []struct {
		name    string
		policy  SystemConfig
		config  SystemConfig
		want    SystemConfig
		wantErr bool
	}{
		{"incomplete", SystemConfig{}, SystemConfig{}, SystemConfig{}, true},
		{"empty policy", SystemConfig{}, SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, false},
		{"empty config", SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, SystemConfig{}, SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, false},
		{"override all from policy", SystemConfig{Issuer: "overridden", ClientID: "overridden", Scopes: []string{"overridden"}, RedirectURL: "overridden", CertificateAuthorityURL: "overridden"}, SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, SystemConfig{Issuer: "overridden", ClientID: "overridden", Scopes: []string{"overridden"}, RedirectURL: "overridden", CertificateAuthorityURL: "overridden"}, false},
		{"override just issuer from policy", SystemConfig{Issuer: "overridden"}, SystemConfig{Issuer: "iss", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, SystemConfig{Issuer: "overridden", ClientID: "id", Scopes: []string{"openid"}, RedirectURL: "redirect", CertificateAuthorityURL: "ca"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := mergeConfig(tt.policy, tt.config)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("mergeConfig() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("mergeConfig() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mergeConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
