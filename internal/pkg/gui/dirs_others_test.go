//go:build !windows

package gui

import (
	"path/filepath"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/names"
)

func TestStateDir(t *testing.T) {
	tests := []struct {
		name       string
		snapCommon string
		xdgState   string
		home       string
		want       string
		wantErr    bool
	}{
		{"default", "", "", "/home/test", filepath.Join("/home/test/.local/state", names.AppName), false},
		{"xdg state home", "", "/var/state", "/home/test", filepath.Join("/var/state", names.AppName), false},
		{"relative xdg state home is ignored", "", "state", "/home/test", filepath.Join("/home/test/.local/state", names.AppName), false},
		{"snap", "/home/test/snap/ssh-ca-client/common", "/var/state", "/home/test", "/home/test/snap/ssh-ca-client/common", false},
		{"no home directory", "", "", "", "", true},
		{"snap path is cleaned", "/home/test/snap/../snap/ssh-ca-client/common/", "", "/home/test", "/home/test/snap/ssh-ca-client/common", false},
		{"snap path is root", "/", "", "/home/test", "", true},
		{"snap path is relative", "snap/common", "", "/home/test", "", true},
		{"relative home directory", "", "", "home/test", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SNAP_USER_COMMON", tt.snapCommon)
			t.Setenv("XDG_STATE_HOME", tt.xdgState)
			t.Setenv("HOME", tt.home)

			got, err := stateDir()
			if (err != nil) != tt.wantErr {
				t.Fatalf("stateDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("stateDir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidatedStatePath(t *testing.T) {
	tests := []struct {
		path    string
		want    string
		wantErr bool
	}{
		{"/home/test/.local/state/app", "/home/test/.local/state/app", false},
		{"/home/test/.local/state/app/", "/home/test/.local/state/app", false},
		{"/home/test/../other/./app", "/home/other/app", false},
		{"", "", true},
		{"relative/app", "", true},
		{"./app", "", true},
		{"/", "", true},
		{"//", "", true},
		{"/home/..", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := validatedStatePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatedStatePath() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("validatedStatePath() = %q, want %q", got, tt.want)
			}
		})
	}
}
