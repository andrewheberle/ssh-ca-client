package persistence

import (
	"os"
	"reflect"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"
	"sigs.k8s.io/yaml"
)

func TestYamlPersistence_Save(t *testing.T) {
	tests := []struct {
		name    string
		c       *userconfig.UserConfig
		p       *YamlPersistence
		wantErr bool
	}{
		{
			"test save",
			&userconfig.UserConfig{
				Certificate:  []byte("cert"),
				PrivateKey:   []byte("key"),
				RefreshToken: []byte("token"),
			},
			&YamlPersistence{
				name: "testdata/ignored.yml",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := tt.p.Set(tt.c)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Save() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Save() succeeded unexpectedly")
			}

			var got userconfig.UserConfig
			b, err := os.ReadFile(tt.p.name)
			if err != nil {
				t.Fatalf("Could not read file from Save(): %v", err)
			}

			if err := yaml.Unmarshal(b, &got); err != nil {
				t.Fatalf("Could not parse file from Save(): %v", err)
			}

			if !reflect.DeepEqual(got, tt.c) {
				t.Errorf("Save() = %v, want %v", got, tt.c)
			}
		})
	}
}
