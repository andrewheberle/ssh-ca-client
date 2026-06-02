package keyringpersistence

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/userconfig"
	"github.com/zalando/go-keyring"
)

func TestKeyringPersistence_Set(t *testing.T) {
	tests := []struct {
		name    string
		c       *userconfig.UserConfig
		p       *KeyringPersistence
		wantErr bool
	}{
		{
			"test save",
			&userconfig.UserConfig{
				Certificate:  []byte("cert"),
				PrivateKey:   []byte("key"),
				RefreshToken: []byte("token"),
			},
			&KeyringPersistence{
				user: "testuser",
			},
			false,
		},
	}

	keyring.MockInit()

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

			v, err := keyring.Get(keyringService, tt.p.user)
			if err != nil {
				t.Fatalf("Could not get value from keyring: %v", err)
			}

			var got userconfig.UserConfig
			if err := json.Unmarshal(fmt.Append(nil, v), &got); err != nil {
				t.Fatalf("problem parsing user config: %v; v = %v", err, v)
			}

			if !reflect.DeepEqual(&got, tt.c) {
				t.Errorf("Save() = %s, want %s", &got, tt.c)
			}
		})
	}
}

func TestNew(t *testing.T) {
	keyring.MockInit()

	p, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	got := p.Get()
	want := &userconfig.UserConfig{}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("New() = %v, want %v", got, want)
	}
}
