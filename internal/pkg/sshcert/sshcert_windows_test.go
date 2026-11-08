package sshcert

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestAddedKeyLifetime(t *testing.T) {
	_, ca := newSigner(t)
	priv, key := newSigner(t)

	tests := []struct {
		name  string
		valid time.Duration
	}{
		{"one hour", time.Hour},
		{"one day", 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := signCert(t, ca, key, ssh.UserCert, tt.valid)

			got := AddedKey(priv, cert)

			// on Windows no lifetime is set for keys added to the agent
			if got.LifetimeSecs != 0 {
				t.Errorf("AddedKey() LifetimeSecs = %d, want 0", got.LifetimeSecs)
			}
		})
	}
}
