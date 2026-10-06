//go:build !windows

package sshcert

import (
	"math"
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
		{"one minute", time.Minute},
		{"one hour", time.Hour},
		{"one day", 24 * time.Hour},
		{"one year", 365 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := signCert(t, ca, key, ssh.UserCert, tt.valid)

			got := AddedKey(priv, cert)

			// allow some slack for time passing and truncation to whole seconds
			want := uint32(tt.valid.Seconds())
			if got.LifetimeSecs > want || got.LifetimeSecs < want-5 {
				t.Errorf("AddedKey() LifetimeSecs = %d, want approximately %d", got.LifetimeSecs, want)
			}
		})
	}
}

func TestAddedKeyLifetimeLimits(t *testing.T) {
	_, ca := newSigner(t)
	priv, key := newSigner(t)

	tests := []struct {
		name        string
		validBefore uint64
		want        uint32
	}{
		{"expired", uint64(time.Now().Add(-time.Hour).Unix()), 1},
		{"no expiry", ssh.CertTimeInfinity, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := signCert(t, ca, key, ssh.UserCert, time.Hour)
			cert.ValidBefore = tt.validBefore

			got := AddedKey(priv, cert)

			if got.LifetimeSecs != tt.want {
				t.Errorf("AddedKey() LifetimeSecs = %d, want %d", got.LifetimeSecs, tt.want)
			}
		})
	}
}

func TestLifetime(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	unix := uint64(now.Unix())

	tests := []struct {
		name        string
		validBefore uint64
		want        uint32
	}{
		{"one hour", unix + 3600, 3600},
		{"one second", unix + 1, 1},
		{"expires now", unix, 1},
		{"expired", unix - 3600, 1},
		{"zero", 0, 1},
		{"no expiry", ssh.CertTimeInfinity, 0},
		{"largest uint32", unix + math.MaxUint32, math.MaxUint32},
		{"beyond uint32", unix + math.MaxUint32 + 1, math.MaxUint32},
		{"largest int64", math.MaxInt64, math.MaxUint32},
		{"beyond int64", math.MaxInt64 + 1, math.MaxUint32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lifetime(tt.validBefore, now); got != tt.want {
				t.Errorf("lifetime() = %d, want %d", got, tt.want)
			}
		})
	}
}
