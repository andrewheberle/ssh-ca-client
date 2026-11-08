//go:build !windows

package sshcert

import (
	"math"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AddedKey returns the SSH key to be added to the Agent
// On non-Windows platforms this includes LifetimeSecs that aligns with
// the certificate expiry time
func AddedKey(key any, cert *ssh.Certificate) agent.AddedKey {
	return agent.AddedKey{
		PrivateKey:   key,
		Certificate:  cert,
		Comment:      cert.KeyId,
		LifetimeSecs: lifetime(cert.ValidBefore, time.Now()),
	}
}

// lifetime returns the number of seconds from now until validBefore for use
// as an agent key lifetime.
//
// A certificate that never expires returns 0 (no lifetime limit), an expired
// certificate returns 1 so it is removed from the agent almost immediately and
// any lifetime too large for a uint32 is clamped to [math.MaxUint32].
func lifetime(validBefore uint64, now time.Time) uint32 {
	if validBefore == ssh.CertTimeInfinity {
		return 0
	}

	if validBefore > math.MaxInt64 {
		return math.MaxUint32
	}

	secs := int64(validBefore) - now.Unix()
	switch {
	case secs < 1:
		return 1
	case secs > math.MaxUint32:
		return math.MaxUint32
	}

	return uint32(secs)
}
