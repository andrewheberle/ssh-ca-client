package sshcert

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AddedKey returns the SSH key to be added to the Agent
// On Windows LifetimeSecs is not set, so the key has no lifetime limit in
// the agent
//
// The Windows agent persists keys across reboots and holds one certificate
// per private key, so adding a renewed certificate replaces the previous one.
// A certificate for a private key that has been replaced is never replaced
// though, so it stays in the agent after it expires; see [RemoveStale].
func AddedKey(key any, cert *ssh.Certificate) agent.AddedKey {
	return agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		Comment:     cert.KeyId,
	}
}
