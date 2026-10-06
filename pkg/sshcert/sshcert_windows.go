package sshcert

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AddedKey returns the SSH key to be added to the Agent
// On Windows LifetimeSecs is not set, so the key has no lifetime limit in
// the agent
func AddedKey(key any, cert *ssh.Certificate) agent.AddedKey {
	return agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		Comment:     cert.KeyId,
	}
}
