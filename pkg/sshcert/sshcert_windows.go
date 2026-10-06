package sshcert

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AddedKey returns the SSH key to be added to the Agent
// On non-Windows platforms this includes LifetimeSecs that aligns with
// the certificate expiry time
func AddedKey(key any, cert *ssh.Certificate) agent.AddedKey {
	return agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		Comment:     cert.KeyId,
	}
}
