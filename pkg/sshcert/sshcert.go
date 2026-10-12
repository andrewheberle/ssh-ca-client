// The sshcert package provides convenience functions for dealing with SSH
// certificates
package sshcert

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ParseCert will parse the provided byte slice (in OpenSSH certificate format)
// and return a [*ssh.Certificate].
//
// Only the first certificate in certBytes is parsed and any remaining data
// is ignored.
//
// Any parsing errors will result in a nil [*ssh.Certificate] returned along
// with the error.
func ParseCert(certBytes []byte) (*ssh.Certificate, error) {
	// Parse the certificate.
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key/certificate: %w", err)
	}

	// Type assert to *ssh.Certificate. If it's not a certificate, this will fail.
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("the provided key is not a SSH certificate, it is a %T", parsedKey)
	}

	return cert, nil
}

// RemoveFromAgent removes cert from the agent a, leaving any other identities
// (such as the plain private key for the certificate) in place. It does
// nothing if the agent does not hold cert.
func RemoveFromAgent(a agent.Agent, cert *ssh.Certificate) error {
	keys, err := a.List()
	if err != nil {
		return fmt.Errorf("could not list agent keys: %w", err)
	}

	want := cert.Marshal()
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), want) {
			if err := a.Remove(cert); err != nil {
				return fmt.Errorf("could not remove certificate from agent: %w", err)
			}

			return nil
		}
	}

	return nil
}
