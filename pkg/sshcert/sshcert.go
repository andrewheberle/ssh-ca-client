// The sshcert package provides convenience functions for dealing with SSH
// certificates
package sshcert

import (
	"bytes"
	"errors"
	"fmt"
	"time"

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

// RemoveStale removes every stale certificate from the agent a: user
// certificates signed by ca that expired at or before now. Plain keys,
// host certificates, certificates from other CAs and certificates that have
// not expired are left in place.
//
// The certificates that were removed are returned. A failure to remove one
// certificate does not stop the others being removed and all failures are
// returned together.
func RemoveStale(a agent.Agent, ca ssh.PublicKey, now time.Time) ([]*ssh.Certificate, error) {
	keys, err := a.List()
	if err != nil {
		return nil, fmt.Errorf("could not list agent keys: %w", err)
	}

	want := ca.Marshal()
	var removed []*ssh.Certificate
	var errs []error
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil {
			// not a key this package can parse, so it cannot be one of ours
			continue
		}

		c, ok := pub.(*ssh.Certificate)
		if !ok || c.CertType != ssh.UserCert || !bytes.Equal(c.SignatureKey.Marshal(), want) {
			continue
		}

		if !expired(c, now) {
			continue
		}

		if err := a.Remove(c); err != nil {
			errs = append(errs, fmt.Errorf("could not remove certificate with serial %d from agent: %w", c.Serial, err))
			continue
		}
		removed = append(removed, c)
	}

	return removed, errors.Join(errs...)
}

// expired reports whether c has expired at now, matching the check made by
// [ssh.CertChecker]. A certificate that never expires has not expired.
func expired(c *ssh.Certificate, now time.Time) bool {
	if c.ValidBefore == ssh.CertTimeInfinity {
		return false
	}

	unix := now.Unix()
	if unix < 0 {
		return false
	}

	return uint64(unix) >= c.ValidBefore
}
