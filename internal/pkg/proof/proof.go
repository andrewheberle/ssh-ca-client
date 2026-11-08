// Package proof generates and parses the proofs of possession the client
// sends to the CA, which show that the client holds a private key.
//
// A proof is bound to the request it is sent with: it signs the current
// timestamp, the key's fingerprint and the request's method and path, so it
// cannot be replayed against another endpoint or with other path parameters.
// See the CA's ADR 0006 for the format.
package proof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// Proof is a proof of possession made by [GenerateForRequest] or read by
// [Parse].
type Proof struct {
	timestamp   int64
	fingerprint string
	signature   *sshsig.Signature
}

// RequestNamespace is the SSHSIG namespace a proof is signed in.
const RequestNamespace = "request-proof-of-possession@com.github.serverless-ssh-ca.andrewheberle"

// getTimestamp is a variable so it can be overridden in tests
var getTimestamp = func() int64 {
	return time.Now().UnixMilli()
}

// GenerateForRequest creates a proof that is bound to a request, so it cannot
// be replayed against another endpoint or with other path parameters (such as
// a different certificate serial), by signing the current timestamp, the
// public key fingerprint and the request using SSHSIG with the provided
// signer and the [RequestNamespace] namespace.
//
// The method is the HTTP method of the request and path is the path of the
// request as the CA serves it, with any parameters filled in, for example
// "/api/v4/user/certificates/12345678901234567890".
//
// The signed data is "<timestamp>.<fingerprint>.<METHOD> <path>" and the proof
// is returned as a string in the format:
// <timestamp>.<fingerprint>.<base64 armored_signature>
func GenerateForRequest(signer ssh.Signer, method, path string) (*Proof, error) {
	// generate data to sign
	timestamp := getTimestamp()
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	data := requestData(timestamp, fingerprint, method, path)

	// generate signature of data
	sig, err := sshsig.Sign(bytes.NewReader(data), signer, sshsig.HashSHA512, RequestNamespace)
	if err != nil {
		return nil, err
	}

	// return encoded data
	return &Proof{timestamp: timestamp, fingerprint: fingerprint, signature: sig}, nil
}

// Parse takes a proof string and validates it is in the expected format, returning a Proof struct if valid.
func Parse(proof string) (Proof, error) {
	timestamp, fingerprint, signature, err := parse(proof)
	if err != nil {
		return Proof{}, fmt.Errorf("invalid proof format: %v", err)
	}

	return Proof{timestamp: timestamp, fingerprint: fingerprint, signature: signature}, nil
}

func requestData(timestamp int64, fingerprint, method, path string) []byte {
	return fmt.Appendf(nil, "%d.%s.%s %s", timestamp, fingerprint, strings.ToUpper(method), path)
}

func parse(proof string) (timestamp int64, fingerprint string, signature *sshsig.Signature, err error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return 0, "", nil, fmt.Errorf("invalid proof format")
	}

	// we dont verify fingerprint here, just return it
	fingerprint = parts[1]

	// decode timestamp (this does not verify it is within an acceptable range, just that it is a valid integer)
	timestamp, err = strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid timestamp in proof: %v", err)
	}

	// check signature format is expected and can be parsed back
	sig, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid signature encoding in proof: %v", err)
	}

	// dearmor signature
	signature, err = sshsig.Unarmor(sig)
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid signature format in proof: %v", err)
	}

	return timestamp, fingerprint, signature, nil
}

// VerifyRequest checks the proof is valid for the request with the provided
// method and path by verifying the signature and that the timestamp is within
// the allowed range.
//
// This verifies a proof made by [GenerateForRequest].
func (p Proof) VerifyRequest(pub ssh.PublicKey, method, path string, allowedrange time.Duration) error {
	// verify timestamp is within allowed range (this is to prevent replay attacks, but allows for some clock skew between client and server)
	proofTime := time.UnixMilli(p.timestamp)
	now := getTimestamp()
	if proofTime.Before(time.UnixMilli(now).Add(-allowedrange)) || proofTime.After(time.UnixMilli(now).Add(allowedrange)) {
		return fmt.Errorf("proof timestamp is outside of allowed time range")
	}

	// verify fingerprint matches signer
	expectedFingerprint := ssh.FingerprintSHA256(pub)
	if p.fingerprint != expectedFingerprint {
		return fmt.Errorf("proof fingerprint did not match (expected fingerprint %s, got %s)", expectedFingerprint, p.fingerprint)
	}

	// verify signature
	data := requestData(p.timestamp, p.fingerprint, method, path)
	if err := sshsig.Verify(bytes.NewReader(data), p.signature, pub, sshsig.HashSHA512, RequestNamespace); err != nil {
		return fmt.Errorf("signature did not verify: %v", err)
	}

	return nil
}

// Ensure Proof implements fmt.Stringer interface
var _ fmt.Stringer = Proof{}

// String returns the proof data as a string
func (p Proof) String() string {
	return fmt.Sprintf("%d.%s.%s", p.timestamp, p.fingerprint, base64.StdEncoding.EncodeToString(sshsig.Armor(p.signature)))
}

// Ensure Proof implements json.Marshaler interface
var _ json.Marshaler = &Proof{}

// MarshalJSON returns the proof data as a JSON string
func (p Proof) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}
