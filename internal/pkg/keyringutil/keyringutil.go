// Package keyringutil stores values in the operating system keyring without
// being limited by the maximum size of a single keyring entry.
//
// Windows Credential Manager limits each entry to 2560 bytes and the macOS
// Keychain (via go-keyring) to roughly 2900 bytes. Values larger than
// [ChunkSize] are split across several entries named "<service> #<n>", with
// the main entry holding a header that records the number of parts and a
// SHA-256 hash of the complete value. Smaller values are stored in a single
// entry exactly as go-keyring would store them, so existing entries remain
// readable.
package keyringutil

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	// ChunkSize is the largest value stored in a single keyring entry. It is
	// below the per-entry limits of Windows Credential Manager and the macOS
	// Keychain with room to spare.
	ChunkSize = 2000

	// maxParts limits the number of parts of a single value
	maxParts = 100

	// headerPrefix identifies a header in the main entry of a value that was
	// split into parts
	headerPrefix = "keyringutil:v1:"
)

var (
	// ErrNotFound is returned when no value is stored. It is the same error
	// returned by go-keyring so either may be checked with errors.Is.
	ErrNotFound = keyring.ErrNotFound

	// ErrIncomplete is returned, along with [ErrNotFound], when a value that
	// was split into parts is missing parts or does not match its hash, such
	// as when a write was interrupted
	ErrIncomplete = errors.New("stored value is incomplete")

	// ErrTooLarge is returned when a value would need more than the maximum
	// number of parts
	ErrTooLarge = errors.New("value is too large to store")
)

// backend is the keyring used to store entries. This is a variable so it
// can be replaced in tests.
var backend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
} = goKeyring{}

// goKeyring stores entries using go-keyring
type goKeyring struct{}

func (goKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (goKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (goKeyring) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

// Set stores value for service and user, replacing any existing value.
func Set(service, user, value string) error {
	// small values are stored as a single entry, unless they could be
	// mistaken for a header
	if len(value) <= ChunkSize && !strings.HasPrefix(value, headerPrefix) {
		if err := backend.Set(service, user, value); err != nil {
			return err
		}

		// remove any parts left from a previous larger value
		return deleteParts(service, user, 1)
	}

	// reject values needing too many parts before splitting them
	if len(value) > maxParts*ChunkSize {
		return fmt.Errorf("%w: %d bytes", ErrTooLarge, len(value))
	}

	parts := split(value)

	// write the parts before the header so the value is never read with an
	// incomplete set of parts
	for i, part := range parts {
		if err := backend.Set(partService(service, i+1), user, part); err != nil {
			return fmt.Errorf("could not store part %d: %w", i+1, err)
		}
	}

	if err := backend.Set(service, user, header(len(parts), value)); err != nil {
		return err
	}

	// remove any parts left from a previous larger value
	return deleteParts(service, user, len(parts)+1)
}

// Get returns the value stored for service and user. [ErrNotFound] is
// returned if no value is stored or a value split into parts is incomplete.
func Get(service, user string) (string, error) {
	v, err := backend.Get(service, user)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(v, headerPrefix) {
		return v, nil
	}

	n, hash, err := parseHeader(v)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	for i := 1; i <= n; i++ {
		part, err := backend.Get(partService(service, i), user)
		if err != nil {
			return "", fmt.Errorf("%w: %w: part %d: %w", ErrNotFound, ErrIncomplete, i, err)
		}
		b.WriteString(part)
	}

	value := b.String()
	if sum(value) != hash {
		return "", fmt.Errorf("%w: %w: hash mismatch", ErrNotFound, ErrIncomplete)
	}

	return value, nil
}

// Delete removes the value stored for service and user, including any parts.
// [ErrNotFound] is returned if no value was stored.
func Delete(service, user string) error {
	err := backend.Delete(service, user)

	// always clean up parts, even if the header was missing
	if partsErr := deleteParts(service, user, 1); partsErr != nil {
		return partsErr
	}

	return err
}

// deleteParts deletes parts from number from onwards. Parts are numbered
// consecutively so this stops at the first missing part.
func deleteParts(service, user string, from int) error {
	for i := from; i <= maxParts; i++ {
		if err := backend.Delete(partService(service, i), user); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return fmt.Errorf("could not delete part %d: %w", i, err)
		}
	}

	return nil
}

// split returns value in parts of at most ChunkSize bytes
func split(value string) []string {
	var parts []string
	for len(value) > ChunkSize {
		parts = append(parts, value[:ChunkSize])
		value = value[ChunkSize:]
	}

	return append(parts, value)
}

// partService returns the service name used for part n of a value
func partService(service string, n int) string {
	return fmt.Sprintf("%s #%d", service, n)
}

// header returns the main entry for a value stored in n parts
func header(n int, value string) string {
	return fmt.Sprintf("%s%d:%s", headerPrefix, n, sum(value))
}

// parseHeader returns the number of parts and hash from a header
func parseHeader(h string) (int, string, error) {
	fields := strings.Split(strings.TrimPrefix(h, headerPrefix), ":")
	if len(fields) != 2 {
		return 0, "", fmt.Errorf("%w: %w: invalid header", ErrNotFound, ErrIncomplete)
	}

	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 1 || n > maxParts {
		return 0, "", fmt.Errorf("%w: %w: invalid number of parts", ErrNotFound, ErrIncomplete)
	}

	return n, fields[1], nil
}

// sum returns the hex encoded SHA-256 hash of value
func sum(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
