package protect

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"codeberg.org/sdassow/atomic"
)

var _ Protector = &KeyfileProtector{}

type KeyfileProtector struct {
	key []byte
}

func NewKeyfileProtector(keyfile string) (*KeyfileProtector, error) {
	key, err := os.ReadFile(keyfile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			key, err := generateKey()
			if err != nil {
				return nil, fmt.Errorf("could not generate keyfile: %w", err)
			}

			if err := atomic.WriteFile(keyfile, bytes.NewReader(key), atomic.FileMode(0600)); err != nil {
				return nil, fmt.Errorf("could not write keyfile: %w", err)
			}

			return &KeyfileProtector{key: key}, nil
		}
	}

	return &KeyfileProtector{key: key}, nil
}

// Decrypt will decrypt provided data using the keyfile. In this case name is ignored
func (p *KeyfileProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return decrypt(p.key, data)
}

// Encrypt will encrypt provided data using the the keyfile. In this case name is ignored
func (p *KeyfileProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return encrypt(p.key, data)
}
