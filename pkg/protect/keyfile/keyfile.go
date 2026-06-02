package keyfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/ssh-ca-client/pkg/protect"
)

var _ protect.Protector = &Protector{}

type Protector struct {
	key []byte
}

func NewProtector(keyfile string) (*Protector, error) {
	key, err := os.ReadFile(keyfile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			key, err := protect.GenerateKey()
			if err != nil {
				return nil, fmt.Errorf("could not generate key for keyfile: %w", err)
			}

			if err := atomic.WriteFile(keyfile, bytes.NewReader(key), atomic.FileMode(0600)); err != nil {
				return nil, fmt.Errorf("could not write keyfile: %w", err)
			}

			return &Protector{key: key}, nil
		}

		return nil, fmt.Errorf("could not read keyfile: %w", err)
	}

	return &Protector{key: key}, nil
}

// Decrypt will decrypt provided data using the keyfile. In this case name is ignored
func (p *Protector) Decrypt(data []byte, name string) ([]byte, error) {
	return protect.Decrypt(p.key, data)
}

// Encrypt will encrypt provided data using the the keyfile. In this case name is ignored
func (p *Protector) Encrypt(data []byte, name string) ([]byte, error) {
	return protect.Encrypt(p.key, data)
}
