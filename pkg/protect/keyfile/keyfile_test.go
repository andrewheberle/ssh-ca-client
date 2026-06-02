package keyfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/pkg/protect"
)

func TestNewProtector_existing(t *testing.T) {
	keyfile := "testdata/keyfile_existing"
	key := fmt.Append(nil, "0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(keyfile, key, 0600); err != nil {
		panic(err)
	}
	defer func() {
		_ = os.Remove(keyfile)
	}()

	p, err := NewProtector(keyfile)
	if err != nil {
		t.Fatalf("could not load existing keyfile: %v", err)
	}

	if !bytes.Equal(key, p.key) {
		t.Errorf("NewProtector() did not match. Got = %v, Want = %v", p.key, key)
	}
}

func TestNewProtector_new(t *testing.T) {
	keyfile := "testdata/keyfile_new"
	if err := os.Remove(keyfile); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic(err)
		}
	}
	defer func() {
		_ = os.Remove(keyfile)
	}()

	p, err := NewProtector(keyfile)
	if err != nil {
		t.Fatalf("could not create new keyfile: %v", err)
	}

	key, err := os.ReadFile(keyfile)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(key, p.key) {
		t.Errorf("NewProtector() did not match. Got = %s, Want = %s", p.key, key)
	}
}

func TestProtector_Encrypt(t *testing.T) {
	keyfile, err := tempKeyfileName()
	defer func() {
		_ = os.Remove(keyfile)
	}()
	if err != nil {
		panic(err)
	}

	p, err := NewProtector(keyfile)
	if err != nil {
		t.Fatalf("could not create keyfile protector: %v", err)
	}

	plaintext := []byte("somedata")

	ciphertext, err := p.Encrypt(plaintext, "")
	if err != nil {
		t.Fatalf("Encrypt() failed unexpectedly: %v", err)
	}

	got, err := protect.Decrypt(p.key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt() failed unexpectedly: %v", err)
	}

	if !reflect.DeepEqual(plaintext, got) {
		t.Errorf("Encrypt() did not match. Got = %v, Want = %v", got, plaintext)
	}
}

func TestProtector_Decrypt(t *testing.T) {
	keyfile, err := tempKeyfileName()
	defer func() {
		_ = os.Remove(keyfile)
	}()
	if err != nil {
		panic(err)
	}

	p, err := NewProtector(keyfile)
	if err != nil {
		t.Fatalf("could not create keyfile protector: %v", err)
	}

	plaintext := fmt.Append(nil, "somedata")
	ciphertext, err := protect.Encrypt(p.key, plaintext)
	if err != nil {
		panic(err)
	}

	got, err := p.Decrypt(ciphertext, "")
	if err != nil {
		t.Fatalf("Decrypt() failed unexpectedly: %v", err)
	}

	if !reflect.DeepEqual(plaintext, got) {
		t.Errorf("Decrypt() did not match. Got = %v, Want = %v", got, plaintext)
	}
}

func tempKeyfileName() (string, error) {
	keyfile, err := os.CreateTemp("testdata", "keyfile_*")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = os.Remove(keyfile.Name())
	}()
	if err := keyfile.Close(); err != nil {
		return keyfile.Name(), err
	}

	return keyfile.Name(), nil
}
