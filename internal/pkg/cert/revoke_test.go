package cert

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// revocableCertificate is a type of certificate that can be revoked
type revocableCertificate struct {
	name     string
	path     string
	certType uint32
	new      func(t *testing.T, server string, store Storage) Revocable
}

var revocableCertificates = []revocableCertificate{
	{
		name:     "user",
		path:     userCertificatePath,
		certType: ssh.UserCert,
		new: func(t *testing.T, server string, store Storage) Revocable {
			return newTestUserCertificate(t, server, store)
		},
	},
	{
		name:     "host",
		path:     hostCertificatePath,
		certType: ssh.HostCert,
		new: func(t *testing.T, server string, store Storage) Revocable {
			return newTestHostCertificate(t, server, store)
		},
	},
}

// revocableStore returns a fakeStore holding a new key and a certificate of
// certType for it with testSerial issued by ca
func revocableStore(t *testing.T, ca *fakeCA, certType uint32) *fakeStore {
	t.Helper()

	signer := newSigner(t)
	now := time.Now()
	c := &ssh.Certificate{
		Key:             signer.PublicKey(),
		Serial:          testSerial,
		CertType:        certType,
		KeyId:           "test",
		ValidPrincipals: []string{"test"},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(time.Hour).Unix()),
	}
	if err := c.SignCert(rand.Reader, ca.ca); err != nil {
		t.Fatalf("could not sign certificate: %v", err)
	}
	ca.revokeKey = signer.PublicKey()

	return &fakeStore{signer: signer, cert: c}
}

func TestRevokeContext(t *testing.T) {
	revokedAt := time.Date(2026, 10, 12, 1, 2, 3, 0, time.UTC)

	tests := []struct {
		name          string
		status        int
		contentType   string
		body          string
		noCert        bool
		removeErr     error
		deleteErr     error
		wantErr       error
		wantAnyErr    bool
		wantRevokedAt bool
		wantRequest   bool
		wantRemoved   bool // certificate deleted from the store
		wantAgent     bool // certificate removed from the agent
	}{
		{name: "revoked", wantRevokedAt: true, wantRequest: true, wantRemoved: true, wantAgent: true},
		{name: "already revoked", status: http.StatusConflict, wantErr: ErrAlreadyRevoked, wantRequest: true, wantRemoved: true, wantAgent: true},
		{name: "unknown certificate", status: http.StatusNotFound, wantErr: ErrUnknownCertificate, wantRequest: true},
		{name: "server error", status: http.StatusInternalServerError, wantAnyErr: true, wantRequest: true},
		{name: "not JSON", contentType: "text/plain", body: "ok", wantErr: ErrUnexpectedResponse, wantRequest: true},
		{name: "no certificate", noCert: true, wantErr: ErrCertificateNotFound},
		{name: "agent removal failed", removeErr: ErrRemovingFromAgent, wantErr: ErrRemovingFromAgent, wantRevokedAt: true, wantRequest: true, wantRemoved: true},
		{name: "delete failed", deleteErr: errors.New("delete failed"), wantErr: ErrDeletingCertificate, wantRevokedAt: true, wantRequest: true, wantAgent: true},
	}
	for _, rc := range revocableCertificates {
		for _, tt := range tests {
			t.Run(rc.name+"/"+tt.name, func(t *testing.T) {
				ca := newFakeCA(t)
				ca.status = tt.status
				ca.contentType = tt.contentType
				ca.body = tt.body
				ca.revokedAt = revokedAt

				store := revocableStore(t, ca, rc.certType)
				store.removeErr = tt.removeErr
				store.deleteErr = tt.deleteErr
				if tt.noCert {
					store.certErr = ErrCertificateNotFound
				}

				got, err := rc.new(t, ca.URL, store).RevokeContext(context.Background())
				switch {
				case tt.wantErr != nil:
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("RevokeContext() error = %v, want %v", err, tt.wantErr)
					}
				case tt.wantAnyErr:
					if err == nil {
						t.Error("RevokeContext() succeeded unexpectedly")
					}
				case err != nil:
					t.Errorf("RevokeContext() error = %v", err)
				}

				if tt.wantRevokedAt && !got.Equal(revokedAt) {
					t.Errorf("RevokeContext() revoked at = %v, want %v", got, revokedAt)
				}

				if !tt.wantRequest {
					if n := ca.requestCount(); n != 0 {
						t.Errorf("CA received %d requests, want 0", n)
					}
					return
				}
				if want := fmt.Sprintf("%s/%d", rc.path, testSerial); ca.path != want {
					t.Errorf("request path = %q, want %q", ca.path, want)
				}
				if ca.proofErr != nil {
					t.Errorf("proof did not verify: %v", ca.proofErr)
				}

				if store.deleted != tt.wantRemoved {
					t.Errorf("certificate deleted = %v, want %v", store.deleted, tt.wantRemoved)
				}
				if store.removedFromAgent != tt.wantAgent {
					t.Errorf("certificate removed from agent = %v, want %v", store.removedFromAgent, tt.wantAgent)
				}
			})
		}
	}
}

func TestRevokeSerialContext(t *testing.T) {
	tests := []struct {
		name        string
		serial      uint64
		wantRemoved bool
	}{
		{"current certificate", testSerial, true},
		{"other certificate", 1, false},
	}
	for _, rc := range revocableCertificates {
		for _, tt := range tests {
			t.Run(rc.name+"/"+tt.name, func(t *testing.T) {
				ca := newFakeCA(t)
				store := revocableStore(t, ca, rc.certType)

				if _, err := rc.new(t, ca.URL, store).RevokeSerialContext(context.Background(), tt.serial); err != nil {
					t.Fatalf("RevokeSerialContext() error = %v", err)
				}

				if want := fmt.Sprintf("%s/%d", rc.path, tt.serial); ca.path != want {
					t.Errorf("request path = %q, want %q", ca.path, want)
				}
				if ca.proofErr != nil {
					t.Errorf("proof did not verify: %v", ca.proofErr)
				}
				if store.deleted != tt.wantRemoved {
					t.Errorf("certificate deleted = %v, want %v", store.deleted, tt.wantRemoved)
				}
				if store.removedFromAgent != tt.wantRemoved {
					t.Errorf("certificate removed from agent = %v, want %v", store.removedFromAgent, tt.wantRemoved)
				}
			})
		}
	}

	t.Run("no certificate", func(t *testing.T) {
		// a serial can be revoked when there is no current certificate
		ca := newFakeCA(t)
		store := revocableStore(t, ca, ssh.UserCert)
		store.certErr = ErrCertificateNotFound

		if _, err := newTestUserCertificate(t, ca.URL, store).RevokeSerialContext(context.Background(), 1); err != nil {
			t.Fatalf("RevokeSerialContext() error = %v", err)
		}
		if store.deleted {
			t.Error("certificate deleted, want nothing removed")
		}
	})
}
