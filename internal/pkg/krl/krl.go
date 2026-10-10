package krl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/httpclient"
	sshkrl "github.com/forfuncsake/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

const Namespace = "krl@com.github.serverless-ssh-ca.andrewheberle"

type Response api.KeyRevocationListResponse

var (
	ErrNoPublicKey       = errors.New("no public key provided for signature verification")
	ErrUnexpectedCA      = errors.New("encountered krl certificate section with unexpected CA")
	ErrUnexpectedSection = errors.New("encountered unexpected section type in krl")
)

// Get retrieves the KRL for certificatetype from server. Requests use the
// client from [httpclient.New] unless opts sets another with
// [api.WithHTTPClient].
func Get(ctx context.Context, server string, certificatetype api.GetCertificateTypeKrlParamsCertificateType, opts ...api.ClientOption) (*Response, error) {
	// options are applied in order, so any client in opts replaces the default
	opts = append([]api.ClientOption{api.WithHTTPClient(httpclient.New())}, opts...)
	client, err := api.NewClientWithResponses(server, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating api client: %w", err)
	}

	res, err := client.GetCertificateTypeKrlWithResponse(ctx, certificatetype)
	if err != nil {
		return nil, fmt.Errorf("requesting krl: %w", err)
	}

	if res.StatusCode() != http.StatusOK {
		// include any error messages returned by the CA
		if res.JSON500 != nil && len(res.JSON500.Errors) > 0 {
			messages := make([]string, 0, len(res.JSON500.Errors))
			for _, e := range res.JSON500.Errors {
				messages = append(messages, e.Message)
			}
			return nil, fmt.Errorf("bad status code: %d: %s", res.StatusCode(), strings.Join(messages, "; "))
		}
		return nil, fmt.Errorf("bad status code: %d", res.StatusCode())
	}

	if res.JSON200 == nil {
		return nil, fmt.Errorf("unexpected response content type: %q", res.ContentType())
	}

	return &Response{
		Krl:       res.JSON200.Krl,
		Signature: res.JSON200.Signature,
	}, nil
}

func (r *Response) VerifyStrict(pub ssh.PublicKey) error {
	// parse the KRL
	parsedKrl, err := sshkrl.ParseKRL(r.Krl)
	if err != nil {
		return fmt.Errorf("problem parsing krl: %w", err)
	}

	// check the only sections of the parsed KRL are for certificates
	for _, section := range parsedKrl.Sections {
		if _, ok := section.(*sshkrl.KRLCertificateSection); !ok {
			return ErrUnexpectedSection
		}
	}

	// error here if public key is not provided
	if pub == nil {
		return ErrNoPublicKey
	}

	// unarmor and verify signature
	sig, err := sshsig.Unarmor([]byte(r.Signature))
	if err != nil {
		return fmt.Errorf("problem unarmoring signature: %w", err)
	}

	if err := sshsig.Verify(bytes.NewReader(r.Krl), sig, pub, sshsig.HashSHA512, Namespace); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// check that all sections are for our CA
	pubBytes := pub.Marshal()
	for _, section := range parsedKrl.Sections {
		switch s := section.(type) {
		case *sshkrl.KRLCertificateSection:
			// a nil CA applies the section to certificates from any CA
			if s.CA == nil || !bytes.Equal(s.CA.Marshal(), pubBytes) {
				return ErrUnexpectedCA
			}
		}
	}

	return nil
}

func (r *Response) Verify(pub ssh.PublicKey) error {
	if err := r.VerifyStrict(pub); err != nil {
		// if the error is that no public key was provided, we can ignore it
		// in this non-strict verification method
		if errors.Is(err, ErrNoPublicKey) {
			return nil
		}
		return err
	}

	return nil
}
