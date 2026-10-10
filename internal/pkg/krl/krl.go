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
	ErrInvalidSignature  = errors.New("krl signature verification failed")
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

// VerifyStrict checks the signature on the KRL using pub, which must be the
// public key of the CA, and that the KRL only contains certificate sections
// for that CA. The signature is checked before the KRL is parsed.
func (r *Response) VerifyStrict(pub ssh.PublicKey) error {
	// error here if public key is not provided
	if pub == nil {
		return ErrNoPublicKey
	}

	// unarmor and verify signature
	sig, err := sshsig.Unarmor([]byte(r.Signature))
	if err != nil {
		return fmt.Errorf("%w: problem unarmoring signature: %w", ErrInvalidSignature, err)
	}

	if err := sshsig.Verify(bytes.NewReader(r.Krl), sig, pub, sshsig.HashSHA512, Namespace); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	parsedKrl, err := r.parse()
	if err != nil {
		return err
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

// Verify is the same as [Response.VerifyStrict] when pub is not nil. When pub
// is nil the signature and CA are not checked, only that the KRL parses and
// contains certificate sections.
func (r *Response) Verify(pub ssh.PublicKey) error {
	if pub == nil {
		_, err := r.parse()
		return err
	}

	return r.VerifyStrict(pub)
}

// parse parses the KRL and checks it only contains certificate sections
func (r *Response) parse() (*sshkrl.KRL, error) {
	parsedKrl, err := sshkrl.ParseKRL(r.Krl)
	if err != nil {
		return nil, fmt.Errorf("problem parsing krl: %w", err)
	}

	for _, section := range parsedKrl.Sections {
		if _, ok := section.(*sshkrl.KRLCertificateSection); !ok {
			return nil, ErrUnexpectedSection
		}
	}

	return parsedKrl, nil
}
