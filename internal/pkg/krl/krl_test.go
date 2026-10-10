package krl_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/httpclient"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
	sshkrl "github.com/forfuncsake/krl"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

var (
	emptykrl []byte = []byte{
		83, 83, 72, 75, 82, 76, 10, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
		0, 0, 0, 105, 212, 134, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0,
	}
	singleitemkrl []byte = []byte{
		83, 83, 72, 75, 82, 76, 10, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
		0, 0, 0, 105, 212, 150, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 0, 125, 0, 0, 0, 104, 0, 0, 0, 19, 101, 99, 100, 115,
		97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0,
		0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 235, 135,
		144, 107, 178, 77, 169, 17, 143, 229, 212, 117, 47, 246, 32, 122, 223,
		122, 172, 184, 252, 223, 27, 21, 91, 101, 72, 187, 45, 114, 162, 180,
		155, 154, 226, 254, 38, 100, 74, 110, 65, 240, 134, 93, 173, 153, 96,
		155, 72, 32, 53, 230, 250, 109, 216, 116, 185, 27, 1, 128, 68, 149,
		103, 18, 0, 0, 0, 0, 32, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1,
	}
)

const (
	capublickey       string = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOuHkGuyTakRj+XUdS/2IHrfeqy4/N8bFVtlSLstcqK0m5ri/iZkSm5B8IZdrZlgm0ggNeb6bdh0uRsBgESVZxI="
	altcapublickey    string = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVtQh5Agnm9nknP29cudULJc2Fdp0ok65tui/+GJ8x/"
	emptykrlSignature string = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EE64eQa7JNqRGP5dR1L/Yget96rLj83xsVW2VIuy1yorSbmuL+JmRKbkHwhl2tmWCbSCA1
5vpt2HS5GwGARJVnEgAAAC5rcmxAY29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbm
RyZXdoZWJlcmxlAAAAAAAAAAZzaGE1MTIAAABlAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA
AABKAAAAIQCba5YCLPYh37+I8I6HuTTIwECXfvjWDcWnja5hEnAq6wAAACEAhuWuJ6CejS
+CctiQacwVcK8B1Ge1HIZsqUcA05XmLTo=
-----END SSH SIGNATURE-----`
	singleitemkrlSignature string = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EE64eQa7JNqRGP5dR1L/Yget96rLj83xsVW2VIuy1yorSbmuL+JmRKbkHwhl2tmWCbSCA1
5vpt2HS5GwGARJVnEgAAAC5rcmxAY29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbm
RyZXdoZWJlcmxlAAAAAAAAAAZzaGE1MTIAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA
AABJAAAAIC8Ym6ZW5kQQscBqKf4zaWfAUg75ApEzHMNHmUaiZPaiAAAAIQDUF0vXlOXnhQ
XVEZqGFoKDQf2bUJaTX2mSodUrjNrQvg==
-----END SSH SIGNATURE-----`
)

type mockClient struct {
	krl []byte
	sig string
}

func (c *mockClient) Do(req *http.Request) (*http.Response, error) {
	if req.URL.String() != "https://ssh.example.com/api/v3/host/krl" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			Body: &mockBody{r: bytes.NewReader(make([]byte, 0))},
		}, nil
	}

	b, err := json.Marshal(api.KeyRevocationListResponse{
		Krl:       c.krl,
		Signature: c.sig,
	})
	if err != nil {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			Body: &mockBody{r: bytes.NewReader(make([]byte, 0))},
		}, nil

	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: &mockBody{r: bytes.NewReader(b)},
	}, nil
}

type mockBody struct {
	r *bytes.Reader
}

func (b *mockBody) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}

func (b *mockBody) Close() error {
	return nil
}

func TestGetAndVerify(t *testing.T) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(capublickey))
	if err != nil {
		panic(err)
	}

	altpub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(altcapublickey))
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name          string
		krldata       []byte
		signature     string
		want          *krl.Response
		wantErr       bool
		pub           ssh.PublicKey
		strict        bool
		wantVerifyErr bool
	}{
		{"invalid data", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, "", &krl.Response{Krl: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, Signature: ""}, false, nil, false, true},
		{"empty krl", emptykrl, "", &krl.Response{Krl: emptykrl, Signature: ""}, false, nil, false, false},
		{"krl with one serial", singleitemkrl, "", &krl.Response{Krl: singleitemkrl, Signature: ""}, false, nil, false, false},
		{"empty krl (strict no signature)", emptykrl, "", &krl.Response{Krl: emptykrl, Signature: ""}, false, nil, true, true},
		{"krl with one serial (strict no signature)", singleitemkrl, "", &krl.Response{Krl: singleitemkrl, Signature: ""}, false, nil, true, true},
		{"empty krl (strict with signature)", emptykrl, emptykrlSignature, &krl.Response{Krl: emptykrl, Signature: emptykrlSignature}, false, pub, true, false},
		{"krl with one serial (strict with signature)", singleitemkrl, singleitemkrlSignature, &krl.Response{Krl: singleitemkrl, Signature: singleitemkrlSignature}, false, pub, true, false},
		{"krl with one serial (strict with signature and alt ca)", singleitemkrl, singleitemkrlSignature, &krl.Response{Krl: singleitemkrl, Signature: singleitemkrlSignature}, false, altpub, true, true},
		{"krl with one serial (strict with invalid signature)", singleitemkrl, emptykrlSignature, &krl.Response{Krl: singleitemkrl, Signature: emptykrlSignature}, false, pub, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := krl.Get(t.Context(), "https://ssh.example.com/", "host", api.WithHTTPClient(&mockClient{krl: tt.krldata, sig: tt.signature}))
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Read() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Read() succeeded unexpectedly")
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Read() = %v, want %v", got, tt.want)
			}

			if tt.strict {
				if gotVerifyErr := got.VerifyStrict(tt.pub); gotVerifyErr != nil {
					if !tt.wantVerifyErr {
						t.Errorf("VerifyStrict() failed: %v", gotVerifyErr)
					}
					return
				}
				if tt.wantVerifyErr {
					t.Fatal("VerifyStrict() succeeded unexpectedly")
				}
			} else {
				if gotVerifyErr := got.Verify(tt.pub); gotVerifyErr != nil {
					if !tt.wantVerifyErr {
						t.Errorf("Verify() failed: %v", gotVerifyErr)
					}
					return
				}
				if tt.wantVerifyErr {
					t.Fatal("Verify() succeeded unexpectedly")
				}
			}

		})
	}
}

// staticClient returns a 200 response with the given content type and body
type staticClient struct {
	contentType string
	body        []byte
}

func (c *staticClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{c.contentType},
		},
		Body: io.NopCloser(bytes.NewReader(c.body)),
	}, nil
}

func TestGetContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		wantErr     bool
	}{
		{"json", "application/json", []byte(`{"krl":"","signature":""}`), false},
		{"html", "text/html", []byte("<html></html>"), true},
		{"plain text", "text/plain", []byte(`{"krl":"","signature":""}`), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := krl.Get(t.Context(), "https://ssh.example.com/", "host", api.WithHTTPClient(&staticClient{contentType: tt.contentType, body: tt.body}))
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Get() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Get() succeeded unexpectedly")
			}
		})
	}
}

func TestVerifyStrictCertificateSectionCA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ca key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating ca signer: %v", err)
	}

	altpub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(altcapublickey))
	if err != nil {
		t.Fatalf("parsing alt ca key: %v", err)
	}

	tests := []struct {
		name    string
		ca      ssh.PublicKey
		wantErr error
	}{
		{"matching ca", signer.PublicKey(), nil},
		{"other ca", altpub, krl.ErrUnexpectedCA},
		{"any ca", nil, krl.ErrUnexpectedCA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &sshkrl.KRL{
				Sections: []sshkrl.KRLSection{
					&sshkrl.KRLCertificateSection{
						CA:       tt.ca,
						Sections: []sshkrl.KRLCertificateSubsection{&sshkrl.KRLCertificateSerialList{1}},
					},
				},
			}
			b, err := k.Marshal(rand.Reader)
			if err != nil {
				t.Fatalf("marshalling krl: %v", err)
			}

			sig, err := sshsig.Sign(bytes.NewReader(b), signer, sshsig.HashSHA512, krl.Namespace)
			if err != nil {
				t.Fatalf("signing krl: %v", err)
			}

			res := &krl.Response{Krl: b, Signature: string(sshsig.Armor(sig))}
			if gotErr := res.VerifyStrict(signer.PublicKey()); !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("VerifyStrict() error = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}

// responseClient returns the response from fn, or the error from the request
// context once it is done
type responseClient struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (c *responseClient) Do(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}

	return c.fn(req)
}

func response(status int, contentType, body string) func(req *http.Request) (*http.Response, error) {
	return func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Header: http.Header{
				"Content-Type": []string{contentType},
			},
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	}
}

func TestGetErrors(t *testing.T) {
	errTransport := errors.New("connection refused")

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()

	tests := []struct {
		name        string
		ctx         context.Context
		fn          func(req *http.Request) (*http.Response, error)
		wantErr     error
		wantMessage string
	}{
		{"not found", t.Context(), response(http.StatusNotFound, "text/plain", "not found"), nil, "bad status code: 404"},
		{"server error with messages", t.Context(), response(http.StatusInternalServerError, "application/json", `{"success":false,"errors":[{"code":1,"message":"krl unavailable"},{"code":2,"message":"try again"}]}`), nil, "bad status code: 500: krl unavailable; try again"},
		{"server error without messages", t.Context(), response(http.StatusInternalServerError, "application/json", `{"success":false,"errors":[]}`), nil, "bad status code: 500"},
		{"server error not json", t.Context(), response(http.StatusInternalServerError, "text/plain", "internal error"), nil, "bad status code: 500"},
		{"transport error", t.Context(), func(req *http.Request) (*http.Response, error) { return nil, errTransport }, errTransport, ""},
		{"cancelled context", cancelled, response(http.StatusOK, "application/json", `{"krl":"","signature":""}`), context.Canceled, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := krl.Get(tt.ctx, "https://ssh.example.com/", "host", api.WithHTTPClient(&responseClient{fn: tt.fn}))
			if gotErr == nil {
				t.Fatal("Get() succeeded unexpectedly")
			}
			if tt.wantErr != nil && !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("Get() error = %v, want %v", gotErr, tt.wantErr)
			}
			if tt.wantMessage != "" && !strings.HasSuffix(gotErr.Error(), tt.wantMessage) {
				t.Errorf("Get() error = %q, want suffix %q", gotErr, tt.wantMessage)
			}
		})
	}
}

func TestGetDefaultClient(t *testing.T) {
	var gotUserAgent, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		gotHeader = r.Header.Get("X-Test")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"krl":"","signature":""}`))
	}))
	defer srv.Close()

	tests := []struct {
		name string
		opts []api.ClientOption
	}{
		{"no options", nil},
		{"request editor", []api.ClientOption{api.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			req.Header.Set("X-Test", "set")
			return nil
		})}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserAgent, gotHeader = "", ""

			if _, err := krl.Get(t.Context(), srv.URL, "host", tt.opts...); err != nil {
				t.Fatalf("Get() failed: %v", err)
			}

			if want := httpclient.GenerateUserAgent(httpclient.UserAgent); gotUserAgent != want {
				t.Errorf("User-Agent = %q, want %q", gotUserAgent, want)
			}
			if tt.opts != nil && gotHeader != "set" {
				t.Errorf("X-Test = %q, want %q", gotHeader, "set")
			}
		})
	}
}

// errParse matches any error that is not a signature error, as parse errors
// from the krl library are not exported
var errParse = errors.New("parse error")

func TestVerifyOrder(t *testing.T) {
	newSigner := func() ssh.Signer {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatalf("creating signer: %v", err)
		}
		return signer
	}
	ca := newSigner()
	other := newSigner()

	marshal := func(sections ...sshkrl.KRLSection) []byte {
		b, err := (&sshkrl.KRL{Sections: sections}).Marshal(rand.Reader)
		if err != nil {
			t.Fatalf("marshalling krl: %v", err)
		}
		return b
	}
	sign := func(b []byte, signer ssh.Signer) string {
		sig, err := sshsig.Sign(bytes.NewReader(b), signer, sshsig.HashSHA512, krl.Namespace)
		if err != nil {
			t.Fatalf("signing krl: %v", err)
		}
		return string(sshsig.Armor(sig))
	}

	malformed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	valid := marshal(&sshkrl.KRLCertificateSection{
		CA:       ca.PublicKey(),
		Sections: []sshkrl.KRLCertificateSubsection{&sshkrl.KRLCertificateSerialList{1}},
	})
	explicitKey := marshal(&sshkrl.KRLExplicitKeySection{other.PublicKey()})

	tests := []struct {
		name      string
		krl       []byte
		signature string
		pub       ssh.PublicKey
		strict    bool
		wantErr   error
	}{
		{"strict valid", valid, sign(valid, ca), ca.PublicKey(), true, nil},
		{"strict no key with malformed krl", malformed, "", nil, true, krl.ErrNoPublicKey},
		{"strict malformed signature with malformed krl", malformed, "not a signature", ca.PublicKey(), true, krl.ErrInvalidSignature},
		{"strict wrong signer with malformed krl", malformed, sign(malformed, other), ca.PublicKey(), true, krl.ErrInvalidSignature},
		{"strict wrong signer with unexpected section", explicitKey, sign(explicitKey, other), ca.PublicKey(), true, krl.ErrInvalidSignature},
		{"strict signature for other data", valid, sign(explicitKey, ca), ca.PublicKey(), true, krl.ErrInvalidSignature},
		{"strict signed malformed krl", malformed, sign(malformed, ca), ca.PublicKey(), true, errParse},
		{"strict signed unexpected section", explicitKey, sign(explicitKey, ca), ca.PublicKey(), true, krl.ErrUnexpectedSection},
		{"no key valid", valid, "", nil, false, nil},
		{"no key malformed krl", malformed, "", nil, false, errParse},
		{"no key unexpected section", explicitKey, "", nil, false, krl.ErrUnexpectedSection},
		{"key wrong signer", valid, sign(valid, other), ca.PublicKey(), false, krl.ErrInvalidSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &krl.Response{Krl: tt.krl, Signature: tt.signature}

			var gotErr error
			if tt.strict {
				gotErr = res.VerifyStrict(tt.pub)
			} else {
				gotErr = res.Verify(tt.pub)
			}

			switch tt.wantErr {
			case nil:
				if gotErr != nil {
					t.Errorf("verify failed: %v", gotErr)
				}
			case errParse:
				if gotErr == nil || errors.Is(gotErr, krl.ErrInvalidSignature) || errors.Is(gotErr, krl.ErrNoPublicKey) {
					t.Errorf("verify error = %v, want parse error", gotErr)
				}
			default:
				if !errors.Is(gotErr, tt.wantErr) {
					t.Errorf("verify error = %v, want %v", gotErr, tt.wantErr)
				}
			}
		})
	}
}
