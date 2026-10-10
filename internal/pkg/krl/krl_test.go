package krl_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
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

// errParse matches any error that is not one of the exported errors, as parse
// errors from the krl library are not exported
var errParse = errors.New("parse error")

// newSigner returns a signer for a new ed25519 key
func newSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	return signerFromKey(t, priv)
}

func signerFromKey(t *testing.T, key crypto.Signer) ssh.Signer {
	t.Helper()

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	return signer
}

// marshal returns a KRL containing sections
func marshal(t *testing.T, sections ...sshkrl.KRLSection) []byte {
	t.Helper()

	b, err := (&sshkrl.KRL{Sections: sections}).Marshal(rand.Reader)
	if err != nil {
		t.Fatalf("marshalling krl: %v", err)
	}

	return b
}

// sign returns the armored signature of b by signer, as the CA creates it
func sign(t *testing.T, b []byte, signer ssh.Signer) string {
	t.Helper()

	return signWith(t, b, signer, sshsig.HashSHA512, krl.Namespace)
}

func signWith(t *testing.T, b []byte, signer ssh.Signer, hash sshsig.HashAlgorithm, namespace string) string {
	t.Helper()

	sig, err := sshsig.Sign(bytes.NewReader(b), signer, hash, namespace)
	if err != nil {
		t.Fatalf("signing krl: %v", err)
	}

	return string(sshsig.Armor(sig))
}

// certificateSection returns a certificate section for ca revoking serial 1
func certificateSection(ca ssh.PublicKey) *sshkrl.KRLCertificateSection {
	return &sshkrl.KRLCertificateSection{
		CA:       ca,
		Sections: []sshkrl.KRLCertificateSubsection{&sshkrl.KRLCertificateSerialList{1}},
	}
}

// checkErr reports whether got matches want, which may be nil or errParse
func checkErr(t *testing.T, method string, got, want error) {
	t.Helper()

	switch want {
	case nil:
		if got != nil {
			t.Errorf("%s() failed: %v", method, got)
		}
	case errParse:
		for _, err := range []error{krl.ErrInvalidSignature, krl.ErrNoPublicKey, krl.ErrOlderKRL, krl.ErrUnexpectedCA, krl.ErrUnexpectedSection} {
			if errors.Is(got, err) {
				t.Errorf("%s() error = %v, want parse error", method, got)
				return
			}
		}
		if got == nil {
			t.Errorf("%s() succeeded unexpectedly, want parse error", method)
		}
	default:
		if !errors.Is(got, want) {
			t.Errorf("%s() error = %v, want %v", method, got, want)
		}
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

func TestGet(t *testing.T) {
	signer := newSigner(t)
	b := marshal(t, certificateSection(signer.PublicKey()))
	want := &krl.Response{Krl: b, Signature: sign(t, b, signer)}

	body, err := json.Marshal(api.KeyRevocationListResponse(*want))
	if err != nil {
		t.Fatalf("marshalling response: %v", err)
	}

	tests := []struct {
		name            string
		certificateType api.GetCertificateTypeKrlParamsCertificateType
		wantPath        string
	}{
		{"host", api.GetCertificateTypeKrlParamsCertificateTypeHost, "/api/v3/host/krl"},
		{"user", api.GetCertificateTypeKrlParamsCertificateTypeUser, "/api/v3/user/krl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			client := &responseClient{fn: func(req *http.Request) (*http.Response, error) {
				gotPath = req.URL.Path
				return response(http.StatusOK, "application/json", string(body))(req)
			}}

			got, err := krl.Get(t.Context(), "https://ssh.example.com/", tt.certificateType, api.WithHTTPClient(client))
			if err != nil {
				t.Fatalf("Get() failed: %v", err)
			}

			if gotPath != tt.wantPath {
				t.Errorf("Get() requested %q, want %q", gotPath, tt.wantPath)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Get() = %v, want %v", got, want)
			}
		})
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
		{"ok as html", t.Context(), response(http.StatusOK, "text/html", "<html></html>"), nil, `unexpected response content type: "text/html"`},
		{"ok as plain text", t.Context(), response(http.StatusOK, "text/plain", `{"krl":"","signature":""}`), nil, `unexpected response content type: "text/plain"`},
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

func TestVerifyStrict(t *testing.T) {
	ca := newSigner(t)
	other := newSigner(t)

	malformed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	empty := marshal(t)
	valid := marshal(t, certificateSection(ca.PublicKey()))
	allSubsections := marshal(t, &sshkrl.KRLCertificateSection{
		CA: ca.PublicKey(),
		Sections: []sshkrl.KRLCertificateSubsection{
			&sshkrl.KRLCertificateSerialList{1, 2, 3},
			&sshkrl.KRLCertificateSerialRange{Min: 10, Max: 20},
			&sshkrl.KRLCertificateSerialBitmap{Offset: 100, Bitmap: big.NewInt(0b1011)},
			&sshkrl.KRLCertificateKeyID{"revoked@example.com"},
		},
	})
	multipleSections := marshal(t, certificateSection(ca.PublicKey()), certificateSection(ca.PublicKey()))
	otherCA := marshal(t, certificateSection(other.PublicKey()))
	anyCA := marshal(t, certificateSection(nil))
	oneOtherCA := marshal(t, certificateSection(ca.PublicKey()), certificateSection(other.PublicKey()))
	explicitKey := marshal(t, &sshkrl.KRLExplicitKeySection{other.PublicKey()})
	fingerprintSHA1 := marshal(t, &sshkrl.KRLFingerprintSection{sha1.Sum(other.PublicKey().Marshal())})
	fingerprintSHA256 := marshal(t, &sshkrl.KRLFingerprintSHA256Section{sha256.Sum256(other.PublicKey().Marshal())})
	mixedSections := marshal(t, certificateSection(ca.PublicKey()), &sshkrl.KRLExplicitKeySection{other.PublicKey()})

	// change the last byte (the revoked serial) after signing
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1]++

	tests := []struct {
		name      string
		krl       []byte
		signature string
		pub       ssh.PublicKey
		wantErr   error
	}{
		{"empty krl", empty, sign(t, empty, ca), ca.PublicKey(), nil},
		{"serial list", valid, sign(t, valid, ca), ca.PublicKey(), nil},
		{"all certificate subsections", allSubsections, sign(t, allSubsections, ca), ca.PublicKey(), nil},
		{"multiple sections", multipleSections, sign(t, multipleSections, ca), ca.PublicKey(), nil},

		{"no public key", valid, sign(t, valid, ca), nil, krl.ErrNoPublicKey},
		{"no signature", valid, "", ca.PublicKey(), krl.ErrInvalidSignature},
		{"malformed signature", valid, "not a signature", ca.PublicKey(), krl.ErrInvalidSignature},
		{"wrong signer", valid, sign(t, valid, other), ca.PublicKey(), krl.ErrInvalidSignature},
		{"signature for other data", valid, sign(t, empty, ca), ca.PublicKey(), krl.ErrInvalidSignature},
		{"krl changed after signing", tampered, sign(t, valid, ca), ca.PublicKey(), krl.ErrInvalidSignature},
		{"wrong namespace", valid, signWith(t, valid, ca, sshsig.HashSHA512, "file"), ca.PublicKey(), krl.ErrInvalidSignature},
		{"sha256 signature", valid, signWith(t, valid, ca, sshsig.HashSHA256, krl.Namespace), ca.PublicKey(), krl.ErrInvalidSignature},

		{"malformed krl", malformed, sign(t, malformed, ca), ca.PublicKey(), errParse},
		{"other ca", otherCA, sign(t, otherCA, ca), ca.PublicKey(), krl.ErrUnexpectedCA},
		{"any ca", anyCA, sign(t, anyCA, ca), ca.PublicKey(), krl.ErrUnexpectedCA},
		{"one section for other ca", oneOtherCA, sign(t, oneOtherCA, ca), ca.PublicKey(), krl.ErrUnexpectedCA},
		{"explicit key section", explicitKey, sign(t, explicitKey, ca), ca.PublicKey(), krl.ErrUnexpectedSection},
		{"sha1 fingerprint section", fingerprintSHA1, sign(t, fingerprintSHA1, ca), ca.PublicKey(), krl.ErrUnexpectedSection},
		{"sha256 fingerprint section", fingerprintSHA256, sign(t, fingerprintSHA256, ca), ca.PublicKey(), krl.ErrUnexpectedSection},
		{"certificate and explicit key sections", mixedSections, sign(t, mixedSections, ca), ca.PublicKey(), krl.ErrUnexpectedSection},

		// the public key and signature are checked before the krl is parsed
		{"no public key with malformed krl", malformed, "", nil, krl.ErrNoPublicKey},
		{"malformed signature with malformed krl", malformed, "not a signature", ca.PublicKey(), krl.ErrInvalidSignature},
		{"wrong signer with malformed krl", malformed, sign(t, malformed, other), ca.PublicKey(), krl.ErrInvalidSignature},
		{"wrong signer with explicit key section", explicitKey, sign(t, explicitKey, other), ca.PublicKey(), krl.ErrInvalidSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &krl.Response{Krl: tt.krl, Signature: tt.signature}
			checkErr(t, "VerifyStrict", res.VerifyStrict(tt.pub), tt.wantErr)
		})
	}
}

func TestVerifyStrictKeyTypes(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ecdsa key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}

	tests := []struct {
		name   string
		signer ssh.Signer
	}{
		{"ed25519", newSigner(t)},
		{"ecdsa", signerFromKey(t, ecdsaKey)},
		{"rsa", signerFromKey(t, rsaKey)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := marshal(t, certificateSection(tt.signer.PublicKey()))
			res := &krl.Response{Krl: b, Signature: sign(t, b, tt.signer)}
			checkErr(t, "VerifyStrict", res.VerifyStrict(tt.signer.PublicKey()), nil)
		})
	}
}

func TestVerify(t *testing.T) {
	ca := newSigner(t)
	other := newSigner(t)

	malformed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
	empty := marshal(t)
	valid := marshal(t, certificateSection(ca.PublicKey()))
	otherCA := marshal(t, certificateSection(other.PublicKey()))
	explicitKey := marshal(t, &sshkrl.KRLExplicitKeySection{other.PublicKey()})

	tests := []struct {
		name      string
		krl       []byte
		signature string
		pub       ssh.PublicKey
		wantErr   error
	}{
		// without a public key only the sections are checked
		{"no public key empty krl", empty, "", nil, nil},
		{"no public key valid", valid, "", nil, nil},
		{"no public key invalid signature", valid, "not a signature", nil, nil},
		{"no public key other ca", otherCA, "", nil, nil},
		{"no public key malformed krl", malformed, "", nil, errParse},
		{"no public key explicit key section", explicitKey, "", nil, krl.ErrUnexpectedSection},

		// with a public key it is the same as VerifyStrict
		{"public key valid", valid, sign(t, valid, ca), ca.PublicKey(), nil},
		{"public key no signature", valid, "", ca.PublicKey(), krl.ErrInvalidSignature},
		{"public key wrong signer", valid, sign(t, valid, other), ca.PublicKey(), krl.ErrInvalidSignature},
		{"public key other ca", otherCA, sign(t, otherCA, ca), ca.PublicKey(), krl.ErrUnexpectedCA},
		{"public key explicit key section", explicitKey, sign(t, explicitKey, ca), ca.PublicKey(), krl.ErrUnexpectedSection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &krl.Response{Krl: tt.krl, Signature: tt.signature}
			checkErr(t, "Verify", res.Verify(tt.pub), tt.wantErr)
		})
	}
}

func TestCheckNotOlder(t *testing.T) {
	ca := newSigner(t)

	// generated returns a KRL with version and generated date, as the CA sets
	// version 1 and the generated date for every KRL
	generated := func(version, date uint64) []byte {
		t.Helper()

		k := &sshkrl.KRL{
			Version:       version,
			GeneratedDate: date,
			Sections:      []sshkrl.KRLSection{certificateSection(ca.PublicKey())},
		}
		b, err := k.Marshal(rand.Reader)
		if err != nil {
			t.Fatalf("marshalling krl: %v", err)
		}

		return b
	}

	const date = 1_800_000_000

	tests := []struct {
		name     string
		krl      []byte
		existing []byte
		wantErr  error
	}{
		{"same krl", generated(1, date), generated(1, date), nil},
		{"generated later", generated(1, date+1), generated(1, date), nil},
		{"generated earlier", generated(1, date-1), generated(1, date), krl.ErrOlderKRL},
		{"higher version generated earlier", generated(2, date-1), generated(1, date), nil},
		{"lower version generated later", generated(1, date+1), generated(2, date), krl.ErrOlderKRL},
		{"existing malformed", generated(1, date), []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, errParse},
		{"existing empty", generated(1, date), []byte{}, errParse},
		{"krl malformed", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, generated(1, date), errParse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &krl.Response{Krl: tt.krl}
			checkErr(t, "CheckNotOlder", res.CheckNotOlder(tt.existing), tt.wantErr)
		})
	}
}

func TestParse(t *testing.T) {
	ca := newSigner(t)
	other := newSigner(t)

	valid := marshal(t, certificateSection(ca.PublicKey()), certificateSection(other.PublicKey()))
	explicitKey := marshal(t, &sshkrl.KRLExplicitKeySection{other.PublicKey()})

	tests := []struct {
		name         string
		krl          []byte
		wantSections int
		wantErr      error
	}{
		{"empty krl", marshal(t), 0, nil},
		// the CA of each section is only checked by VerifyStrict
		{"certificate sections", valid, 2, nil},
		{"malformed krl", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, 0, errParse},
		{"explicit key section", explicitKey, 0, krl.ErrUnexpectedSection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := (&krl.Response{Krl: tt.krl}).Parse()
			checkErr(t, "Parse", gotErr, tt.wantErr)

			if gotErr == nil && len(got.Sections) != tt.wantSections {
				t.Errorf("Parse() sections = %d, want %d", len(got.Sections), tt.wantSections)
			}
		})
	}
}
