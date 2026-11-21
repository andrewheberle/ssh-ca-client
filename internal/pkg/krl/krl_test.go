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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		for _, err := range []error{krl.ErrInvalidSignature, krl.ErrNoPublicKey, krl.ErrOlderKRL, krl.ErrUnexpectedCA, krl.ErrUnexpectedSection, krl.ErrUnexpectedType, krl.ErrUntypedKRL} {
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

// serve returns a client that answers every request with b and its
// signature, as the CA does
func serve(t *testing.T, b []byte, signature string) *responseClient {
	t.Helper()

	body, err := json.Marshal(api.KeyRevocationListResponse{Krl: b, Signature: signature})
	if err != nil {
		t.Fatalf("marshalling response: %v", err)
	}

	return &responseClient{fn: response(http.StatusOK, "application/json", string(body))}
}

// fetch returns b, signed by ca, after fetching and verifying it as the user
// KRL
func fetch(t *testing.T, ca ssh.Signer, b []byte) *krl.Verified {
	t.Helper()

	return fetchType(t, ca, b, krl.User)
}

// fetchType returns b, signed by ca, after fetching and verifying it as the
// KRL for certificateType
func fetchType(t *testing.T, ca ssh.Signer, b []byte, certificateType krl.CertificateType) *krl.Verified {
	t.Helper()

	v, err := krl.Fetch(t.Context(), "https://ssh.example.com/", certificateType, ca.PublicKey(), api.WithHTTPClient(serve(t, b, sign(t, b, ca))))
	if err != nil {
		t.Fatalf("Fetch() failed: %v", err)
	}

	return v
}

// generated returns a KRL revoking a certificate from ca with version and
// generated date and no comment, as CA 1.0.2 and earlier generate it
func generated(t *testing.T, ca ssh.Signer, version, date uint64) []byte {
	t.Helper()

	return typed(t, ca, version, date, "")
}

// typed returns a KRL as for [generated], with comment, which later CAs set
// to the certificate type
func typed(t *testing.T, ca ssh.Signer, version, date uint64, comment string) []byte {
	t.Helper()

	k := &sshkrl.KRL{
		Version:       version,
		GeneratedDate: date,
		Comment:       comment,
		Sections:      []sshkrl.KRLSection{certificateSection(ca.PublicKey())},
	}
	b, err := k.Marshal(rand.Reader)
	if err != nil {
		t.Fatalf("marshalling krl: %v", err)
	}

	return b
}

func TestFetch(t *testing.T) {
	ca := newSigner(t)

	const date = 1_800_000_000
	b := generated(t, ca, 3, date)
	signature := sign(t, b, ca)

	tests := []struct {
		name            string
		certificateType krl.CertificateType
		wantPath        string
	}{
		{"host", krl.Host, "/api/v4/host/krl"},
		{"user", krl.User, "/api/v4/user/krl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			client := &responseClient{fn: func(req *http.Request) (*http.Response, error) {
				gotPath = req.URL.Path
				return serve(t, b, signature).Do(req)
			}}

			got, err := krl.Fetch(t.Context(), "https://ssh.example.com/", tt.certificateType, ca.PublicKey(), api.WithHTTPClient(client))
			if err != nil {
				t.Fatalf("Fetch() failed: %v", err)
			}

			if gotPath != tt.wantPath {
				t.Errorf("Fetch() requested %q, want %q", gotPath, tt.wantPath)
			}
			if !bytes.Equal(got.Bytes(), b) {
				t.Errorf("Bytes() = %x, want %x", got.Bytes(), b)
			}
			if got.Version() != 3 {
				t.Errorf("Version() = %d, want 3", got.Version())
			}
			if want := time.Unix(date, 0).UTC(); !got.Generated().Equal(want) {
				t.Errorf("Generated() = %v, want %v", got.Generated(), want)
			}
			if got.Sections() != 1 {
				t.Errorf("Sections() = %d, want 1", got.Sections())
			}
		})
	}

	t.Run("bytes cannot change the krl", func(t *testing.T) {
		v := fetch(t, ca, b)

		v.Bytes()[0]++
		if !bytes.Equal(v.Bytes(), b) {
			t.Errorf("Bytes() changed after modifying a returned slice")
		}
	})
}

func TestFetchErrors(t *testing.T) {
	ca := newSigner(t)
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
			_, gotErr := krl.Fetch(tt.ctx, "https://ssh.example.com/", krl.Host, ca.PublicKey(), api.WithHTTPClient(&responseClient{fn: tt.fn}))
			if gotErr == nil {
				t.Fatal("Fetch() succeeded unexpectedly")
			}
			if tt.wantErr != nil && !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("Fetch() error = %v, want %v", gotErr, tt.wantErr)
			}
			if tt.wantMessage != "" && !strings.HasSuffix(gotErr.Error(), tt.wantMessage) {
				t.Errorf("Fetch() error = %q, want suffix %q", gotErr, tt.wantMessage)
			}
		})
	}
}

func TestFetchNoRequest(t *testing.T) {
	ca := newSigner(t)
	client := &responseClient{fn: func(req *http.Request) (*http.Response, error) {
		t.Errorf("Fetch() made a request to %q", req.URL)
		return response(http.StatusOK, "application/json", `{"krl":"","signature":""}`)(req)
	}}

	tests := []struct {
		name            string
		certificateType krl.CertificateType
		pub             ssh.PublicKey
		wantErr         error
	}{
		{"empty type", "", ca.PublicKey(), nil},
		{"unknown type", "other", ca.PublicKey(), nil},
		{"no public key", krl.User, nil, krl.ErrNoPublicKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := krl.Fetch(t.Context(), "https://ssh.example.com/", tt.certificateType, tt.pub, api.WithHTTPClient(client))
			if err == nil {
				t.Fatal("Fetch() succeeded unexpectedly")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Fetch() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestFetchDefaultClient(t *testing.T) {
	ca := newSigner(t)
	b := marshal(t, certificateSection(ca.PublicKey()))
	body, err := json.Marshal(api.KeyRevocationListResponse{Krl: b, Signature: sign(t, b, ca)})
	if err != nil {
		t.Fatalf("marshalling response: %v", err)
	}

	var gotUserAgent, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		gotHeader = r.Header.Get("X-Test")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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

			if _, err := krl.Fetch(t.Context(), srv.URL, krl.Host, ca.PublicKey(), tt.opts...); err != nil {
				t.Fatalf("Fetch() failed: %v", err)
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

func TestFetchVerification(t *testing.T) {
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
	otherCAThenExplicitKey := marshal(t, certificateSection(other.PublicKey()), &sshkrl.KRLExplicitKeySection{other.PublicKey()})

	// change the last byte (the revoked serial) after signing
	tampered := bytes.Clone(valid)
	tampered[len(tampered)-1]++

	tests := []struct {
		name         string
		krl          []byte
		signature    string
		wantSections int
		wantErr      error
	}{
		{"empty krl", empty, sign(t, empty, ca), 0, nil},
		{"serial list", valid, sign(t, valid, ca), 1, nil},
		{"all certificate subsections", allSubsections, sign(t, allSubsections, ca), 1, nil},
		{"multiple sections", multipleSections, sign(t, multipleSections, ca), 2, nil},

		{"no signature", valid, "", 0, krl.ErrInvalidSignature},
		{"malformed signature", valid, "not a signature", 0, krl.ErrInvalidSignature},
		{"wrong signer", valid, sign(t, valid, other), 0, krl.ErrInvalidSignature},
		{"signature for other data", valid, sign(t, empty, ca), 0, krl.ErrInvalidSignature},
		{"krl changed after signing", tampered, sign(t, valid, ca), 0, krl.ErrInvalidSignature},
		{"wrong namespace", valid, signWith(t, valid, ca, sshsig.HashSHA512, "file"), 0, krl.ErrInvalidSignature},
		{"sha256 signature", valid, signWith(t, valid, ca, sshsig.HashSHA256, krl.Namespace), 0, krl.ErrInvalidSignature},

		{"malformed krl", malformed, sign(t, malformed, ca), 0, errParse},
		{"other ca", otherCA, sign(t, otherCA, ca), 0, krl.ErrUnexpectedCA},
		{"any ca", anyCA, sign(t, anyCA, ca), 0, krl.ErrUnexpectedCA},
		{"one section for other ca", oneOtherCA, sign(t, oneOtherCA, ca), 0, krl.ErrUnexpectedCA},
		{"explicit key section", explicitKey, sign(t, explicitKey, ca), 0, krl.ErrUnexpectedSection},
		{"sha1 fingerprint section", fingerprintSHA1, sign(t, fingerprintSHA1, ca), 0, krl.ErrUnexpectedSection},
		{"sha256 fingerprint section", fingerprintSHA256, sign(t, fingerprintSHA256, ca), 0, krl.ErrUnexpectedSection},
		{"certificate and explicit key sections", mixedSections, sign(t, mixedSections, ca), 0, krl.ErrUnexpectedSection},

		// section types are checked before the CA of each section
		{"other ca then explicit key section", otherCAThenExplicitKey, sign(t, otherCAThenExplicitKey, ca), 0, krl.ErrUnexpectedSection},

		// the signature is checked before the krl is parsed
		{"malformed signature with malformed krl", malformed, "not a signature", 0, krl.ErrInvalidSignature},
		{"wrong signer with malformed krl", malformed, sign(t, malformed, other), 0, krl.ErrInvalidSignature},
		{"wrong signer with explicit key section", explicitKey, sign(t, explicitKey, other), 0, krl.ErrInvalidSignature},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := krl.Fetch(t.Context(), "https://ssh.example.com/", krl.User, ca.PublicKey(), api.WithHTTPClient(serve(t, tt.krl, tt.signature)))
			checkErr(t, "Fetch", err, tt.wantErr)

			if err == nil && got.Sections() != tt.wantSections {
				t.Errorf("Sections() = %d, want %d", got.Sections(), tt.wantSections)
			}
		})
	}
}

func TestFetchKeyTypes(t *testing.T) {
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
			fetch(t, tt.signer, marshal(t, certificateSection(tt.signer.PublicKey())))
		})
	}
}

// TestFetchType checks the certificate type the CA signs into the KRL's
// comment is the one requested, so the KRL for one type can't be used as the
// other (#239). CA 1.0.2 and earlier leave the comment empty.
func TestFetchType(t *testing.T) {
	ca := newSigner(t)
	other := newSigner(t)

	const date = 1_800_000_000

	tests := []struct {
		name      string
		requested krl.CertificateType
		comment   string
		wantTyped bool
		wantErr   error
	}{
		{"user krl", krl.User, "user", true, nil},
		{"host krl", krl.Host, "host", true, nil},
		{"untyped as user", krl.User, "", false, nil},
		{"untyped as host", krl.Host, "", false, nil},

		{"host krl as user", krl.User, "host", false, krl.ErrUnexpectedType},
		{"user krl as host", krl.Host, "user", false, krl.ErrUnexpectedType},
		{"type in another case", krl.User, "User", false, krl.ErrUnexpectedType},
		{"type with more text", krl.User, "user krl", false, krl.ErrUnexpectedType},
		{"unknown type", krl.User, "other", false, krl.ErrUnexpectedType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := typed(t, ca, 1, date, tt.comment)

			got, err := krl.Fetch(t.Context(), "https://ssh.example.com/", tt.requested, ca.PublicKey(), api.WithHTTPClient(serve(t, b, sign(t, b, ca))))
			checkErr(t, "Fetch", err, tt.wantErr)

			if err == nil && got.Typed() != tt.wantTyped {
				t.Errorf("Typed() = %v, want %v", got.Typed(), tt.wantTyped)
			}
		})
	}

	// the signature is checked before the type, so an unsigned KRL is
	// reported as unsigned
	t.Run("wrong signer and type", func(t *testing.T) {
		b := typed(t, ca, 1, date, "host")

		_, err := krl.Fetch(t.Context(), "https://ssh.example.com/", krl.User, ca.PublicKey(), api.WithHTTPClient(serve(t, b, sign(t, b, other))))
		checkErr(t, "Fetch", err, krl.ErrInvalidSignature)
	})
}

// TestInstallType checks that once a KRL naming its type is installed, only
// a KRL of that type replaces it: an untyped KRL then comes from a CA that
// was downgraded, or is an old KRL replayed, which may be the other type's
// (#239). File modes are checked by TestInstall.
func TestInstallType(t *testing.T) {
	ca := newSigner(t)

	const date = 1_800_000_000
	malformed := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}

	tests := []struct {
		name        string
		requested   krl.CertificateType
		krl         []byte
		existing    []byte
		wantOutcome krl.Outcome
		wantErr     error
	}{
		{"untyped with no existing krl", krl.User, generated(t, ca, 1, date), nil, krl.Written, nil},
		{"untyped over untyped", krl.User, generated(t, ca, 1, date+1), generated(t, ca, 1, date), krl.Written, nil},
		{"untyped over malformed", krl.User, generated(t, ca, 1, date), malformed, krl.ReplacedUnparseable, nil},
		{"typed with no existing krl", krl.User, typed(t, ca, 1, date, "user"), nil, krl.Written, nil},
		{"typed over typed", krl.User, typed(t, ca, 1, date+1, "user"), typed(t, ca, 1, date, "user"), krl.Written, nil},
		{"typed over malformed", krl.Host, typed(t, ca, 1, date, "host"), malformed, krl.ReplacedUnparseable, nil},

		// the CA's version and generated date don't change when it starts
		// naming the type, so the same KRL replaces its untyped copy
		{"typed over untyped of the same version", krl.User, typed(t, ca, 1, date, "user"), generated(t, ca, 1, date), krl.Written, nil},

		{"untyped over typed", krl.User, generated(t, ca, 1, date+1), typed(t, ca, 1, date, "user"), krl.Written, krl.ErrUntypedKRL},
		{"untyped of a higher version over typed", krl.User, generated(t, ca, 9, date+1), typed(t, ca, 1, date, "user"), krl.Written, krl.ErrUntypedKRL},
		{"over the other type", krl.User, typed(t, ca, 2, date+1, "user"), typed(t, ca, 1, date, "host"), krl.Written, krl.ErrUnexpectedType},
		{"untyped over the other type", krl.User, generated(t, ca, 2, date+1), typed(t, ca, 1, date, "host"), krl.Written, krl.ErrUnexpectedType},

		// the type is checked before the version
		{"older over the other type", krl.User, typed(t, ca, 1, date-1, "user"), typed(t, ca, 1, date, "host"), krl.Written, krl.ErrUnexpectedType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := fetchType(t, ca, tt.krl, tt.requested)
			path := filepath.Join(t.TempDir(), "revocation_list")
			if tt.existing != nil {
				if err := os.WriteFile(path, tt.existing, 0600); err != nil {
					t.Fatalf("writing existing krl: %v", err)
				}
			}

			got, err := v.Install(path)
			checkErr(t, "Install", err, tt.wantErr)

			want := tt.krl
			if tt.wantErr != nil {
				want = tt.existing
			} else if got != tt.wantOutcome {
				t.Errorf("Install() = %v, want %v", got, tt.wantOutcome)
			}

			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading krl: %v", err)
			}
			if !bytes.Equal(b, want) {
				t.Errorf("krl file = %x, want %x", b, want)
			}
		})
	}
}
