//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andrewheberle/ssh-ca-client/internal/pkg/api"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/cert/filestore"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/krl"
	"github.com/andrewheberle/ssh-ca-client/pkg/proof"
	"github.com/andrewheberle/ssh-ca-client/pkg/sshkey"
	sshkrl "github.com/forfuncsake/krl"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/crypto/ssh"
)

const (
	// audience is the audience the CA requires on identity tokens
	audience = "ssh-ca-client"

	// startTimeout is how long to wait for the CA to start listening
	startTimeout = time.Second * 15

	// stopTimeout is how long to wait for the CA to exit before killing it
	stopTimeout = time.Second * 5
)

// testIDP is an OIDC identity provider that serves a JWKS for the CA to
// verify tokens with and signs tokens for the tests
type testIDP struct {
	*httptest.Server

	signer jose.Signer
}

func newIDP(t *testing.T) *testIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating IdP key: %v", err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       jose.JSONWebKey{Key: key, KeyID: "e2e", Algorithm: string(jose.RS256), Use: "sig"},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("creating IdP signer: %v", err)
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "e2e", Algorithm: string(jose.RS256), Use: "sig"}},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	idp := &testIDP{
		Server: httptest.NewServer(mux),
		signer: signer,
	}
	t.Cleanup(idp.Close)

	return idp
}

// claims returns valid token claims for email, with groups as the claim the
// CA takes principals from. The groups claim is left out when no groups are
// provided.
func (idp *testIDP) claims(email string, groups ...string) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss":   idp.URL,
		"sub":   "sub|" + email,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"email": email,
	}

	if len(groups) > 0 {
		claims["groups"] = groups
	}

	return claims
}

// sign returns a JWT for claims
func (idp *testIDP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	token, err := jwt.Signed(idp.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("signing token: %v", err)
	}

	return token
}

// tokens returns valid access and identity tokens for email
func (idp *testIDP) tokens(t *testing.T, email string, groups ...string) *auth.Tokens {
	t.Helper()

	token := idp.sign(t, idp.claims(email, groups...))

	return &auth.Tokens{Access: token, Identity: token}
}

// staticAuth is an [auth.Handler] that returns fixed tokens
type staticAuth struct {
	tokens *auth.Tokens
}

func (a *staticAuth) GetTokens() (*auth.Tokens, error) {
	return a.tokens, nil
}

func (a *staticAuth) GetTokensContext(ctx context.Context) (*auth.Tokens, error) {
	return a.tokens, nil
}

// testCA is a running instance of the CA harness
type testCA struct {
	// URL is the base URL of the CA
	URL string

	// PublicKey is the public key of the CA
	PublicKey ssh.PublicKey

	// IDP is the identity provider the CA trusts
	IDP *testIDP

	// Signer is the CA private key, for creating certificates the CA did not
	// issue itself
	Signer ssh.Signer

	logFile string
}

type caConfig struct {
	key      crypto.Signer
	keyType  sshkey.KeyType
	curve    elliptic.Curve
	bindings map[string]string
}

type caOption func(*caConfig)

// withBinding sets a Worker binding (environment variable) of the CA
func withBinding(name, value string) caOption {
	return func(c *caConfig) {
		c.bindings[name] = value
	}
}

// withBindings sets several Worker bindings (environment variables) of the CA
func withBindings(bindings map[string]string) caOption {
	return func(c *caConfig) {
		maps.Copy(c.bindings, bindings)
	}
}

// withCAKey sets the CA private key rather than generating one
func withCAKey(key crypto.Signer) caOption {
	return func(c *caConfig) {
		c.key = key
	}
}

// withCAKeyType sets the type of CA private key
func withCAKeyType(keyType sshkey.KeyType, curve elliptic.Curve) caOption {
	return func(c *caConfig) {
		c.keyType = keyType
		c.curve = curve
	}
}

// newCA starts a CA, with its own identity provider, that is stopped when the
// test completes.
//
// Errors logged by the CA that indicate a fault in the harness rather than an
// expected rejection of a request fail the test, as the CA does not report
// all of these to clients.
func newCA(t *testing.T, opts ...caOption) *testCA {
	t.Helper()

	idp := newIDP(t)

	config := &caConfig{
		keyType: sshkey.KeyTypeEd25519,
		bindings: map[string]string{
			"ISSUER_DN":                            "CN=SSH CA,O=ssh-ca-client e2e,C=AU",
			"JWT_JWKS_URL":                         idp.URL + "/jwks",
			"JWT_ISSUER":                           idp.URL,
			"JWT_AUD":                              audience,
			"JWT_ALGORITHMS":                       "RS256",
			"JWT_SSH_CERTIFICATE_PRINCIPALS_CLAIM": "groups",
			"SSH_CERTIFICATE_LIFETIME":             "24 hours",
			"SSH_CERTIFICATE_PRINCIPALS":           "",
			"SSH_CERTIFICATE_INCLUDE_SELF":         "true",
			"SSH_CERTIFICATE_INCLUDE_SELF_EMAIL":   "false",
			"SSH_CERTIFICATE_EXTENSIONS":           "permit-agent-forwarding,permit-port-forwarding,permit-pty",
			"SSH_HOST_CERTIFICATE_LIFETIME":        "30 days",
			"SSH_HOST_CERTIFICATE_ALLOWED_EMAILS":  "host-admin@example.com",
			"SSH_HOST_CERTIFICATE_ALLOWED_ROLES":   "host-admins",
			"CERTIFICATE_REQUEST_TIME_SKEW_MAX":    "90 seconds",
			"DB_CERTIFICATE_RETENTION":             "1 year",
			"LOG_LEVEL":                            "info",
		},
	}
	for _, o := range opts {
		o(config)
	}

	// generate CA key unless one was provided
	key := config.key
	if key == nil {
		var err error
		key, err = sshkey.GeneratePrivateKey(config.keyType, config.curve)
		if err != nil {
			t.Fatalf("generating CA key: %v", err)
		}
	}
	signer, err := ssh.NewSignerFromSigner(key)
	if err != nil {
		t.Fatalf("creating CA signer: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshalling CA key: %v", err)
	}

	// write harness config
	dir := t.TempDir()
	portFile := filepath.Join(dir, "port")
	logFile := filepath.Join(dir, "ca.log")
	configFile := filepath.Join(dir, "config.json")

	harnessConfig, err := json.Marshal(map[string]any{
		"private_key": string(pem.EncodeToMemory(block)),
		"bindings":    config.bindings,
		"port_file":   portFile,
		"log_file":    logFile,
	})
	if err != nil {
		t.Fatalf("marshalling harness config: %v", err)
	}
	if err := os.WriteFile(configFile, harnessConfig, 0o600); err != nil {
		t.Fatalf("writing harness config: %v", err)
	}

	// start harness
	output, err := os.Create(filepath.Join(dir, "output.log"))
	if err != nil {
		t.Fatalf("creating harness output file: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })

	cmd := exec.Command(nodePath, serverPath, configFile)
	cmd.Stdout = output
	cmd.Stderr = output
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("creating harness stdin: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting harness: %v", err)
	}

	exited := make(chan error, 1)
	go func() {
		exited <- cmd.Wait()
	}()

	t.Cleanup(func() {
		// closing stdin asks the harness to exit
		_ = stdin.Close()
		select {
		case <-exited:
		case <-time.After(stopTimeout):
			_ = cmd.Process.Kill()
			<-exited
		}

		checkLog(t, logFile)

		if t.Failed() {
			logContents(t, "CA log", logFile)
			logContents(t, "CA harness output", output.Name())
		}
	})

	port, err := waitForPort(portFile, exited)
	if err != nil {
		t.Fatalf("waiting for CA to start: %v", err)
	}

	return &testCA{
		URL:       "http://127.0.0.1:" + port,
		PublicKey: signer.PublicKey(),
		IDP:       idp,
		Signer:    signer,
		logFile:   logFile,
	}
}

// waitForPort waits for the harness to write the port it is listening on
func waitForPort(portFile string, exited <-chan error) (string, error) {
	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()

	timeout := time.After(startTimeout)

	for {
		select {
		case err := <-exited:
			return "", fmt.Errorf("harness exited: %v", err)
		case <-timeout:
			return "", errors.New("timed out")
		case <-ticker.C:
			b, err := os.ReadFile(portFile)
			if err == nil && len(b) > 0 {
				return strings.TrimSpace(string(b)), nil
			}
		}
	}
}

// logEntry is a line logged by the CA or harness
type logEntry struct {
	Level   string `json:"level"`
	Message string `json:"message"`

	// set for requests logged by the harness
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// faultMessages are messages logged by the CA when returning an internal
// server error
var faultMessages = []string{"unhandled error", "unexpected error from router"}

// checkLog fails the test for any errors logged by the CA that indicate a
// fault in the harness, such as database errors, which are otherwise only
// logged by the CA when issuing certificates.
func checkLog(t *testing.T, logFile string) {
	t.Helper()

	b, err := os.ReadFile(logFile)
	if errors.Is(err, os.ErrNotExist) {
		return
	} else if err != nil {
		t.Errorf("reading CA log: %v", err)
		return
	}

	for line := range bytes.Lines(b) {
		var entry logEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		if entry.Level != "error" {
			continue
		}

		if strings.HasPrefix(entry.Message, "harness") ||
			strings.Contains(entry.Message, "database") ||
			slices.Contains(faultMessages, entry.Message) {
			t.Errorf("CA logged a fault: %s", bytes.TrimSpace(line))
		}
	}
}

// assertRejected checks the CA rejected a request with an error containing
// message, to ensure a request failed for the expected reason
func (ca *testCA) assertRejected(t *testing.T, message string) {
	t.Helper()

	b, err := os.ReadFile(ca.logFile)
	if err != nil {
		t.Fatalf("reading CA log: %v", err)
	}

	for line := range bytes.Lines(b) {
		var entry logEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		if entry.Status >= http.StatusBadRequest && strings.Contains(entry.Body, message) {
			return
		}
	}

	t.Errorf("CA did not reject a request with %q", message)
}

func logContents(t *testing.T, name, path string) {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Logf("%s: %v", name, err)
		return
	}

	t.Logf("%s:\n%s", name, b)
}

// newStore returns a [filestore.Storage] with a newly generated private key
func (ca *testCA) newStore(t *testing.T, opts ...filestore.Option) *filestore.Storage {
	t.Helper()

	store, err := filestore.New(ca.PublicKey, filepath.Join(t.TempDir(), "id"), opts...)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}

	if err := store.GeneratePrivateKey(); err != nil {
		t.Fatalf("generating private key: %v", err)
	}

	return store
}

// userCertificate returns a [cert.UserCertificate] for the CA
func (ca *testCA) userCertificate(t *testing.T, store cert.Storage, tokens *auth.Tokens) *cert.UserCertificate {
	t.Helper()

	u, err := cert.NewUserCertificate(ca.URL, store)
	if err != nil {
		t.Fatalf("creating user certificate: %v", err)
	}
	u.AuthHandler = &staticAuth{tokens: tokens}

	return u
}

// hostCertificate returns a [cert.HostCertificate] for the CA
func (ca *testCA) hostCertificate(t *testing.T, store cert.Storage, tokens *auth.Tokens, principals ...string) *cert.HostCertificate {
	t.Helper()

	h, err := cert.NewHostCertificate(ca.URL, store)
	if err != nil {
		t.Fatalf("creating host certificate: %v", err)
	}
	h.AuthHandler = &staticAuth{tokens: tokens}
	h.Principals = principals

	return h
}

// client returns an API client for the CA
func (ca *testCA) client(t *testing.T) *api.ClientWithResponses {
	t.Helper()

	client, err := api.NewClientWithResponses(ca.URL)
	if err != nil {
		t.Fatalf("creating API client: %v", err)
	}

	return client
}

// revoke revokes the certificate with serial using the API, with proof of
// possession of the private key in store, as the client does not implement
// revocation. The status code of the response is returned.
func (ca *testCA) revoke(t *testing.T, certificateType api.PostCertificateTypeRevokeParamsCertificateType, serial uint64, store cert.Storage) int {
	t.Helper()

	signer, err := store.Signer()
	if err != nil {
		t.Fatalf("getting signer: %v", err)
	}

	p, err := proof.Generate(signer)
	if err != nil {
		t.Fatalf("generating proof: %v", err)
	}

	res, err := ca.client(t).PostCertificateTypeRevokeWithResponse(context.Background(), certificateType, api.CertificateRevocation{
		Serial:    strconv.FormatUint(serial, 10),
		PublicKey: ssh.MarshalAuthorizedKey(signer.PublicKey()),
		Proof:     p.String(),
	})
	if err != nil {
		t.Fatalf("revoking certificate: %v", err)
	}

	return res.StatusCode()
}

// krl fetches and verifies the KRL for certificateType
func (ca *testCA) krl(t *testing.T, certificateType api.GetCertificateTypeKrlParamsCertificateType) *sshkrl.KRL {
	t.Helper()

	res, err := krl.Get(ca.URL, certificateType)
	if err != nil {
		t.Fatalf("getting %s KRL: %v", certificateType, err)
	}

	if err := res.VerifyStrict(ca.PublicKey); err != nil {
		t.Fatalf("verifying %s KRL: %v", certificateType, err)
	}

	parsed, err := sshkrl.ParseKRL(res.Krl)
	if err != nil {
		t.Fatalf("parsing %s KRL: %v", certificateType, err)
	}

	return parsed
}

// sign creates a certificate signed by the CA private key without involving
// the CA, for certificates the CA would not issue itself
func (ca *testCA) sign(t *testing.T, c *ssh.Certificate) {
	t.Helper()

	if err := c.SignCert(rand.Reader, ca.Signer); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
}

// certificate returns the certificate saved in store
func certificate(t *testing.T, store cert.Storage) *ssh.Certificate {
	t.Helper()

	c, err := store.Certificate()
	if err != nil {
		t.Fatalf("getting certificate: %v", err)
	}

	return c
}

// waitUntilValid waits until the validity period of c has started, as the CA
// may set ValidAfter up to a second in the future and does not renew
// certificates before they are valid
func waitUntilValid(c *ssh.Certificate) {
	time.Sleep(time.Until(time.Unix(int64(c.ValidAfter), 0)) + time.Millisecond*50)
}

// lifetime returns the validity period of c
func lifetime(c *ssh.Certificate) time.Duration {
	return time.Duration(c.ValidBefore-c.ValidAfter) * time.Second
}

// assertLifetime checks the validity period of c is want, allowing for the
// CA setting the start and end of the period at slightly different times
func assertLifetime(t *testing.T, c *ssh.Certificate, want time.Duration) {
	t.Helper()

	if got := lifetime(c); math.Abs(float64(got-want)) > float64(time.Second*2) {
		t.Errorf("certificate lifetime = %s, want %s", got, want)
	}
}

// assertStatus checks err is from the CA responding with status code
func assertStatus(t *testing.T, err error, code int) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected the CA to respond with status %d but there was no error", code)
	}

	if want := fmt.Sprintf("bad status code: %d", code); !strings.Contains(err.Error(), want) {
		t.Fatalf("expected the CA to respond with status %d, got error: %v", code, err)
	}
}

// certStore is a [cert.Storage] that returns a fixed certificate, for
// presenting certificates to the CA that the wrapped store would not accept
type certStore struct {
	cert.Storage

	certificate *ssh.Certificate
}

func (s *certStore) Certificate() (*ssh.Certificate, error) {
	return s.certificate, nil
}

func (s *certStore) CertificateBytes() ([]byte, error) {
	return ssh.MarshalAuthorizedKey(s.certificate), nil
}

func (s *certStore) SaveCertificate(c *ssh.Certificate) error {
	s.certificate = c
	return nil
}

var _ cert.Storage = (*certStore)(nil)

// keysEqual reports whether two public keys are the same
func keysEqual(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}
