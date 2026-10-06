package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	testClientID    = "test-client"
	// port 0 has the login server listen on any free port
	testRedirectURL = "http://127.0.0.1:0/auth/callback"
)

// grant controls how the fake IdP responds to a token request for one grant
// type
type grant struct {
	status       int    // non-zero to fail the request with this status
	omitIDToken  bool   // do not include an id_token in the response
	wrongKey     bool   // sign the id_token with a key the verifier does not trust
	refreshToken string // refresh token to issue, empty to omit
	expiresIn    int    // access token lifetime in seconds, 0 for one hour
}

// fakeIdP is a minimal OIDC provider supporting discovery, JWKS and the
// authorization_code (with PKCE) and refresh_token grants
type fakeIdP struct {
	*httptest.Server

	key      *rsa.PrivateKey
	otherKey *rsa.PrivateKey

	mu              sync.Mutex
	code            grant
	refresh         grant
	challenges      map[string]string // authorization code -> PKCE challenge
	tokenRequests   int
	gotRefreshToken string
	issued          Tokens // the last tokens issued
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()

	idp := &fakeIdP{
		key:        newRSAKey(t),
		otherKey:   newRSAKey(t),
		challenges: make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", idp.discovery)
	mux.HandleFunc("GET /jwks", idp.jwks)
	mux.HandleFunc("POST /token", idp.token)
	idp.Server = httptest.NewServer(mux)
	t.Cleanup(idp.Close)

	return idp
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate RSA key: %v", err)
	}

	return key
}

func (idp *fakeIdP) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                idp.URL,
		"authorization_endpoint":                idp.URL + "/authorize",
		"token_endpoint":                        idp.URL + "/token",
		"jwks_uri":                              idp.URL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (idp *fakeIdP) jwks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(idp.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idp.key.E)).Bytes()),
		}},
	})
}

func (idp *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	idp.tokenRequests++

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	var g grant
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		g = idp.code

		// check the PKCE code verifier matches the challenge for this code
		challenge, ok := idp.challenges[r.PostForm.Get("code")]
		delete(idp.challenges, r.PostForm.Get("code"))
		hash := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(hash[:]) != challenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
	case "refresh_token":
		g = idp.refresh
		idp.gotRefreshToken = r.PostForm.Get("refresh_token")
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}

	if g.status != 0 {
		writeJSON(w, g.status, map[string]string{"error": "server_error"})
		return
	}

	expiresIn := 3600
	if g.expiresIn != 0 {
		expiresIn = g.expiresIn
	}

	res := map[string]any{
		"access_token": fmt.Sprintf("access-%d", idp.tokenRequests),
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}
	if g.refreshToken != "" {
		res["refresh_token"] = g.refreshToken
	}

	idp.issued = Tokens{Access: res["access_token"].(string)}
	if !g.omitIDToken {
		key := idp.key
		if g.wrongKey {
			key = idp.otherKey
		}
		idp.issued.Identity = idp.idToken(key)
		res["id_token"] = idp.issued.Identity
	}

	writeJSON(w, http.StatusOK, res)
}

// idToken returns an RS256 signed ID token for the test client
func (idp *fakeIdP) idToken(key *rsa.PrivateKey) string {
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": idp.URL,
		"sub": "test-user",
		"aud": testClientID,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})

	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	hash := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		panic(err)
	}

	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// issueCode returns a new authorization code bound to the PKCE challenge
func (idp *fakeIdP) issueCode(challenge string) string {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	code := fmt.Sprintf("code-%d", len(idp.challenges)+idp.tokenRequests)
	idp.challenges[code] = challenge

	return code
}

// lastIssued returns the most recently issued tokens
func (idp *fakeIdP) lastIssued() Tokens {
	idp.mu.Lock()
	defer idp.mu.Unlock()

	return idp.issued
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// browser controls how the simulated browser behaves during the login flow
type browser struct {
	badState  bool // return a state that does not match the session
	badCode   bool // return an authorization code the IdP did not issue
	noCookies bool // do not send the session cookie to the callback
}

// browserResult is the outcome of a simulated browser login
type browserResult struct {
	Code int    // status code of the callback response
	Body string // body of the callback response
	Err  error  // set if the browser could not complete the flow

	LoginURL string // the login URL the browser was opened at
}

// completeLogin simulates the user's browser completing the login flow over
// HTTP against the handler's login server: it requests loginURL, has the IdP
// issue an authorization code for the redirect and then requests the callback
func (b browser) completeLogin(idp *fakeIdP, loginURL string) *browserResult {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return &browserResult{Err: err}
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	res, err := client.Get(loginURL)
	if err != nil {
		return &browserResult{Err: fmt.Errorf("login request failed: %w", err)}
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		return &browserResult{Err: fmt.Errorf("login status = %d, want %d", res.StatusCode, http.StatusFound)}
	}

	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		return &browserResult{Err: err}
	}

	code := idp.issueCode(loc.Query().Get("code_challenge"))
	if b.badCode {
		code = "not-issued"
	}

	q := url.Values{}
	q.Set("code", code)
	q.Set("state", loc.Query().Get("state"))
	if b.badState {
		q.Set("state", "wrong")
	}

	// the IdP redirects to the callback on the same server as the login URL
	callbackURL, _ := url.Parse(loginURL)
	callbackURL.Path = "/auth/callback"
	callbackURL.RawQuery = q.Encode()

	if b.noCookies {
		client.Jar = nil
	}

	res, err = client.Get(callbackURL.String())
	if err != nil {
		return &browserResult{Err: fmt.Errorf("callback request failed: %w", err)}
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)

	return &browserResult{Code: res.StatusCode, Body: string(body), LoginURL: loginURL}
}

// callback calls Callback directly without first calling Login
func callback(h *OidcHandler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.Callback(rec, httptest.NewRequest(http.MethodGet, "/auth/callback?code=x&state=y", nil))

	return rec
}

// stubOpenURL replaces openURL for the duration of the test
func stubOpenURL(t *testing.T, fn func(loginURL string) error) {
	t.Helper()

	orig := openURL
	openURL = fn
	t.Cleanup(func() { openURL = orig })
}

// stubBrowser replaces openURL with a simulated browser that completes the
// login flow in the background. The result is sent on the returned channel.
func stubBrowser(t *testing.T, idp *fakeIdP, b browser, openErr error) <-chan *browserResult {
	t.Helper()

	ch := make(chan *browserResult, 1)
	stubOpenURL(t, func(loginURL string) error {
		checkLoginURL(t, loginURL)
		go func() { ch <- b.completeLogin(idp, loginURL) }()
		return openErr
	})

	return ch
}

// checkLoginURL checks loginURL uses the redirect URL host, the login path
// and the port actually listened on
func checkLoginURL(t *testing.T, loginURL string) {
	t.Helper()

	u, err := url.Parse(loginURL)
	if err != nil {
		t.Errorf("login URL %q could not be parsed: %v", loginURL, err)
		return
	}
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Path != "/auth/login" {
		t.Errorf("login URL = %q, want http://127.0.0.1:<port>/auth/login", loginURL)
	}
	if u.Port() == "" || u.Port() == "0" {
		t.Errorf("login URL = %q, want the listening port", loginURL)
	}
}

// awaitBrowser waits for the simulated browser result and fails the test if
// the browser could not complete the flow
func awaitBrowser(t *testing.T, ch <-chan *browserResult) *browserResult {
	t.Helper()

	res := <-ch
	if res.Err != nil {
		t.Fatalf("browser error: %v", res.Err)
	}

	return res
}

func newHandler(t *testing.T, idp *fakeIdP, opts ...OidcHandlerOption) *OidcHandler {
	t.Helper()

	h, err := NewOidcHandler(OidcConfig{
		ClientID:    testClientID,
		Issuer:      idp.URL,
		RedirectURL: testRedirectURL,
		Scopes:      []string{oidc.ScopeOpenID},
	}, opts...)
	if err != nil {
		t.Fatalf("NewOidcHandler() error = %v", err)
	}

	return h
}

func TestNewOidcHandler(t *testing.T) {
	idp := newFakeIdP(t)

	t.Run("defaults", func(t *testing.T) {
		h := newHandler(t, idp)

		if h.loginTimeout != DefaultLoginTimeout {
			t.Errorf("loginTimeout = %v, want %v", h.loginTimeout, DefaultLoginTimeout)
		}
		if h.oauth2Config.ClientID != testClientID {
			t.Errorf("ClientID = %q, want %q", h.oauth2Config.ClientID, testClientID)
		}
		if h.oauth2Config.Endpoint.TokenURL != idp.URL+"/token" {
			t.Errorf("TokenURL = %q, want %q", h.oauth2Config.Endpoint.TokenURL, idp.URL+"/token")
		}
		if h.loginPending() {
			t.Errorf("login pending after NewOidcHandler()")
		}
	})

	t.Run("with login timeout", func(t *testing.T) {
		h := newHandler(t, idp, WithLoginTimeout(time.Minute))

		if h.loginTimeout != time.Minute {
			t.Errorf("loginTimeout = %v, want %v", h.loginTimeout, time.Minute)
		}
	})

	t.Run("redirect URL", func(t *testing.T) {
		tests := []struct {
			redirectURL    string
			wantListenAddr string
			wantErr        bool
		}{
			{"http://localhost:3000/auth/callback", "localhost:3000", false},
			{"http://127.0.0.1:8080/callback", "127.0.0.1:8080", false},
			{"http://[::1]:3000/auth/callback", "[::1]:3000", false},
			{"http://localhost/auth/callback", "localhost:80", false},
			{"https://localhost:3000/auth/callback", "", true},
			{"ftp://localhost/auth/callback", "", true},
			{"http:///auth/callback", "", true},
			{"localhost:3000/auth/callback", "", true},
			{"http://[::1", "", true},
		}
		for _, tt := range tests {
			t.Run(tt.redirectURL, func(t *testing.T) {
				h, err := NewOidcHandler(OidcConfig{
					ClientID:    testClientID,
					Issuer:      idp.URL,
					RedirectURL: tt.redirectURL,
				})
				if (err != nil) != tt.wantErr {
					t.Fatalf("NewOidcHandler() error = %v, wantErr %v", err, tt.wantErr)
				}
				if err == nil && h.listenAddr != tt.wantListenAddr {
					t.Errorf("listenAddr = %q, want %q", h.listenAddr, tt.wantListenAddr)
				}
			})
		}
	})

	t.Run("custom login path", func(t *testing.T) {
		h, err := NewOidcHandler(OidcConfig{
			ClientID:    testClientID,
			Issuer:      idp.URL,
			LoginPath:   "/custom/login",
			RedirectURL: testRedirectURL,
		})
		if err != nil {
			t.Fatalf("NewOidcHandler() error = %v", err)
		}

		gotURL := make(chan string, 1)
		stubOpenURL(t, func(loginURL string) error {
			gotURL <- loginURL
			return nil
		})
		h.loginTimeout = 50 * time.Millisecond
		_, _ = h.GetTokensContext(context.Background())

		u, err := url.Parse(<-gotURL)
		if err != nil {
			t.Fatalf("could not parse login URL: %v", err)
		}
		if u.Path != "/custom/login" {
			t.Errorf("login URL path = %q, want %q", u.Path, "/custom/login")
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		_, err := NewOidcHandler(OidcConfig{ClientID: testClientID, Issuer: idp.URL + "/missing"})
		if err == nil {
			t.Errorf("NewOidcHandler() error = nil, want error")
		}
	})
}

func TestOidcHandler_GetTokensContext_Interactive(t *testing.T) {
	tests := []struct {
		name             string
		refreshToken     string
		openErr          error
		wantRefreshToken string
	}{
		{"success", "refresh-1", nil, "refresh-1"},
		{"no refresh token issued", "", nil, ""},
		{"browser could not be opened", "refresh-1", errors.New("no browser"), "refresh-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.code.refreshToken = tt.refreshToken
			h := newHandler(t, idp)
			callbacks := stubBrowser(t, idp, browser{}, tt.openErr)

			tokens, err := h.GetTokens()
			if err != nil {
				t.Fatalf("GetTokens() error = %v", err)
			}

			want := idp.lastIssued()
			if *tokens != want {
				t.Errorf("GetTokens() = %+v, want %+v", *tokens, want)
			}
			if h.refreshToken != tt.wantRefreshToken {
				t.Errorf("refreshToken = %q, want %q", h.refreshToken, tt.wantRefreshToken)
			}
			if h.loginPending() {
				t.Errorf("login still pending after GetTokens()")
			}

			res := awaitBrowser(t, callbacks)
			if res.Code != http.StatusOK {
				t.Errorf("callback status = %d, want %d", res.Code, http.StatusOK)
			}

			// the login server is stopped once the login completes
			if res, err := http.Get(res.LoginURL); err == nil {
				res.Body.Close()
				t.Errorf("login server still running after GetTokens()")
			}

			// a second callback after the login completed is rejected
			if res := callback(h); res.Code != http.StatusBadRequest {
				t.Errorf("late callback status = %d, want %d", res.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestOidcHandler_GetTokensContext_NoCallback(t *testing.T) {
	t.Run("login timeout", func(t *testing.T) {
		idp := newFakeIdP(t)
		h := newHandler(t, idp, WithLoginTimeout(50*time.Millisecond))
		stubOpenURL(t, func(string) error { return nil })

		_, err := h.GetTokensContext(context.Background())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("GetTokensContext() error = %v, want %v", err, context.DeadlineExceeded)
		}
		if h.loginPending() {
			t.Errorf("login still pending after timeout")
		}
	})

	t.Run("context cancelled", func(t *testing.T) {
		idp := newFakeIdP(t)
		h := newHandler(t, idp)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stubOpenURL(t, func(string) error {
			cancel()
			return nil
		})

		_, err := h.GetTokensContext(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("GetTokensContext() error = %v, want %v", err, context.Canceled)
		}
		if h.loginPending() {
			t.Errorf("login still pending after cancel")
		}
	})

	t.Run("port already in use", func(t *testing.T) {
		idp := newFakeIdP(t)
		h := newHandler(t, idp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("could not listen: %v", err)
		}
		defer ln.Close()
		h.listenAddr = ln.Addr().String()

		stubOpenURL(t, func(string) error {
			t.Errorf("browser opened although the login server could not start")
			return nil
		})

		if _, err := h.GetTokensContext(context.Background()); err == nil {
			t.Errorf("GetTokensContext() error = nil, want error")
		}
		if h.loginPending() {
			t.Errorf("login still pending after listen failure")
		}
	})
}

func TestOidcHandler_GetTokensContext_CallbackFailure(t *testing.T) {
	tests := []struct {
		name       string
		browser    browser
		code       grant
		wantStatus int
	}{
		{"state mismatch", browser{badState: true}, grant{}, http.StatusBadRequest},
		{"missing session", browser{noCookies: true}, grant{}, http.StatusBadRequest},
		{"invalid authorization code", browser{badCode: true}, grant{}, http.StatusInternalServerError},
		{"token endpoint error", browser{}, grant{status: http.StatusInternalServerError}, http.StatusInternalServerError},
		{"no id token", browser{}, grant{omitIDToken: true}, http.StatusInternalServerError},
		{"id token not verified", browser{}, grant{wrongKey: true}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.code = tt.code
			idp.code.refreshToken = "refresh-1"

			// a long timeout ensures the failure ends the wait early
			h := newHandler(t, idp, WithLoginTimeout(10*time.Second))
			callbacks := stubBrowser(t, idp, tt.browser, nil)

			tokens, err := h.GetTokensContext(context.Background())
			if !errors.Is(err, ErrLoginFailed) {
				t.Fatalf("GetTokensContext() error = %v, want %v", err, ErrLoginFailed)
			}
			if tokens != nil {
				t.Errorf("GetTokensContext() tokens = %+v, want nil", tokens)
			}
			if h.refreshToken != "" {
				t.Errorf("refreshToken = %q, want empty", h.refreshToken)
			}

			if res := awaitBrowser(t, callbacks); res.Code != tt.wantStatus {
				t.Errorf("callback status = %d, want %d", res.Code, tt.wantStatus)
			}
		})
	}
}

func TestOidcHandler_Callback_NoLoginInProgress(t *testing.T) {
	idp := newFakeIdP(t)
	h := newHandler(t, idp)

	if res := callback(h); res.Code != http.StatusBadRequest {
		t.Errorf("callback status = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if idp.tokenRequests != 0 {
		t.Errorf("token endpoint called %d times, want 0", idp.tokenRequests)
	}
}

func TestOidcHandler_GetTokensContext_Refresh(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tests := []struct {
			name             string
			refreshToken     string
			wantRefreshToken string
		}{
			{"new refresh token issued", "refresh-new", "refresh-new"},
			{"refresh token unchanged", "", "refresh-old"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				idp := newFakeIdP(t)
				idp.refresh.refreshToken = tt.refreshToken
				h := newHandler(t, idp)
				h.refreshToken = "refresh-old"
				stubOpenURL(t, func(string) error {
					t.Errorf("interactive login started despite valid refresh token")
					return nil
				})

				tokens, err := h.GetTokensContext(context.Background())
				if err != nil {
					t.Fatalf("GetTokensContext() error = %v", err)
				}

				if want := idp.lastIssued(); *tokens != want {
					t.Errorf("GetTokensContext() = %+v, want %+v", *tokens, want)
				}
				if idp.gotRefreshToken != "refresh-old" {
					t.Errorf("IdP got refresh token %q, want %q", idp.gotRefreshToken, "refresh-old")
				}
				if h.refreshToken != tt.wantRefreshToken {
					t.Errorf("refreshToken = %q, want %q", h.refreshToken, tt.wantRefreshToken)
				}
			})
		}
	})

	t.Run("falls back to interactive login", func(t *testing.T) {
		tests := []struct {
			name    string
			refresh grant
		}{
			{"token endpoint error", grant{status: http.StatusBadRequest}},
			{"no id token", grant{omitIDToken: true}},
			{"id token not verified", grant{wrongKey: true}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				idp := newFakeIdP(t)
				idp.refresh = tt.refresh
				idp.code.refreshToken = "refresh-interactive"
				h := newHandler(t, idp)
				h.refreshToken = "refresh-old"
				callbacks := stubBrowser(t, idp, browser{}, nil)

				tokens, err := h.GetTokensContext(context.Background())
				if err != nil {
					t.Fatalf("GetTokensContext() error = %v", err)
				}

				awaitBrowser(t, callbacks)

				if want := idp.lastIssued(); *tokens != want {
					t.Errorf("GetTokensContext() = %+v, want %+v", *tokens, want)
				}
				if h.refreshToken != "refresh-interactive" {
					t.Errorf("refreshToken = %q, want %q", h.refreshToken, "refresh-interactive")
				}
			})
		}
	})
}

// memStore is an in-memory [tokenstore.Store]
type memStore struct {
	mu        sync.Mutex
	v         string
	setErr    error
	deleteErr error
	sets      int
	deletes   int
}

func (s *memStore) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deletes++
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.v = ""

	return nil
}

func (s *memStore) Get() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.v
}

func (s *memStore) Set(v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sets++
	if s.setErr != nil {
		return s.setErr
	}
	s.v = v

	return nil
}

func TestOidcHandler_TokenStore(t *testing.T) {
	t.Run("default store does not load a refresh token", func(t *testing.T) {
		h := newHandler(t, newFakeIdP(t))

		if h.refreshToken != "" {
			t.Errorf("refreshToken = %q, want empty", h.refreshToken)
		}
	})

	t.Run("loads persisted refresh token", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.refresh.refreshToken = "refresh-new"
		store := &memStore{v: "refresh-persisted"}
		h := newHandler(t, idp, WithTokenStore(store))
		stubOpenURL(t, func(string) error {
			t.Errorf("interactive login started despite persisted refresh token")
			return nil
		})

		if h.refreshToken != "refresh-persisted" {
			t.Fatalf("refreshToken = %q, want %q", h.refreshToken, "refresh-persisted")
		}

		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		if idp.gotRefreshToken != "refresh-persisted" {
			t.Errorf("IdP got refresh token %q, want %q", idp.gotRefreshToken, "refresh-persisted")
		}
		if got := store.Get(); got != "refresh-new" {
			t.Errorf("persisted refresh token = %q, want %q", got, "refresh-new")
		}
	})

	t.Run("persists refresh token from interactive login", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.code.refreshToken = "refresh-interactive"
		store := &memStore{}
		h := newHandler(t, idp, WithTokenStore(store))
		callbacks := stubBrowser(t, idp, browser{}, nil)

		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)

		if got := store.Get(); got != "refresh-interactive" {
			t.Errorf("persisted refresh token = %q, want %q", got, "refresh-interactive")
		}
	})

	t.Run("removes persisted refresh token when refresh fails", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.refresh.status = http.StatusBadRequest
		store := &memStore{v: "refresh-invalid"}
		h := newHandler(t, idp, WithTokenStore(store), WithLoginTimeout(50*time.Millisecond))
		stubOpenURL(t, func(string) error { return nil })

		if _, err := h.GetTokensContext(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("GetTokensContext() error = %v, want %v", err, context.DeadlineExceeded)
		}

		if store.deletes != 1 {
			t.Errorf("Delete() called %d times, want 1", store.deletes)
		}
		if got := store.Get(); got != "" {
			t.Errorf("persisted refresh token = %q, want empty", got)
		}
	})

	t.Run("store errors do not fail GetTokensContext", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.refresh.status = http.StatusBadRequest
		idp.code.refreshToken = "refresh-interactive"
		store := &memStore{
			v:         "refresh-invalid",
			setErr:    errors.New("set failed"),
			deleteErr: errors.New("delete failed"),
		}
		h := newHandler(t, idp, WithTokenStore(store))
		callbacks := stubBrowser(t, idp, browser{}, nil)

		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)

		if store.deletes != 1 || store.sets != 1 {
			t.Errorf("Delete() called %d times and Set() called %d times, want 1 each", store.deletes, store.sets)
		}
		if h.refreshToken != "refresh-interactive" {
			t.Errorf("refreshToken = %q, want %q", h.refreshToken, "refresh-interactive")
		}
	})
}

func TestOidcHandler_GetTokensContext_Cache(t *testing.T) {
	// failBrowser fails the test if an interactive login is started
	failBrowser := func(t *testing.T) {
		stubOpenURL(t, func(string) error {
			t.Errorf("interactive login started despite cached tokens")
			return nil
		})
	}

	t.Run("tokens reused until near expiry", func(t *testing.T) {
		idp := newFakeIdP(t)
		h := newHandler(t, idp)
		callbacks := stubBrowser(t, idp, browser{}, nil)

		first, err := h.GetTokensContext(context.Background())
		if err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)
		requests := idp.tokenRequests

		failBrowser(t)
		for range 3 {
			got, err := h.GetTokensContext(context.Background())
			if err != nil {
				t.Fatalf("GetTokensContext() error = %v", err)
			}
			if *got != *first {
				t.Errorf("GetTokensContext() = %+v, want cached %+v", *got, *first)
			}
		}
		if idp.tokenRequests != requests {
			t.Errorf("IdP received %d token requests, want %d", idp.tokenRequests, requests)
		}
	})

	t.Run("returned tokens are copies", func(t *testing.T) {
		idp := newFakeIdP(t)
		h := newHandler(t, idp)
		callbacks := stubBrowser(t, idp, browser{}, nil)

		first, err := h.GetTokensContext(context.Background())
		if err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)
		want := *first
		first.Access = "changed"

		failBrowser(t)
		got, err := h.GetTokensContext(context.Background())
		if err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		if *got != want {
			t.Errorf("GetTokensContext() = %+v, want %+v", *got, want)
		}
	})

	t.Run("refreshed when about to expire", func(t *testing.T) {
		idp := newFakeIdP(t)
		// tokens expiring within tokenExpiryMargin are not reused
		idp.code.expiresIn = int(tokenExpiryMargin.Seconds()) / 2
		idp.code.refreshToken = "refresh-1"
		h := newHandler(t, idp)
		callbacks := stubBrowser(t, idp, browser{}, nil)

		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)

		failBrowser(t)
		got, err := h.GetTokensContext(context.Background())
		if err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		if idp.gotRefreshToken != "refresh-1" {
			t.Errorf("IdP got refresh token %q, want %q", idp.gotRefreshToken, "refresh-1")
		}
		if want := idp.lastIssued(); *got != want {
			t.Errorf("GetTokensContext() = %+v, want refreshed %+v", *got, want)
		}

		// refreshed tokens are cached too
		requests := idp.tokenRequests
		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		if idp.tokenRequests != requests {
			t.Errorf("IdP received %d token requests, want %d", idp.tokenRequests, requests)
		}
	})

	t.Run("interactive login when about to expire without refresh token", func(t *testing.T) {
		idp := newFakeIdP(t)
		idp.code.expiresIn = int(tokenExpiryMargin.Seconds()) / 2
		h := newHandler(t, idp)
		callbacks := stubBrowser(t, idp, browser{}, nil)

		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)

		callbacks = stubBrowser(t, idp, browser{}, nil)
		if _, err := h.GetTokensContext(context.Background()); err != nil {
			t.Fatalf("GetTokensContext() error = %v", err)
		}
		awaitBrowser(t, callbacks)
	})

	t.Run("failed login is not cached", func(t *testing.T) {
		idp := newFakeIdP(t)
		h := newHandler(t, idp)
		callbacks := stubBrowser(t, idp, browser{badState: true}, nil)

		if _, err := h.GetTokensContext(context.Background()); !errors.Is(err, ErrLoginFailed) {
			t.Fatalf("GetTokensContext() error = %v, want %v", err, ErrLoginFailed)
		}
		awaitBrowser(t, callbacks)

		if h.tokens != nil {
			t.Errorf("tokens cached after failed login")
		}
	})
}
