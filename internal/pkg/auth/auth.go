package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/andrewheberle/opener"
	"github.com/andrewheberle/ssh-ca-client/internal/pkg/auth/tokenstore"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

// Handler provides the tokens needed to request a certificate. Any
// interactive login, including running the local HTTP server it needs, is
// handled by the implementation.
type Handler interface {
	GetTokens() (*Tokens, error)
	GetTokensContext(ctx context.Context) (*Tokens, error)
}

type Tokens struct {
	Access   string
	Identity string
}

var ErrLoginFailed = errors.New("interactive login failed")

const (
	// DefaultLoginTimeout is how long GetTokensContext waits for the interactive
	// login flow to complete
	DefaultLoginTimeout = time.Minute * 5

	// tokenExpiryMargin is how long before expiry cached tokens stop being
	// reused, so tokens do not expire while a request is being made
	tokenExpiryMargin = time.Minute

	// serverTimeout is the read and write timeout of the login HTTP server.
	// This allows for the token exchange with the IdP during the callback.
	serverTimeout = time.Second * 30

	// serverShutdownTimeout is how long in-flight requests to the login HTTP
	// server, such as the callback response, have to complete
	serverShutdownTimeout = time.Second * 5
)

// openURL opens the login URL in the user's browser. This is a variable so
// it can be replaced in tests.
var openURL = opener.OpenUrl

// loginResult is passed from Callback to a waiting GetTokensContext
type loginResult struct {
	tokens       *Tokens
	expiry       time.Time
	refreshToken string
	err          error
}

type OidcHandler struct {
	// options
	logger       *slog.Logger
	loginTimeout time.Duration
	tokenstore   tokenstore.Store

	// internal state
	mu           sync.Mutex
	oauth2Config oauth2.Config
	store        *sessions.CookieStore
	verifier     *oidc.IDTokenVerifier
	refreshToken string
	callbackPath string
	loginPath    string
	listenAddr   string

	// tokens are reused until shortly before tokensExpiry
	tokens       *Tokens
	tokensExpiry time.Time

	// pending is non-nil only while an interactive login is in progress. It
	// is guarded by flowMu rather than mu as GetTokensContext holds mu while
	// waiting for Callback.
	flowMu  sync.Mutex
	pending chan loginResult
}

type OidcConfig struct {
	ClientID    string
	Issuer      string
	LoginPath   string
	RedirectURL string
	Scopes      []string
}

var _ Handler = &OidcHandler{}

func NewOidcHandler(config OidcConfig, opts ...OidcHandlerOption) (*OidcHandler, error) {
	// set up oidc provider
	provider, err := oidc.NewProvider(context.Background(), config.Issuer)
	if err != nil {
		return nil, err
	}

	// default the login path to be /auth/login
	if config.LoginPath == "" {
		config.LoginPath = "/auth/login"
	}

	// parse the redirect URL and set loginPath
	u, err := url.Parse(config.RedirectURL)
	if err != nil {
		return nil, err
	}

	// the login HTTP server listens on the address the IdP redirects to
	listenAddr, err := listenAddress(u)
	if err != nil {
		return nil, err
	}

	// set defaults
	h := &OidcHandler{
		callbackPath: u.Path,
		listenAddr:   listenAddr,
		logger:       slog.New(slog.DiscardHandler),
		loginPath:    config.LoginPath,
		loginTimeout: DefaultLoginTimeout,
		oauth2Config: oauth2.Config{
			ClientID:    config.ClientID,
			RedirectURL: config.RedirectURL,
			Endpoint:    provider.Endpoint(),
			Scopes:      config.Scopes,
		},
		store:      sessions.NewCookieStore(securecookie.GenerateRandomKey(32)),
		tokenstore: new(tokenstore.DiscardStore),
		verifier:   provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
	}

	// set from options
	for _, o := range opts {
		o(h)
	}

	// load any persisted refresh token
	h.refreshToken = h.tokenstore.Get()

	return h, nil
}

// The Login method is intended for use as the handler function for
// the initial login URL of the OIDC auth flow process.
//
// This will start the OIDC auth flow process and redirect the user to
// the configured OIDC IdP.
func (h *OidcHandler) Login(w http.ResponseWriter, r *http.Request) {
	// store codeVerifier in session
	codeVerifier, codeChallenge := generatePKCE()
	session, _ := h.store.Get(r, "auth-session")
	session.Values["code_verifier"] = codeVerifier

	// generate random state string and add to session
	b := make([]byte, 128)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "Could not generate random bytes", http.StatusInternalServerError)
		h.logger.Error("Could not generate random bytes", "error", err)
		return
	}
	state := base64.URLEncoding.EncodeToString(b)
	session.Values["state"] = state

	// save to session
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Could not save session state", http.StatusInternalServerError)
		h.logger.Error("Could not save session state", "error", err)
		return
	}

	// generate redirect url for auth flow
	authCodeURL := h.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// redirect to start auth flow
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

// The Callback method is intended for use as the handler function for
// the callback URL of the OIDC auth flow process as part of the Serverless
// SSH CA
//
// The result of the callback, whether successful or not, is passed to the
// waiting GetTokensContext call. Callbacks received when no interactive
// login is in progress are rejected.
func (h *OidcHandler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")

	// only accept a callback while a login is waiting for one
	if !h.loginPending() {
		http.Error(w, "No login in progress", http.StatusBadRequest)
		h.logger.Error("No login in progress")
		return
	}

	// load session state
	session, _ := h.store.Get(r, "auth-session")

	// get state value
	expectedState, ok := session.Values["state"].(string)
	if !ok {
		h.callbackError(w, "Missing state in session", http.StatusBadRequest, nil)
		return
	}

	// verify state
	if expectedState != r.FormValue("state") {
		h.callbackError(w, "State mismatch", http.StatusBadRequest, nil)
		return
	}

	// retrieve codeVerifier from session
	codeVerifier, ok := session.Values["code_verifier"].(string)
	if !ok {
		h.callbackError(w, "Missing code_verifier in session", http.StatusBadRequest, nil)
		return
	}

	// handle token exchange
	token, err := h.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		h.callbackError(w, "Token exchange failed", http.StatusInternalServerError, err)
		return
	}

	rawIDToken, expiry, err := h.verifyToken(ctx, token)
	if err != nil {
		h.callbackError(w, "Failed to verify ID Token", http.StatusInternalServerError, err)
		return
	}

	// pass tokens to the waiting GetTokensContext
	h.deliver(loginResult{
		tokens:       &Tokens{Access: token.AccessToken, Identity: rawIDToken},
		expiry:       expiry,
		refreshToken: token.RefreshToken,
	})

	// Signal complete
	_, _ = w.Write([]byte("You may now close this window"))
	h.logger.Info("completed auth flow")
}

// HttpHandler returns the [http.Handler] for the login and callback paths.
// GetTokensContext serves this itself when an interactive login is needed.
func (h *OidcHandler) HttpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(h.callbackPath, h.Callback)
	mux.HandleFunc(h.loginPath, h.Login)

	return mux
}

// callbackError writes an error response for a failed callback, logs it and
// passes the error to the waiting GetTokensContext so it returns immediately
func (h *OidcHandler) callbackError(w http.ResponseWriter, msg string, code int, err error) {
	http.Error(w, msg, code)

	if err != nil {
		h.logger.Error(msg, "error", err)
		h.deliver(loginResult{err: fmt.Errorf("%w: %s: %w", ErrLoginFailed, msg, err)})
		return
	}

	h.logger.Error(msg)
	h.deliver(loginResult{err: fmt.Errorf("%w: %s", ErrLoginFailed, msg)})
}

// loginPending reports whether an interactive login is waiting for a callback
func (h *OidcHandler) loginPending() bool {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	return h.pending != nil
}

// deliver passes res to the waiting GetTokensContext. Only the first result
// is delivered and it is dropped if no login is in progress.
func (h *OidcHandler) deliver(res loginResult) {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	if h.pending == nil {
		return
	}

	select {
	case h.pending <- res:
	default:
	}
}

// verifyToken extracts the ID token from token and verifies it. The returned
// expiry is the earlier of the access token and ID token expiry.
func (h *OidcHandler) verifyToken(ctx context.Context, token *oauth2.Token) (string, time.Time, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", time.Time{}, fmt.Errorf("no id_token found")
	}

	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", time.Time{}, err
	}

	expiry := idToken.Expiry
	if !token.Expiry.IsZero() && token.Expiry.Before(expiry) {
		expiry = token.Expiry
	}

	return rawIDToken, expiry, nil
}

func (h *OidcHandler) GetTokens() (*Tokens, error) {
	return h.GetTokensContext(context.Background())
}

// GetTokensContext returns access and ID tokens. Previously obtained tokens
// are reused until shortly before they expire, then a refresh token is used if
// one is available. Otherwise the interactive login flow is started: a local
// HTTP server is run on the redirect URL address and this blocks until the
// Callback completes, the login timeout is reached or ctx is done.
func (h *OidcHandler) GetTokensContext(ctx context.Context) (*Tokens, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// reuse tokens that are not about to expire
	if h.tokens != nil && time.Until(h.tokensExpiry) > tokenExpiryMargin {
		tokens := *h.tokens
		return &tokens, nil
	}
	h.tokens = nil

	// check for a refresh token
	if h.refreshToken != "" {
		tokens, expiry, refreshToken, err := h.refresh(ctx)
		if err == nil {
			h.setRefreshToken(refreshToken)
			h.setTokens(tokens, expiry)

			return tokens, nil
		}

		// had an error so wipe the refresh token
		h.logger.Warn("could not refresh tokens", "error", err)
		h.setRefreshToken("")
	}

	// No refresh token or we had an error so trigger the interactive sign-in
	// process.
	res, err := h.interactiveLogin(ctx)
	if err != nil {
		return nil, err
	}

	h.setRefreshToken(res.refreshToken)
	h.setTokens(res.tokens, res.expiry)

	return res.tokens, nil
}

// interactiveLogin runs the login HTTP server, opens the user's browser at the
// login URL and waits for the result of the Callback. The server is stopped
// before returning. The caller must hold mu.
func (h *OidcHandler) interactiveLogin(ctx context.Context) (loginResult, error) {
	// listen before opening the browser so the callback endpoint is ready and
	// bind errors are returned immediately
	ln, err := net.Listen("tcp", h.listenAddr)
	if err != nil {
		return loginResult{}, fmt.Errorf("could not listen on %s: %w", h.listenAddr, err)
	}

	// register for the callback result before serving so a fast callback is
	// not missed
	ch := make(chan loginResult, 1)
	h.flowMu.Lock()
	h.pending = ch
	h.flowMu.Unlock()

	defer func() {
		h.flowMu.Lock()
		h.pending = nil
		h.flowMu.Unlock()
	}()

	srv := &http.Server{
		Handler:      h.HttpHandler(),
		ReadTimeout:  serverTimeout,
		WriteTimeout: serverTimeout,
	}

	serveErr := make(chan error, 1)
	go func() {
		defer close(serveErr)

		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	// stop the server, allowing in-flight requests (such as the callback
	// response to the browser) to complete
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), serverShutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			h.logger.Warn("could not cleanly shut down login server", "error", err)
		}
		<-serveErr
	}()

	// the login URL uses the redirect URL host so the session cookie set by
	// Login is sent with the callback, with the port actually listened on
	u, _ := url.Parse(h.oauth2Config.RedirectURL)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	loginURL := (&url.URL{Scheme: "http", Host: net.JoinHostPort(u.Hostname(), port), Path: h.loginPath}).String()

	h.logger.Info("starting interactive login flow", "url", loginURL)

	if err := openURL(loginURL); err != nil {
		h.logger.Error("could not open browser, please visit URL manually", "url", loginURL)
	}

	ctx, cancel := context.WithTimeout(ctx, h.loginTimeout)
	defer cancel()

	select {
	case res := <-ch:
		if res.err != nil {
			return loginResult{}, res.err
		}

		return res, nil
	case err := <-serveErr:
		return loginResult{}, fmt.Errorf("login server failed: %w", err)
	case <-ctx.Done():
		return loginResult{}, fmt.Errorf("interactive login did not complete: %w", ctx.Err())
	}
}

// setTokens caches tokens until expiry. The caller must hold mu.
func (h *OidcHandler) setTokens(tokens *Tokens, expiry time.Time) {
	cached := *tokens
	h.tokens = &cached
	h.tokensExpiry = expiry
}

// refresh obtains new tokens using the current refresh token. The returned
// refresh token is the one to use next time, which may be unchanged.
func (h *OidcHandler) refresh(ctx context.Context) (*Tokens, time.Time, string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	tokenSource := h.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: h.refreshToken,
	})

	// try to obtain a new auth token
	token, err := tokenSource.Token()
	if err != nil {
		return nil, time.Time{}, "", err
	}

	rawIDToken, expiry, err := h.verifyToken(ctx, token)
	if err != nil {
		return nil, time.Time{}, "", err
	}

	return &Tokens{Access: token.AccessToken, Identity: rawIDToken}, expiry, token.RefreshToken, nil
}

// setRefreshToken stores the refresh token and persists it to the token
// store. An empty refreshToken removes any persisted refresh token so an
// invalid one is not loaded again. The caller must hold mu.
func (h *OidcHandler) setRefreshToken(refreshToken string) {
	h.refreshToken = refreshToken

	if refreshToken == "" {
		if err := h.tokenstore.Delete(); err != nil {
			h.logger.Warn("persisted refresh token could not be removed", "error", err)
		}
		return
	}

	if err := h.tokenstore.Set(refreshToken); err != nil {
		h.logger.Warn("refresh token could not be persisted at this time", "error", err)
	}
}

// listenAddress returns the host:port for the login HTTP server to listen on,
// based on the redirect URL. The server only supports plain HTTP so the
// redirect URL must use the http scheme. If it has no port, port 80 is used.
func listenAddress(redirectURL *url.URL) (string, error) {
	if redirectURL.Scheme != "http" {
		return "", fmt.Errorf("redirect URL %q must use the http scheme", redirectURL)
	}

	if redirectURL.Hostname() == "" {
		return "", fmt.Errorf("redirect URL %q has no host", redirectURL)
	}

	port := redirectURL.Port()
	if port == "" {
		port = "80"
	}

	return net.JoinHostPort(redirectURL.Hostname(), port), nil
}

func generatePKCE() (string, string) {
	b := make([]byte, 90)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	codeVerifier := base64.URLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return codeVerifier, codeChallenge
}

type OidcHandlerOption func(*OidcHandler)

// WithLoginTimeout sets how long GetTokensContext waits for the interactive
// login flow to complete. The default is [DefaultLoginTimeout].
func WithLoginTimeout(d time.Duration) OidcHandlerOption {
	return func(h *OidcHandler) {
		h.loginTimeout = d
	}
}

// WithTokenStore sets the store used to persist the refresh token between
// runs. The default is a [tokenstore.DiscardStore], which does not persist
// the refresh token.
func WithTokenStore(store tokenstore.Store) OidcHandlerOption {
	return func(h *OidcHandler) {
		h.tokenstore = store
	}
}
