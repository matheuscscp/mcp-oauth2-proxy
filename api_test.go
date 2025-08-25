package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

// mockProvider implements the provider interface for testing
type mockProvider struct {
	oauth2ConfigFunc func() *oauth2.Config
	verifyUserResult string
	verifyUserError  error
}

func (m *mockProvider) oauth2Config() *oauth2.Config {
	if m.oauth2ConfigFunc != nil {
		return m.oauth2ConfigFunc()
	}
	return &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/auth",
			TokenURL: "https://example.com/token",
		},
	}
}

func (m *mockProvider) verifyUser(ctx context.Context, ts oauth2.TokenSource) (string, error) {
	if m.verifyUserError != nil {
		return "", m.verifyUserError
	}
	if m.verifyUserResult != "" {
		return m.verifyUserResult, nil
	}
	return "test-user@example.com", nil
}

// mockSessionStore allows simulating sessionStore failures
type mockSessionStore struct {
	sessionStore
	storeError            error
	storeTransactionError error
	retrieveError         bool
}

func (m *mockSessionStore) store(s *session) (string, error) {
	if m.storeError != nil {
		return "", m.storeError
	}
	return m.sessionStore.store(s)
}

func (m *mockSessionStore) storeTransaction(tx *transaction) (string, error) {
	if m.storeTransactionError != nil {
		return "", m.storeTransactionError
	}
	return m.sessionStore.storeTransaction(tx)
}

func (m *mockSessionStore) retrieve(key string) (*session, bool) {
	if m.retrieveError {
		return nil, false
	}
	return m.sessionStore.retrieve(key)
}

func (m *mockSessionStore) retrieveTransaction(key string) (*transaction, bool) {
	if m.retrieveError {
		return nil, false
	}
	return m.sessionStore.retrieveTransaction(key)
}

func newTestConfig() *config {
	return &config{
		Provider: providerConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
		Server: serverConfig{
			Addr: "localhost:8080",
		},
	}
}

func compileRegexList(in []string, out *[]*regexp.Regexp) error {
	for _, s := range in {
		r, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("failed to compile regex '%s': %w", s, err)
		}
		*out = append(*out, r)
	}
	return nil
}

func setupConfig(g *WithT, conf *config) *config {
	if conf == nil {
		return newTestConfig()
	}
	if err := compileRegexList(conf.Proxy.AllowedRedirectURLs, &conf.Proxy.regexAllowedRedirectURLs); err != nil {
		g.Expect(err).ToNot(HaveOccurred())
	}
	return conf
}

func parseJSONResponse(g *WithT, body []byte) map[string]any {
	var response map[string]any
	err := json.Unmarshal(body, &response)
	g.Expect(err).ToNot(HaveOccurred())
	return response
}

func newTestTransaction() *transaction {
	return &transaction{
		clientParams: transactionClientParams{
			codeChallenge: pkceS256Challenge("test-verifier"),
			redirectURL:   "https://example.com/callback",
			state:         "test-state",
		},
		codeVerifier: "test-verifier",
	}
}

// mockPrivateKeySource implements the privateKeySource interface for testing
type mockPrivateKeySource struct {
	currentError  error
	privateKey    jwk.Key
	publicKeyList []jwk.Key
}

func (m *mockPrivateKeySource) current(now time.Time) (jwk.Key, error) {
	if m.currentError != nil {
		return nil, m.currentError
	}
	if m.privateKey != nil {
		return m.privateKey, nil
	}
	// Generate a test key if none provided
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	key, _ := jwk.Import(priv)
	return key, nil
}

func (m *mockPrivateKeySource) publicKeys(now time.Time) []jwk.Key {
	return m.publicKeyList
}

func newTestTokenIssuer(keySource privateKeySource) *tokenIssuer {
	if keySource == nil {
		// Create a working test key source with the same key for signing and verifying
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		privateKey, _ := jwk.Import(priv)
		publicKey, _ := privateKey.PublicKey()
		keySource = &mockPrivateKeySource{
			privateKey:    privateKey,
			publicKeyList: []jwk.Key{publicKey},
		}
	}
	return &tokenIssuer{keySource}
}

// newTestTokenIssuerWithSharedKeys creates a token issuer that uses the same keys for all tests
func newTestTokenIssuerWithSharedKeys() (*tokenIssuer, jwk.Key, jwk.Key) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey, _ := jwk.Import(priv)
	publicKey, _ := privateKey.PublicKey()
	keySource := &mockPrivateKeySource{
		privateKey:    privateKey,
		publicKeyList: []jwk.Key{publicKey},
	}
	return &tokenIssuer{keySource}, privateKey, publicKey
}

func fixedTimeFunc() func() time.Time {
	fixedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return fixedTime }
}

// parseJWT parses and validates a JWT token using the given public key
func parseJWT(g *WithT, tokenString string, publicKey jwk.Key) jwt.Token {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(issuerAlgorithm(), publicKey), jwt.WithValidate(true))
	g.Expect(err).ToNot(HaveOccurred())
	return token
}

// assertJWTClaims verifies standard JWT claims
func assertJWTClaims(g *WithT, token jwt.Token, expectedIssuer, expectedSubject, expectedAudience string) {
	issuer, ok := token.Issuer()
	g.Expect(ok).To(BeTrue())
	g.Expect(issuer).To(Equal(expectedIssuer))

	subject, ok := token.Subject()
	g.Expect(ok).To(BeTrue())
	g.Expect(subject).To(Equal(expectedSubject))

	audiences, ok := token.Audience()
	g.Expect(ok).To(BeTrue())
	g.Expect(audiences).To(HaveLen(1))
	g.Expect(audiences[0]).To(Equal(expectedAudience))

	exp, ok := token.Expiration()
	g.Expect(ok).To(BeTrue())
	g.Expect(exp).To(BeTemporally(">=", time.Now()))

	nbf, ok := token.NotBefore()
	g.Expect(ok).To(BeTrue())
	g.Expect(nbf).To(BeTemporally("<=", time.Now().Add(time.Minute)))

	iat, ok := token.IssuedAt()
	g.Expect(ok).To(BeTrue())
	g.Expect(iat).To(BeTemporally("<=", time.Now().Add(time.Minute)))

	jti, ok := token.JwtID()
	g.Expect(ok).To(BeTrue())
	g.Expect(jti).ToNot(BeEmpty())
}

func newMockTokenServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		})
	}))
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name                string
		bearerToken         string
		useValidToken       bool
		expectedStatus      int
		expectedWWWAuth     bool
		expectedAccessToken bool
	}{
		{
			name:            "missing bearer token",
			bearerToken:     "",
			expectedStatus:  http.StatusUnauthorized,
			expectedWWWAuth: true,
		},
		{
			name:            "invalid bearer token",
			bearerToken:     "invalid-token",
			expectedStatus:  http.StatusUnauthorized,
			expectedWWWAuth: true,
		},
		{
			name:                "valid bearer token",
			useValidToken:       true,
			expectedStatus:      http.StatusOK,
			expectedAccessToken: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer, _, _ := newTestTokenIssuerWithSharedKeys()
			mockProv := &mockProvider{}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

			req := httptest.NewRequest(http.MethodGet, pathAuthenticate, nil)
			bearerToken := tt.bearerToken
			if tt.useValidToken {
				// Issue a valid token for this test
				validToken, _, err := tokenIssuer.issue("https://example.com", "test-user", "mcp-oauth2-proxy", time.Now())
				g.Expect(err).ToNot(HaveOccurred())
				bearerToken = validToken
			}
			if bearerToken != "" {
				req.Header.Set("Authorization", "Bearer "+bearerToken)
			}
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))
			if tt.expectedWWWAuth {
				g.Expect(rec.Header().Get("WWW-Authenticate")).To(ContainSubstring("Bearer realm="))
			}
			if tt.expectedAccessToken {
				// Assert access token header is set
				g.Expect(rec.Header().Get(responseHeaderAccessToken)).To(Equal(bearerToken))

				// Parse and validate JWT claims - use the same tokenIssuer's public keys
				publicKeys := tokenIssuer.publicKeys(time.Now())
				g.Expect(publicKeys).To(HaveLen(1))
				token := parseJWT(g, bearerToken, publicKeys[0])

				// Assert JWT claims
				assertJWTClaims(g, token, "https://example.com", "test-user", "mcp-oauth2-proxy")
			}
		})
	}
}

func TestOAuthProtectedResource(t *testing.T) {
	g := NewWithT(t)

	tokenIssuer := newTestTokenIssuer(nil)
	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

	req := httptest.NewRequest(http.MethodGet, pathOAuthProtectedResource, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusOK))
	g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

	response := parseJSONResponse(g, rec.Body.Bytes())

	authServers, ok := response["authorization_servers"].([]any)
	g.Expect(ok).To(BeTrue())
	g.Expect(authServers).To(HaveLen(1))

	authServer := authServers[0].(map[string]any)
	g.Expect(authServer["issuer"]).To(Equal("https://example.com"))
	g.Expect(authServer["authorization_endpoint"]).To(Equal("https://example.com" + pathAuthorize))
}

func TestOAuthAuthorizationServer(t *testing.T) {
	g := NewWithT(t)

	tokenIssuer := newTestTokenIssuer(nil)
	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

	req := httptest.NewRequest(http.MethodGet, pathOAuthAuthorizationServer, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusOK))
	g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

	response := parseJSONResponse(g, rec.Body.Bytes())

	g.Expect(response["issuer"]).To(Equal("https://example.com"))
	g.Expect(response["authorization_endpoint"]).To(Equal("https://example.com" + pathAuthorize))
	g.Expect(response["token_endpoint"]).To(Equal("https://example.com" + pathToken))
	g.Expect(response["registration_endpoint"]).To(Equal("https://example.com" + pathRegister))
	g.Expect(response["code_challenge_methods_supported"]).To(Equal([]any{authorizationServerCodeChallengeMethod}))
	g.Expect(response["grant_types_supported"]).To(Equal([]any{authorizationServerGrantType}))
	g.Expect(response["response_modes_supported"]).To(Equal([]any{authorizationServerResponseMode}))
	g.Expect(response["response_types_supported"]).To(Equal([]any{authorizationServerResponseType}))
	g.Expect(response["scopes_supported"]).To(Equal([]any{authorizationServerScope}))
	g.Expect(response["token_endpoint_auth_methods_supported"]).To(Equal([]any{authorizationServerTokenEndpointAuthMethod}))
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name                 string
		requestBody          string
		expectedStatus       int
		checkResponse        bool
		config               *config
		expectRedirectURIs   bool
		expectedRedirectURIs []string
	}{
		{
			name:           "invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty redirect URI",
			requestBody:    `{"redirect_uris": [""]}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid redirect URI not in allow list",
			requestBody:    `{"redirect_uris": ["https://evil.com/callback"]}`,
			expectedStatus: http.StatusBadRequest,
			config: &config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
				},
				Server: serverConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:               "valid registration without redirect URIs",
			requestBody:        `{"client_name": "test-client"}`,
			expectedStatus:     http.StatusCreated,
			checkResponse:      true,
			expectRedirectURIs: false,
		},
		{
			name:                 "valid registration with any redirect URI when no allow list configured",
			requestBody:          `{"redirect_uris": ["https://any-domain.com/callback"], "client_name": "test-client"}`,
			expectedStatus:       http.StatusCreated,
			checkResponse:        true,
			expectRedirectURIs:   true,
			expectedRedirectURIs: []string{"https://any-domain.com/callback"},
			config: &config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{}, // Empty list should allow any URL
				},
				Server: serverConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:                 "valid registration with redirect URIs matching regex",
			requestBody:          `{"redirect_uris": ["https://example.com/callback"], "client_name": "test-client"}`,
			expectedStatus:       http.StatusCreated,
			checkResponse:        true,
			expectRedirectURIs:   true,
			expectedRedirectURIs: []string{"https://example.com/callback"},
			config: &config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{"^https://example\\.com/.*"}, // This should match
				},
				Server: serverConfig{
					Addr: "localhost:8080",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer := newTestTokenIssuer(nil)
			mockProv := &mockProvider{}
			conf := setupConfig(g, tt.config)
			sessionStore := newMemorySessionStore()

			api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

			req := httptest.NewRequest(http.MethodPost, pathRegister, strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
				response := parseJSONResponse(g, rec.Body.Bytes())

				g.Expect(response["client_id"]).To(Equal("mcp-oauth2-proxy"))
				g.Expect(response["token_endpoint_auth_method"]).To(Equal(authorizationServerTokenEndpointAuthMethod))

				if tt.expectRedirectURIs {
					if tt.expectedRedirectURIs != nil {
						expected := make([]any, len(tt.expectedRedirectURIs))
						for i, uri := range tt.expectedRedirectURIs {
							expected[i] = uri
						}
						g.Expect(response["redirect_uris"]).To(Equal(expected))
					} else {
						g.Expect(response["redirect_uris"]).To(Equal([]any{"https://example.com/callback"}))
					}
				} else {
					g.Expect(response["redirect_uris"]).To(BeNil())
				}
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		expectRedirect bool
		expectError    bool
		sessionStore   sessionStore
		pkceError      bool
		config         *config
	}{
		{
			name:           "unsupported code challenge method",
			queryParams:    "code_challenge_method=plain",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
		},
		{
			name:           "missing code_challenge_method",
			queryParams:    "redirect_uri=https://example.com/callback&state=test-state",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty code_challenge_method",
			queryParams:    "code_challenge_method=&redirect_uri=https://example.com/callback&state=test-state",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid redirect URL",
			queryParams:    fmt.Sprintf("code_challenge_method=%s&redirect_uri=https://evil.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus: http.StatusBadRequest,
			config: &config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
				},
				Server: serverConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:           "session store error",
			queryParams:    fmt.Sprintf("code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus: http.StatusInternalServerError,
			sessionStore:   &mockSessionStore{sessionStore: newMemorySessionStore(), storeTransactionError: errors.New("session store failure")},
		},
		{
			name:           "PKCE generation error",
			queryParams:    fmt.Sprintf("code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus: http.StatusInternalServerError,
			pkceError:      true,
		},
		{
			name:           "valid authorize request",
			queryParams:    fmt.Sprintf("code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus: http.StatusSeeOther,
			expectRedirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Handle PKCE error override
			if tt.pkceError {
				originalPkceVerifier := pkceVerifier
				defer func() { pkceVerifier = originalPkceVerifier }()
				pkceVerifier = func() (string, error) {
					return "", errors.New("PKCE generation failed")
				}
			}

			tokenIssuer := newTestTokenIssuer(nil)
			mockProv := &mockProvider{}
			conf := setupConfig(g, tt.config)
			sessionStore := tt.sessionStore
			if sessionStore == nil {
				sessionStore = newMemorySessionStore()
			}

			api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

			req := httptest.NewRequest(http.MethodGet, pathAuthorize+"?"+tt.queryParams, nil)
			req.Host = "example.com"
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.expectRedirect {
				location := rec.Header().Get("Location")
				g.Expect(location).To(ContainSubstring("https://example.com/auth"))
				g.Expect(rec.Header().Get("Set-Cookie")).To(ContainSubstring(stateCookieName))
			}
		})
	}
}

func TestCallback(t *testing.T) {
	tests := []struct {
		name             string
		setupSession     bool
		setCookie        bool
		queryParams      string
		tokens           any
		exchangeError    error
		verifyError      error
		expectedStatus   int
		sessionStore     sessionStore
		csrfMismatch     bool
		retrieveError    bool
		needsTokenServer bool
		issueError       bool
	}{
		{
			name:           "missing CSRF cookie",
			setupSession:   false,
			setCookie:      false,
			queryParams:    "code=auth-code&state=test-state",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "session expired",
			setupSession:   false,
			setCookie:      true,
			queryParams:    "code=auth-code&state=test-state",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "CSRF token mismatch",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=different-state",
			expectedStatus: http.StatusBadRequest,
			csrfMismatch:   true,
		},
		{
			name:           "session not found",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			expectedStatus: http.StatusBadRequest,
			retrieveError:  true,
		},
		{
			name:             "session store error in callback",
			setupSession:     true,
			setCookie:        true,
			queryParams:      "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			tokens:           map[string]string{"access_token": "token"},
			expectedStatus:   http.StatusInternalServerError,
			sessionStore:     &mockSessionStore{sessionStore: newMemorySessionStore(), storeError: errors.New("session store failure in callback")},
			needsTokenServer: true,
		},
		{
			name:           "token exchange failure",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			exchangeError:  errors.New("exchange failed"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:             "token verification failure",
			setupSession:     true,
			setCookie:        true,
			queryParams:      "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			verifyError:      errors.New("verify failed"),
			expectedStatus:   http.StatusBadRequest,
			needsTokenServer: true,
		},
		{
			name:             "token issuer failure",
			setupSession:     true,
			setCookie:        true,
			queryParams:      "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			tokens:           map[string]string{"access_token": "token"},
			expectedStatus:   http.StatusInternalServerError,
			needsTokenServer: true,
			issueError:       true,
		},
		{
			name:             "successful callback",
			setupSession:     true,
			setCookie:        true,
			queryParams:      "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			tokens:           map[string]string{"access_token": "token"},
			expectedStatus:   http.StatusSeeOther,
			needsTokenServer: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			mockProv := &mockProvider{
				verifyUserResult: "test-user@example.com",
				verifyUserError:  tt.verifyError,
			}

			// Mock the Exchange method by overriding oauth2ConfigFunc
			if tt.exchangeError != nil {
				// Use httptest server for token exchange failure
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "exchange failed", http.StatusBadRequest)
				}))
				defer server.Close()

				mockProv.oauth2ConfigFunc = func() *oauth2.Config {
					return &oauth2.Config{
						Endpoint: oauth2.Endpoint{
							AuthURL:  "https://example.com/auth",
							TokenURL: server.URL,
						},
					}
				}
			} else if tt.needsTokenServer {
				// Use httptest server for successful token exchange
				server := newMockTokenServer()
				defer server.Close()

				mockProv.oauth2ConfigFunc = func() *oauth2.Config {
					return &oauth2.Config{
						Endpoint: oauth2.Endpoint{
							AuthURL:  "https://example.com/auth",
							TokenURL: server.URL,
						},
					}
				}
			}

			conf := newTestConfig()
			sessionStore := tt.sessionStore
			if sessionStore == nil {
				sessionStore = newMemorySessionStore()
			}

			// Setup token issuer with potential error
			var keySource privateKeySource
			if tt.issueError {
				keySource = &mockPrivateKeySource{currentError: errors.New("key generation failed")}
			}
			tokenIssuer := newTestTokenIssuer(keySource)
			api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

			// For successful callback test, we need the session key to match the cookie value
			var sessionKey string
			if tt.setupSession {
				tx := newTestTransaction()
				var err error
				sessionKey, err = sessionStore.storeTransaction(tx)
				g.Expect(err).ToNot(HaveOccurred())

				// For session not found test, replace session store after setting up session
				if tt.retrieveError {
					sessionStore = &mockSessionStore{sessionStore: sessionStore, retrieveError: true}
					// Need to recreate API with updated session store
					var keySource privateKeySource
					if tt.issueError {
						keySource = &mockPrivateKeySource{currentError: errors.New("key generation failed")}
					}
					tokenIssuer = newTestTokenIssuer(keySource)
					api = newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)
				}
			} else {
				sessionKey = "invalid-state"
			}

			// Replace placeholder with actual session key for query params
			queryParams := strings.Replace(tt.queryParams, "SESSION_KEY_PLACEHOLDER", sessionKey, 1)
			req := httptest.NewRequest(http.MethodGet, pathCallback+"?"+queryParams, nil)
			req.Host = "example.com"

			if tt.setCookie {
				req.Header.Set("Cookie", fmt.Sprintf("%s=%s", stateCookieName, sessionKey))
			}

			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))
		})
	}
}

func TestCORS(t *testing.T) {
	tests := []struct {
		name                   string
		method                 string
		origin                 string
		requestHeaders         string
		expectedStatus         int
		expectedOrigin         string
		expectedVary           string
		expectedCredentials    string
		expectedMethods        string
		expectedHeaders        string
		expectNextCalled       bool
	}{
		{
			name:                "OPTIONS request with origin - preflight",
			method:              http.MethodOptions,
			origin:              "https://example.com",
			requestHeaders:      "Content-Type,Authorization",
			expectedStatus:      http.StatusNoContent,
			expectedOrigin:      "https://example.com",
			expectedVary:        "Origin",
			expectedCredentials: "true",
			expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
			expectedHeaders:     "Content-Type,Authorization",
			expectNextCalled:    false,
		},
		{
			name:                "OPTIONS request without origin - preflight",
			method:              http.MethodOptions,
			expectedStatus:      http.StatusNoContent,
			expectedCredentials: "true",
			expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
			expectNextCalled:    false,
		},
		{
			name:                "GET request with origin",
			method:              http.MethodGet,
			origin:              "https://app.example.com",
			expectedStatus:      http.StatusOK,
			expectedOrigin:      "https://app.example.com",
			expectedVary:        "Origin",
			expectedCredentials: "true",
			expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
			expectNextCalled:    true,
		},
		{
			name:                "POST request without origin",
			method:              http.MethodPost,
			expectedStatus:      http.StatusOK,
			expectedCredentials: "true",
			expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
			expectNextCalled:    true,
		},
		{
			name:                "PUT request with origin and request headers",
			method:              http.MethodPut,
			origin:              "https://localhost:3000",
			requestHeaders:      "X-Custom-Header",
			expectedStatus:      http.StatusOK,
			expectedOrigin:      "https://localhost:3000",
			expectedVary:        "Origin",
			expectedCredentials: "true",
			expectedMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
			expectedHeaders:     "X-Custom-Header",
			expectNextCalled:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			nextCalled := false
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			handler := handleCORS(nextHandler)

			req := httptest.NewRequest(tt.method, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.requestHeaders != "" {
				req.Header.Set("Access-Control-Request-Headers", tt.requestHeaders)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))
			g.Expect(nextCalled).To(Equal(tt.expectNextCalled))

			// Check CORS headers
			g.Expect(rec.Header().Get("Access-Control-Allow-Credentials")).To(Equal(tt.expectedCredentials))
			g.Expect(rec.Header().Get("Access-Control-Allow-Methods")).To(Equal(tt.expectedMethods))

			if tt.expectedOrigin != "" {
				g.Expect(rec.Header().Get("Access-Control-Allow-Origin")).To(Equal(tt.expectedOrigin))
				g.Expect(rec.Header().Get("Vary")).To(Equal(tt.expectedVary))
			} else {
				g.Expect(rec.Header().Get("Access-Control-Allow-Origin")).To(BeEmpty())
				g.Expect(rec.Header().Get("Vary")).To(BeEmpty())
			}

			if tt.expectedHeaders != "" {
				g.Expect(rec.Header().Get("Access-Control-Allow-Headers")).To(Equal(tt.expectedHeaders))
			} else {
				g.Expect(rec.Header().Get("Access-Control-Allow-Headers")).To(BeEmpty())
			}
		})
	}
}

func TestToken(t *testing.T) {
	tests := []struct {
		name           string
		setupSession   bool
		formData       string
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "invalid form data",
			formData:       "invalid%form%data",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "expired authorization code",
			setupSession:   false,
			formData:       "code=invalid-code&code_verifier=test-verifier",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "PKCE verification failure",
			setupSession:   true,
			formData:       "code=valid-code&code_verifier=wrong-verifier",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "successful token exchange",
			setupSession:   true,
			formData:       "code=valid-code&code_verifier=test-verifier",
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer, _, _ := newTestTokenIssuerWithSharedKeys()
			mockProv := &mockProvider{}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

			var authzCode string
			var jwtToken string
			if tt.setupSession {
				tx := newTestTransaction()

				// Issue a real JWT token for this test
				now := time.Now()
				var exp time.Time
				var err error
				jwtToken, exp, err = tokenIssuer.issue("https://example.com", "test-user@example.com", "mcp-oauth2-proxy", now)
				g.Expect(err).ToNot(HaveOccurred())

				// Create outcome with real JWT token
				outcome := &oauth2.Token{
					AccessToken: jwtToken,
					TokenType:   "Bearer",
					Expiry:      exp,
				}
				s := &session{tx: tx, outcome: outcome}
				authzCode, err = sessionStore.store(s)
				g.Expect(err).ToNot(HaveOccurred())

				// Replace the code in form data
				if strings.Contains(tt.formData, "code=valid-code") {
					tt.formData = strings.Replace(tt.formData, "valid-code", authzCode, 1)
				}
			}

			req := httptest.NewRequest(http.MethodPost, pathToken, strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
				response := parseJSONResponse(g, rec.Body.Bytes())

				// Assert basic OAuth2 token response structure
				g.Expect(response["access_token"]).To(Equal(jwtToken))
				g.Expect(response["token_type"]).To(Equal("Bearer"))
				g.Expect(response["expiry"]).ToNot(BeNil())

				// Parse and validate JWT claims - use the same tokenIssuer's public keys
				publicKeys := tokenIssuer.publicKeys(time.Now())
				g.Expect(publicKeys).To(HaveLen(1))
				token := parseJWT(g, jwtToken, publicKeys[0])

				// Assert JWT claims
				assertJWTClaims(g, token, "https://example.com", "test-user@example.com", "mcp-oauth2-proxy")
			}
		})
	}
}
