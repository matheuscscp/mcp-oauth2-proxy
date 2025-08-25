package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

// mockProvider implements the provider interface for testing
type mockProvider struct {
	scopes                            []string
	verifyBearerTokenError            error
	oauth2ConfigFunc                  func(r *http.Request) *oauth2.Config
	verifyAndRepackExchangedTokensRes any
	verifyAndRepackExchangedTokensErr error
}

func (m *mockProvider) supportedScopes() []string {
	return m.scopes
}

func (m *mockProvider) oauth2Config(r *http.Request) *oauth2.Config {
	if m.oauth2ConfigFunc != nil {
		return m.oauth2ConfigFunc(r)
	}
	return &oauth2.Config{
		ClientID:    "test-client-id",
		RedirectURL: callbackURL(r),
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://example.com/auth",
			TokenURL: "https://example.com/token",
		},
	}
}

func (m *mockProvider) verifyBearerToken(ctx context.Context, bearerToken string) error {
	return m.verifyBearerTokenError
}

func (m *mockProvider) verifyAndRepackExchangedTokens(ctx context.Context, token *oauth2.Token) (any, error) {
	return m.verifyAndRepackExchangedTokensRes, m.verifyAndRepackExchangedTokensErr
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
		name             string
		bearerToken      string
		verifyTokenError error
		expectedStatus   int
		expectedWWWAuth  bool
	}{
		{
			name:            "missing bearer token",
			bearerToken:     "",
			expectedStatus:  http.StatusUnauthorized,
			expectedWWWAuth: true,
		},
		{
			name:             "invalid bearer token",
			bearerToken:      "invalid-token",
			verifyTokenError: errors.New("invalid token"),
			expectedStatus:   http.StatusUnauthorized,
			expectedWWWAuth:  true,
		},
		{
			name:           "valid bearer token",
			bearerToken:    "valid-token",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			mockProv := &mockProvider{
				verifyBearerTokenError: tt.verifyTokenError,
			}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, &conf.Proxy, sessionStore)

			req := httptest.NewRequest(http.MethodGet, pathAuthenticate, nil)
			if tt.bearerToken != "" {
				req.Header.Set("Authorization", "Bearer "+tt.bearerToken)
			}
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))
			if tt.expectedWWWAuth {
				g.Expect(rec.Header().Get("WWW-Authenticate")).To(ContainSubstring("Bearer realm="))
			}
		})
	}
}

func TestOAuthProtectedResource(t *testing.T) {
	g := NewWithT(t)

	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(mockProv, &conf.Proxy, sessionStore)

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

	mockProv := &mockProvider{
		scopes: []string{"openid", "profile"},
	}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(mockProv, &conf.Proxy, sessionStore)

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
	g.Expect(response["scopes_supported"]).To(Equal([]any{"openid", "profile"}))
	g.Expect(response["code_challenge_methods_supported"]).To(Equal([]any{authorizationServerCodeChallengeMethod}))
	g.Expect(response["grant_types_supported"]).To(Equal([]any{authorizationServerGrantType}))
	g.Expect(response["response_modes_supported"]).To(Equal([]any{authorizationServerResponseMode}))
	g.Expect(response["response_types_supported"]).To(Equal([]any{authorizationServerResponseType}))
	g.Expect(response["token_endpoint_auth_methods_supported"]).To(Equal([]any{authorizationServerTokenEndpointAuthMethod}))
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name               string
		requestBody        string
		expectedStatus     int
		checkResponse      bool
		config             *config
		expectRedirectURIs bool
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
			name:               "valid registration with redirect URIs",
			requestBody:        `{"redirect_uris": ["https://example.com/callback"], "client_name": "test-client"}`,
			expectedStatus:     http.StatusCreated,
			checkResponse:      true,
			expectRedirectURIs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			mockProv := &mockProvider{}
			conf := setupConfig(g, tt.config)
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, &conf.Proxy, sessionStore)

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
					g.Expect(response["redirect_uris"]).To(Equal([]any{"https://example.com/callback"}))
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

			mockProv := &mockProvider{}
			conf := setupConfig(g, tt.config)
			sessionStore := tt.sessionStore
			if sessionStore == nil {
				sessionStore = newMemorySessionStore()
			}

			api := newAPI(mockProv, &conf.Proxy, sessionStore)

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
				verifyAndRepackExchangedTokensRes: tt.tokens,
				verifyAndRepackExchangedTokensErr: tt.verifyError,
			}

			// Mock the Exchange method by overriding oauth2ConfigFunc
			if tt.exchangeError != nil {
				// Use httptest server for token exchange failure
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "exchange failed", http.StatusBadRequest)
				}))
				defer server.Close()

				mockProv.oauth2ConfigFunc = func(r *http.Request) *oauth2.Config {
					return &oauth2.Config{
						ClientID:    "test-client-id",
						RedirectURL: callbackURL(r),
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

				mockProv.oauth2ConfigFunc = func(r *http.Request) *oauth2.Config {
					return &oauth2.Config{
						ClientID:    "test-client-id",
						RedirectURL: callbackURL(r),
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

			api := newAPI(mockProv, &conf.Proxy, sessionStore)

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
					api = newAPI(mockProv, &conf.Proxy, sessionStore)
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

			mockProv := &mockProvider{}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, &conf.Proxy, sessionStore)

			var authzCode string
			if tt.setupSession {
				tx := newTestTransaction()
				tokens := map[string]string{"access_token": "test-token"}
				s := &session{tx: tx, tokens: tokens}
				var err error
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
				g.Expect(response["access_token"]).To(Equal("test-token"))
			}
		})
	}
}
