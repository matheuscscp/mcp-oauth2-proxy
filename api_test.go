package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	storeError    error
	retrieveError bool
}

func (m *mockSessionStore) store(tx url.Values, tokens any) (string, error) {
	if m.storeError != nil {
		return "", m.storeError
	}
	return m.sessionStore.store(tx, tokens)
}

func (m *mockSessionStore) retrieve(key string) (url.Values, any, bool) {
	if m.retrieveError {
		return nil, nil, false
	}
	return m.sessionStore.retrieve(key)
}

// callCountingSessionStore counts store calls and fails after a threshold
type callCountingSessionStore struct {
	sessionStore
	callCount int
	failAfter int
}

func (c *callCountingSessionStore) store(tx url.Values, tokens any) (string, error) {
	c.callCount++
	if c.callCount > c.failAfter {
		return "", errors.New("session store failure in callback")
	}
	return c.sessionStore.store(tx, tokens)
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

			api := newAPI(mockProv, conf, sessionStore)

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

	api := newAPI(mockProv, conf, sessionStore)

	req := httptest.NewRequest(http.MethodGet, pathOAuthProtectedResource, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusOK))
	g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

	var response map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	g.Expect(err).ToNot(HaveOccurred())

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

	api := newAPI(mockProv, conf, sessionStore)

	req := httptest.NewRequest(http.MethodGet, pathOAuthAuthorizationServer, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusOK))
	g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

	var response map[string]any
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(response["issuer"]).To(Equal("https://example.com"))
	g.Expect(response["authorization_endpoint"]).To(Equal("https://example.com" + pathAuthorize))
	g.Expect(response["token_endpoint"]).To(Equal("https://example.com" + pathToken))
	g.Expect(response["registration_endpoint"]).To(Equal("https://example.com" + pathRegister))
	g.Expect(response["scopes_supported"]).To(Equal([]any{"openid", "profile"}))
	g.Expect(response["token_endpoint_auth_methods_supported"]).To(Equal([]any{authorizationServerAuthMethod}))
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "invalid JSON",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing redirect_uris",
			requestBody:    `{"client_name": "test"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "valid registration",
			requestBody:    `{"redirect_uris": ["https://example.com/callback"]}`,
			expectedStatus: http.StatusCreated,
			checkResponse:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			mockProv := &mockProvider{}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, conf, sessionStore)

			req := httptest.NewRequest(http.MethodPost, pathRegister, strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
				var response map[string]any
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				g.Expect(err).ToNot(HaveOccurred())

				g.Expect(response["client_id"]).To(Equal("test-client-id"))
				g.Expect(response["token_endpoint_auth_method"]).To(Equal(authorizationServerAuthMethod))
				g.Expect(response["redirect_uris"]).To(Equal([]any{"https://example.com/callback"}))
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
	}{
		{
			name:           "unsupported code challenge method",
			queryParams:    "code_challenge_method=plain",
			expectedStatus: http.StatusBadRequest,
			expectError:    true,
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

			mockProv := &mockProvider{}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, conf, sessionStore)

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
		name           string
		setupSession   bool
		setCookie      bool
		queryParams    string
		tokens         any
		exchangeError  error
		verifyError    error
		expectedStatus int
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
			name:           "token exchange failure",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=test-state",
			exchangeError:  errors.New("exchange failed"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "token verification failure",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=test-state",
			verifyError:    errors.New("verify failed"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "successful callback",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			tokens:         map[string]string{"access_token": "token"},
			expectedStatus: http.StatusSeeOther,
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
			} else if tt.name == "successful callback" {
				// Use httptest server for successful token exchange
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{
						"access_token": "test-access-token",
						"token_type":   "Bearer",
					})
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
			}

			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, conf, sessionStore)

			// For successful callback test, we need the session key to match the cookie value
			var sessionKey string
			if tt.setupSession {
				tx := url.Values{}
				tx.Set(queryParamCodeVerifier, "test-verifier")
				tx.Set(queryParamRedirectURI, "https://example.com/callback")
				tx.Set(queryParamState, "test-state")
				var err error
				sessionKey, err = sessionStore.store(tx, nil)
				g.Expect(err).ToNot(HaveOccurred())
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

			api := newAPI(mockProv, conf, sessionStore)

			var authzCode string
			if tt.setupSession {
				tx := url.Values{}
				// Use the actual PKCE challenge calculation
				challenge := pkceS256Challenge("test-verifier")
				tx.Set(queryParamCodeChallenge, challenge)
				tokens := map[string]string{"access_token": "test-token"}
				var err error
				authzCode, err = sessionStore.store(tx, tokens)
				g.Expect(err).ToNot(HaveOccurred())

				// Replace the code in form data
				if tt.formData == "code=valid-code&code_verifier=test-verifier" {
					tt.formData = fmt.Sprintf("code=%s&code_verifier=test-verifier", authzCode)
				}
			}

			req := httptest.NewRequest(http.MethodPost, pathToken, strings.NewReader(tt.formData))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
				var response map[string]any
				err := json.Unmarshal(rec.Body.Bytes(), &response)
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(response["access_token"]).To(Equal("test-token"))
			}
		})
	}
}

func TestCallbackCSRFMismatch(t *testing.T) {
	g := NewWithT(t)

	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(mockProv, conf, sessionStore)

	// Set up session
	tx := url.Values{}
	tx.Set(queryParamCodeVerifier, "test-verifier")
	tx.Set(queryParamRedirectURI, "https://example.com/callback")
	tx.Set(queryParamState, "test-state")
	sessionKey, err := sessionStore.store(tx, nil)
	g.Expect(err).ToNot(HaveOccurred())

	// Use different state in query than in cookie
	req := httptest.NewRequest(http.MethodGet, pathCallback+"?code=auth-code&state=different-state", nil)
	req.Host = "example.com"
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", stateCookieName, sessionKey))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusBadRequest))
}

func TestAuthorizeMissingParameters(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			mockProv := &mockProvider{}
			conf := newTestConfig()
			sessionStore := newMemorySessionStore()

			api := newAPI(mockProv, conf, sessionStore)

			req := httptest.NewRequest(http.MethodGet, pathAuthorize+"?"+tt.queryParams, nil)
			req.Host = "example.com"
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))
		})
	}
}

func TestAuthorizeSessionStoreError(t *testing.T) {
	g := NewWithT(t)

	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := &mockSessionStore{
		sessionStore: newMemorySessionStore(),
		storeError:   errors.New("session store failure"),
	}

	api := newAPI(mockProv, conf, sessionStore)

	queryParams := fmt.Sprintf("code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod)
	req := httptest.NewRequest(http.MethodGet, pathAuthorize+"?"+queryParams, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusInternalServerError))
}

func TestCallbackSessionStoreError(t *testing.T) {
	g := NewWithT(t)

	// Create a session store that succeeds on first call but fails on second
	baseStore := newMemorySessionStore()
	sessionStore := &callCountingSessionStore{
		sessionStore: baseStore,
		callCount:    0,
		failAfter:    0, // Fail on first call from the counting store
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	mockProv := &mockProvider{
		oauth2ConfigFunc: func(r *http.Request) *oauth2.Config {
			return &oauth2.Config{
				ClientID:    "test-client-id",
				RedirectURL: callbackURL(r),
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://example.com/auth",
					TokenURL: server.URL,
				},
			}
		},
		verifyAndRepackExchangedTokensRes: map[string]string{"access_token": "token"},
	}

	// Set up initial session using base store directly
	tx := url.Values{}
	tx.Set(queryParamCodeVerifier, "test-verifier")
	tx.Set(queryParamRedirectURI, "https://example.com/callback")
	tx.Set(queryParamState, "test-state")
	sessionKey, err := baseStore.store(tx, nil)
	g.Expect(err).ToNot(HaveOccurred())

	conf := newTestConfig()
	api := newAPI(mockProv, conf, sessionStore)

	req := httptest.NewRequest(http.MethodGet, pathCallback+"?code=auth-code&state="+sessionKey, nil)
	req.Host = "example.com"
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", stateCookieName, sessionKey))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusInternalServerError))
}

func TestCallbackSessionExpired(t *testing.T) {
	g := NewWithT(t)

	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := &mockSessionStore{
		sessionStore:  newMemorySessionStore(),
		retrieveError: true, // Simulate session not found
	}

	api := newAPI(mockProv, conf, sessionStore)

	req := httptest.NewRequest(http.MethodGet, pathCallback+"?code=auth-code&state=non-existent-state", nil)
	req.Host = "example.com"
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", stateCookieName, "non-existent-state"))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusBadRequest))
}

func TestCallbackTokenVerificationError(t *testing.T) {
	g := NewWithT(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	mockProv := &mockProvider{
		oauth2ConfigFunc: func(r *http.Request) *oauth2.Config {
			return &oauth2.Config{
				ClientID:    "test-client-id",
				RedirectURL: callbackURL(r),
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://example.com/auth",
					TokenURL: server.URL,
				},
			}
		},
		verifyAndRepackExchangedTokensErr: errors.New("token verification failed"),
	}

	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	// Set up initial session
	tx := url.Values{}
	tx.Set(queryParamCodeVerifier, "test-verifier")
	tx.Set(queryParamRedirectURI, "https://example.com/callback")
	tx.Set(queryParamState, "test-state")
	sessionKey, err := sessionStore.store(tx, nil)
	g.Expect(err).ToNot(HaveOccurred())

	api := newAPI(mockProv, conf, sessionStore)

	req := httptest.NewRequest(http.MethodGet, pathCallback+"?code=auth-code&state="+sessionKey, nil)
	req.Host = "example.com"
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", stateCookieName, sessionKey))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusBadRequest))
}

func TestTokenPKCEVerificationFailure(t *testing.T) {
	g := NewWithT(t)

	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(mockProv, conf, sessionStore)

	// Set up session with a specific code challenge
	tx := url.Values{}
	correctVerifier := "test-verifier"
	codeChallenge := pkceS256Challenge(correctVerifier)
	tx.Set(queryParamCodeChallenge, codeChallenge)

	tokens := map[string]string{"access_token": "test-token"}
	authzCode, err := sessionStore.store(tx, tokens)
	g.Expect(err).ToNot(HaveOccurred())

	// Use wrong verifier in the token request
	wrongVerifier := "wrong-verifier"
	formData := fmt.Sprintf("code=%s&code_verifier=%s", authzCode, wrongVerifier)

	req := httptest.NewRequest(http.MethodPost, pathToken, strings.NewReader(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusBadRequest))
}

func TestCallbackTokenExchangeError(t *testing.T) {
	g := NewWithT(t)

	// Create a server that returns an error for token exchange
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token exchange failed", http.StatusBadRequest)
	}))
	defer server.Close()

	mockProv := &mockProvider{
		oauth2ConfigFunc: func(r *http.Request) *oauth2.Config {
			return &oauth2.Config{
				ClientID:    "test-client-id",
				RedirectURL: callbackURL(r),
				Endpoint: oauth2.Endpoint{
					AuthURL:  "https://example.com/auth",
					TokenURL: server.URL, // Use the failing server
				},
			}
		},
	}

	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	// Set up initial session
	tx := url.Values{}
	tx.Set(queryParamCodeVerifier, "test-verifier")
	tx.Set(queryParamRedirectURI, "https://example.com/callback")
	tx.Set(queryParamState, "test-state")
	sessionKey, err := sessionStore.store(tx, nil)
	g.Expect(err).ToNot(HaveOccurred())

	api := newAPI(mockProv, conf, sessionStore)

	req := httptest.NewRequest(http.MethodGet, pathCallback+"?code=auth-code&state="+sessionKey, nil)
	req.Host = "example.com"
	req.Header.Set("Cookie", fmt.Sprintf("%s=%s", stateCookieName, sessionKey))

	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusBadRequest))
}

func TestAuthorizePKCEGenerationError(t *testing.T) {
	g := NewWithT(t)

	// Save original function and restore after test
	originalPkceVerifier := pkceVerifier
	defer func() { pkceVerifier = originalPkceVerifier }()

	// Override pkceVerifier to return an error
	pkceVerifier = func() (string, error) {
		return "", errors.New("PKCE generation failed")
	}

	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(mockProv, conf, sessionStore)

	queryParams := fmt.Sprintf("code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod)
	req := httptest.NewRequest(http.MethodGet, pathAuthorize+"?"+queryParams, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusInternalServerError))
}
