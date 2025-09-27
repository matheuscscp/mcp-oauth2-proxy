package main

import (
	"context"
	"crypto"
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
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

// createMockMCPServer creates a test MCP server with scopes metadata
func createMockMCPServer(scopes []scopeConfig) *httptest.Server {
	mcpServer := server.NewMCPServer("test-mcp-server", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithHooks(&server.Hooks{
			OnAfterListTools: []server.OnAfterListToolsFunc{
				func(ctx context.Context, id any, message *mcp.ListToolsRequest, result *mcp.ListToolsResult) {
					// Add scopes to the metadata
					if result.Meta == nil {
						result.Meta = &mcp.Meta{
							AdditionalFields: make(map[string]interface{}),
						}
					}
					result.Meta.AdditionalFields["scopes"] = scopes
				},
			},
		}),
	)

	// Create and return the test server
	return server.NewTestStreamableHTTPServer(mcpServer)
}

// createMockMCPServerWithBogusJSON creates a test MCP server that returns invalid JSON in metadata
func createMockMCPServerWithBogusJSON() *httptest.Server {
	mcpServer := server.NewMCPServer("test-mcp-server", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithHooks(&server.Hooks{
			OnAfterListTools: []server.OnAfterListToolsFunc{
				func(ctx context.Context, id any, message *mcp.ListToolsRequest, result *mcp.ListToolsResult) {
					// Add invalid data that will cause JSON unmarshaling to fail
					if result.Meta == nil {
						result.Meta = &mcp.Meta{
							AdditionalFields: make(map[string]interface{}),
						}
					}
					// Create a struct that will marshal to JSON but unmarshal incorrectly
					result.Meta.AdditionalFields["scopes"] = "this is not a valid scope array"
				},
			},
		}),
	)

	// Create and return the test server
	return server.NewTestStreamableHTTPServer(mcpServer)
}

// mockProvider implements the provider interface for testing
type mockProvider struct {
	oauth2ConfigFunc func() *oauth2.Config
	verifyUserResult *userInfo
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

func (m *mockProvider) verifyUser(ctx context.Context, ts oauth2.TokenSource) (*userInfo, error) {
	if m.verifyUserError != nil {
		return nil, m.verifyUserError
	}
	if m.verifyUserResult != nil {
		return m.verifyUserResult, nil
	}
	return &userInfo{username: "test-user@example.com"}, nil
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
		host:         "example.com",
	}
}

// mockPrivateKeySource implements the privateKeySource interface for testing
type mockPrivateKeySource struct {
	currentError  error
	privateKey    jwk.Key
	publicKeyList []jwk.Key
}

func (m *mockPrivateKeySource) current(now time.Time) (private jwk.Key, err error) {
	if m.currentError != nil {
		return nil, m.currentError
	}
	defer func() {
		public, _ := private.PublicKey()
		thumbprint, _ := public.Thumbprint(crypto.SHA256)
		keyID := fmt.Sprintf("%x", thumbprint)
		private.Set(jwk.KeyIDKey, keyID)
		public.Set(jwk.KeyIDKey, keyID)
	}()
	if m.privateKey != nil {
		return m.privateKey, nil
	}
	// Generate a test key if none provided
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	private, _ = jwk.Import(priv)
	return private, nil
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
				validToken, _, err := tokenIssuer.issue("https://example.com", "test-user", "https://example.com", time.Now(), nil, nil)
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
	tests := []struct {
		name           string
		config         *config
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "successful response with default scopes",
			config:         newTestConfig(),
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
		{
			name: "failed to fetch supported scopes from invalid MCP endpoint",
			config: &config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					Hosts: []*hostConfig{
						{
							Host:     "example.com",
							Endpoint: "http://invalid-endpoint-that-does-not-exist:99999",
						},
					},
				},
				Server: serverConfig{
					Addr: "localhost:8080",
				},
			},
			expectedStatus: http.StatusInternalServerError,
			checkResponse:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer := newTestTokenIssuer(nil)
			mockProv := &mockProvider{}
			sessionStore := newMemorySessionStore()

			api := newAPI(tokenIssuer, mockProv, tt.config, sessionStore, time.Now)

			req := httptest.NewRequest(http.MethodGet, pathOAuthAuthorizationServer, nil)
			req.Host = "example.com"
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
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
				g.Expect(response["scopes_supported"]).To(Equal([]any{authorizationServerDefaultScope}))
				g.Expect(response["token_endpoint_auth_methods_supported"]).To(Equal([]any{authorizationServerTokenEndpointAuthMethod}))
			}
		})
	}
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
		name                     string
		queryParams              string
		expectedStatus           int
		expectRedirect           bool
		expectError              bool
		expectedErrorMessage     string
		sessionStore             sessionStore
		pkceError                bool
		config                   *config
		expectScopeSelectionPage bool
		expectScopeTransaction   bool
		expectValidatedScopes    bool
		expectedFilteredScopes   []string
	}{
		{
			name:                 "unsupported code challenge method",
			queryParams:          "response_type=code&code_challenge_method=plain&redirect_uri=https://example.com/callback&state=test-state",
			expectedStatus:       http.StatusBadRequest,
			expectError:          true,
			expectedErrorMessage: "Invalid parameters: 'plain' is not supported for code_challenge_method, only S256 is allowed",
		},
		{
			name:                 "unsupported response type",
			queryParams:          "response_type=plain&code_challenge_method=S256&redirect_uri=https://example.com/callback&state=test-state",
			expectedStatus:       http.StatusBadRequest,
			expectError:          true,
			expectedErrorMessage: "Invalid parameters: 'plain' is not supported for response_type, only code is allowed",
		},
		{
			name:                 "missing code_challenge_method",
			queryParams:          "response_type=code&redirect_uri=https://example.com/callback&state=test-state",
			expectedStatus:       http.StatusBadRequest,
			expectedErrorMessage: "Invalid parameters: '' is not supported for code_challenge_method, only S256 is allowed",
		},
		{
			name:                 "empty code_challenge_method",
			queryParams:          "response_type=code&code_challenge_method=&redirect_uri=https://example.com/callback&state=test-state",
			expectedStatus:       http.StatusBadRequest,
			expectedErrorMessage: "Invalid parameters: '' is not supported for code_challenge_method, only S256 is allowed",
		},
		{
			name:                 "invalid redirect URL",
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://evil.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusBadRequest,
			expectedErrorMessage: "Invalid parameters: redirect_uri is not in the allow list: https://evil.com/callback",
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
			name:                 "session store error",
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusInternalServerError,
			expectedErrorMessage: "Failed to generate state",
			sessionStore:         &mockSessionStore{sessionStore: newMemorySessionStore(), storeTransactionError: errors.New("session store failure")},
		},
		{
			name:                 "PKCE generation error",
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusInternalServerError,
			expectedErrorMessage: "Failed to generate code verifier",
			pkceError:            true,
		},
		{
			name:           "valid authorize request",
			queryParams:    fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus: http.StatusSeeOther,
			expectRedirect: true,
		},
		{
			name:                 "failed to fetch supported scopes from invalid MCP endpoint",
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusInternalServerError,
			expectError:          true,
			expectedErrorMessage: "Failed to get supported scopes",
			config: &config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					Hosts: []*hostConfig{
						{
							Host:     "example.com",
							Endpoint: "http://invalid-endpoint-that-does-not-exist:99999",
						},
					},
				},
				Server: serverConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:                     "scope selection page rendered",
			queryParams:              fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus:           http.StatusOK,
			expectRedirect:           false,
			expectScopeSelectionPage: true,
			config: func() *config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]scopeConfig{
					{
						Name:        "read",
						Description: "Read access to resources",
						Tools:       []string{},
					},
					{
						Name:        "write",
						Description: "Write access to resources",
						Tools:       []string{"read"},
					},
				})
				return &config{
					Provider: providerConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: proxyConfig{
						Hosts: []*hostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
					},
					Server: serverConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
		{
			name:                   "authorize with selected scopes",
			queryParams:            fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state&scope=read%%20write&skip_scope_selection=true", authorizationServerCodeChallengeMethod),
			expectedStatus:         http.StatusSeeOther,
			expectRedirect:         true,
			expectScopeTransaction: true,
			config: func() *config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]scopeConfig{
					{
						Name:        "read",
						Description: "Read access to resources",
						Tools:       []string{},
					},
					{
						Name:        "write",
						Description: "Write access to resources",
						Tools:       []string{"read"},
					},
				})
				return &config{
					Provider: providerConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: proxyConfig{
						Hosts: []*hostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
					},
					Server: serverConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
		{
			name:                   "scope validation filters unsupported scopes",
			queryParams:            fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state&scope=read%%20invalid%%20write&skip_scope_selection=true", authorizationServerCodeChallengeMethod),
			expectedStatus:         http.StatusSeeOther,
			expectRedirect:         true,
			expectScopeTransaction: true,
			expectValidatedScopes:  true,
			expectedFilteredScopes: []string{"read", "write"},
			config: func() *config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]scopeConfig{
					{
						Name:        "read",
						Description: "Read access to resources",
						Tools:       []string{},
					},
					{
						Name:        "write",
						Description: "Write access to resources",
						Tools:       []string{"read"},
					},
				})
				return &config{
					Provider: providerConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: proxyConfig{
						Hosts: []*hostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
					},
					Server: serverConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
		{
			name:                     "consent screen disabled with DisableConsentScreen",
			queryParams:              fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", authorizationServerCodeChallengeMethod),
			expectedStatus:           http.StatusSeeOther,
			expectRedirect:           true,
			expectScopeSelectionPage: false,
			config: func() *config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]scopeConfig{
					{
						Name:        "read",
						Description: "Read access to resources",
						Tools:       []string{},
					},
					{
						Name:        "write",
						Description: "Write access to resources",
						Tools:       []string{"read"},
					},
				})
				return &config{
					Provider: providerConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: proxyConfig{
						Hosts: []*hostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
						DisableConsentScreen: true,
					},
					Server: serverConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
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

			if tt.expectedErrorMessage != "" {
				g.Expect(rec.Body.String()).To(ContainSubstring(tt.expectedErrorMessage))
			}

			if tt.expectRedirect {
				location := rec.Header().Get("Location")
				g.Expect(location).To(ContainSubstring("https://example.com/auth"))
				g.Expect(rec.Header().Get("Set-Cookie")).To(ContainSubstring(stateCookieName))
			}

			// Check for scope selection page
			if tt.expectScopeSelectionPage {
				g.Expect(rec.Header().Get("Content-Type")).To(Equal("text/html; charset=utf-8"))
				body := rec.Body.String()
				g.Expect(body).To(ContainSubstring("Select Permissions"))
				g.Expect(body).To(ContainSubstring("example.com"))
				g.Expect(body).To(ContainSubstring("read"))
				g.Expect(body).To(ContainSubstring("write"))
				g.Expect(body).To(ContainSubstring("Read access to resources"))
				g.Expect(body).To(ContainSubstring("Write access to resources"))
			} else if tt.config != nil && tt.config.Proxy.DisableConsentScreen && len(tt.config.Proxy.Hosts) > 0 {
				// When DisableConsentScreen is true and we have MCP hosts configured,
				// ensure we did NOT render the consent screen
				body := rec.Body.String()
				g.Expect(body).ToNot(ContainSubstring("Select Permissions"))
				// The response should be a redirect, not HTML content
				g.Expect(rec.Code).To(Equal(http.StatusSeeOther))
			}

			// Check for authorize with scopes transaction
			if tt.expectScopeTransaction {
				// Should redirect to OAuth provider
				location := rec.Header().Get("Location")
				g.Expect(location).To(ContainSubstring("https://example.com/auth"))
				g.Expect(rec.Header().Get("Set-Cookie")).To(ContainSubstring(stateCookieName))

				// Verify that the transaction was created and stored (this is verified by the successful redirect)
				// The actual scope verification will happen when the transaction is retrieved during callback
			}

			// Check scope validation if expected
			if tt.expectValidatedScopes {
				// Extract the state cookie to retrieve the stored transaction
				cookies := rec.Header().Values("Set-Cookie")
				var stateValue string
				for _, cookie := range cookies {
					if strings.HasPrefix(cookie, stateCookieName+"=") {
						parts := strings.Split(cookie, "=")
						if len(parts) > 1 {
							stateValue = strings.Split(parts[1], ";")[0]
							break
						}
					}
				}
				g.Expect(stateValue).ToNot(BeEmpty())

				// Retrieve the stored transaction and verify scopes were filtered
				tx, found := sessionStore.retrieveTransaction(stateValue)
				g.Expect(found).To(BeTrue())
				g.Expect(tx.clientParams.scopes).To(Equal(tt.expectedFilteredScopes))
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
		requestHost      string
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
			name:           "host mismatch",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			expectedStatus: http.StatusBadRequest,
			requestHost:    "different.com",
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
				verifyUserResult: &userInfo{username: "test-user@example.com"},
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
			if tt.requestHost != "" {
				req.Host = tt.requestHost
			} else {
				req.Host = "example.com"
			}

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
		requestHost    string
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
			name:           "host mismatch",
			setupSession:   true,
			formData:       "code=valid-code&code_verifier=test-verifier",
			expectedStatus: http.StatusBadRequest,
			requestHost:    "different.com",
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
				jwtToken, exp, err = tokenIssuer.issue("https://example.com", "test-user@example.com", "mcp-oauth2-proxy", now, nil, nil)
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
			if tt.requestHost != "" {
				req.Host = tt.requestHost
			} else {
				req.Host = "example.com"
			}
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

func TestOpenIDConfiguration(t *testing.T) {
	g := NewWithT(t)

	tokenIssuer := newTestTokenIssuer(nil)
	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

	req := httptest.NewRequest(http.MethodGet, pathOpenIDConfiguration, nil)
	req.Host = "example.com"
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusOK))
	g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

	response := parseJSONResponse(g, rec.Body.Bytes())

	g.Expect(response["issuer"]).To(Equal("https://example.com"))
	g.Expect(response["jwks_uri"]).To(Equal("https://example.com" + pathJWKS))

	signingAlgs, ok := response["id_token_signing_alg_values_supported"].([]any)
	g.Expect(ok).To(BeTrue())
	g.Expect(signingAlgs).To(HaveLen(1))
	g.Expect(signingAlgs[0]).To(Equal(issuerAlgorithm().String()))
}

func TestJWKS(t *testing.T) {
	g := NewWithT(t)

	// Create a token issuer with known keys for testing
	tokenIssuer, _, publicKey := newTestTokenIssuerWithSharedKeys()
	mockProv := &mockProvider{}
	conf := newTestConfig()
	sessionStore := newMemorySessionStore()

	api := newAPI(tokenIssuer, mockProv, conf, sessionStore, time.Now)

	req := httptest.NewRequest(http.MethodGet, pathJWKS, nil)
	rec := httptest.NewRecorder()

	api.ServeHTTP(rec, req)

	g.Expect(rec.Code).To(Equal(http.StatusOK))
	g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

	response := parseJSONResponse(g, rec.Body.Bytes())

	keys, ok := response["keys"].([]any)
	g.Expect(ok).To(BeTrue())
	g.Expect(keys).To(HaveLen(1))

	// Verify the returned key has the expected structure
	key := keys[0].(map[string]any)
	g.Expect(key["kty"]).To(Equal("RSA"))
	g.Expect(key["n"]).ToNot(BeEmpty()) // RSA modulus
	g.Expect(key["e"]).ToNot(BeEmpty()) // RSA exponent

	// Check if optional fields are present
	if alg, exists := key["alg"]; exists {
		g.Expect(alg).To(Equal(issuerAlgorithm().String()))
	}

	// Verify we can recreate the same public key from the JWK response
	keyBytes, err := json.Marshal(key)
	g.Expect(err).ToNot(HaveOccurred())

	reconstructedKey, err := jwk.ParseKey(keyBytes)
	g.Expect(err).ToNot(HaveOccurred())

	// The reconstructed key should have the same key ID as the original
	origKeyID, origExists := publicKey.KeyID()
	reconKeyID, reconExists := reconstructedKey.KeyID()
	g.Expect(reconExists).To(Equal(origExists))
	if origExists && reconExists {
		g.Expect(reconKeyID).To(Equal(origKeyID))
	}
}
