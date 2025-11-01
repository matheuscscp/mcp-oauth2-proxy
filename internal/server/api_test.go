package server

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
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/issuer"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/provider"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/store"
)

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name                string
		bearerToken         string
		useValidToken       bool
		expectedStatus      int
		expectedWWWAuth     bool
		expectedAccessToken bool
		requestHost         string
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
		{
			name:           "host not allowed",
			bearerToken:    "some-token",
			expectedStatus: http.StatusMisdirectedRequest,
			requestHost:    "not-allowed.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer, _, _ := newTestTokenIssuerWithSharedKeys()
			mockProv := &mockProvider{}
			conf := newTestConfig()
			st := store.NewMemoryStore()

			api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

			req := httptest.NewRequest(http.MethodGet, pathAuthenticate, nil)
			if tt.requestHost != "" {
				req.Host = tt.requestHost
			}
			bearerToken := tt.bearerToken
			if tt.useValidToken {
				// Issue a valid token for this test
				validToken, _, err := tokenIssuer.Issue("https://example.com", "test-user", "https://example.com", time.Now(), nil, nil)
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
	tests := []struct {
		name           string
		requestHost    string
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "successful response",
			requestHost:    "example.com",
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
		{
			name:           "host not allowed",
			requestHost:    "not-allowed.com",
			expectedStatus: http.StatusMisdirectedRequest,
			checkResponse:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer := newTestTokenIssuer(nil)
			mockProv := &mockProvider{}
			conf := newTestConfig()
			st := store.NewMemoryStore()

			api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

			req := httptest.NewRequest(http.MethodGet, pathOAuthProtectedResource, nil)
			req.Host = tt.requestHost
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
				g.Expect(rec.Header().Get("Content-Type")).To(Equal("application/json"))

				response := parseJSONResponse(g, rec.Body.Bytes())

				authServers, ok := response["authorization_servers"].([]any)
				g.Expect(ok).To(BeTrue())
				g.Expect(authServers).To(HaveLen(1))

				authServer := authServers[0].(map[string]any)
				g.Expect(authServer["issuer"]).To(Equal("https://example.com"))
				g.Expect(authServer["authorization_endpoint"]).To(Equal("https://example.com" + pathAuthorize))
			}
		})
	}
}

func TestOAuthAuthorizationServer(t *testing.T) {
	tests := []struct {
		name           string
		config         *config.Config
		requestHost    string
		expectedStatus int
		checkResponse  bool
	}{
		{
			name:           "successful response with default scopes",
			config:         newTestConfig(),
			requestHost:    "example.com",
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
		{
			name: "successful response with no endpoint configured",
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{
							Host: "example.com",
							// No endpoint configured - should still work
						},
					},
				},
				Server: config.ServerConfig{
					Addr: "localhost:8080",
				},
			},
			requestHost:    "example.com",
			expectedStatus: http.StatusOK,
			checkResponse:  true,
		},
		{
			name: "failed to fetch supported scopes from invalid MCP endpoint",
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{
							Host:     "example.com",
							Endpoint: "http://invalid-endpoint-that-does-not-exist:99999",
						},
					},
				},
				Server: config.ServerConfig{
					Addr: "localhost:8080",
				},
			},
			requestHost:    "example.com",
			expectedStatus: http.StatusInternalServerError,
			checkResponse:  false,
		},
		{
			name:           "host not allowed",
			config:         newTestConfig(),
			requestHost:    "not-allowed.com",
			expectedStatus: http.StatusMisdirectedRequest,
			checkResponse:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer := newTestTokenIssuer(nil)
			mockProv := &mockProvider{}
			st := store.NewMemoryStore()

			api := newAPI(tokenIssuer, mockProv, tt.config, st, time.Now)

			req := httptest.NewRequest(http.MethodGet, pathOAuthAuthorizationServer, nil)
			req.Host = tt.requestHost
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
				g.Expect(response["code_challenge_methods_supported"]).To(Equal([]any{constants.AuthorizationServerCodeChallengeMethod}))
				g.Expect(response["grant_types_supported"]).To(Equal([]any{constants.AuthorizationServerGrantType}))
				g.Expect(response["response_modes_supported"]).To(Equal([]any{constants.AuthorizationServerResponseMode}))
				g.Expect(response["response_types_supported"]).To(Equal([]any{constants.AuthorizationServerResponseType}))
				g.Expect(response["scopes_supported"]).To(Equal([]any{constants.AuthorizationServerDefaultScope}))
				g.Expect(response["token_endpoint_auth_methods_supported"]).To(Equal([]any{constants.AuthorizationServerTokenEndpointAuthMethod}))
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
		config               *config.Config
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
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{Host: "example.com"},
					},
					AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
				},
				Server: config.ServerConfig{
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
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{Host: "example.com"},
					},
					AllowedRedirectURLs: []string{}, // Empty list should allow any URL
				},
				Server: config.ServerConfig{
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
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{Host: "example.com"},
					},
					AllowedRedirectURLs: []string{"^https://example\\.com/.*"}, // This should match
				},
				Server: config.ServerConfig{
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
			st := store.NewMemoryStore()

			api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

			req := httptest.NewRequest(http.MethodPost, pathRegister, strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			api.ServeHTTP(rec, req)

			g.Expect(rec.Code).To(Equal(tt.expectedStatus))

			if tt.checkResponse {
				response := parseJSONResponse(g, rec.Body.Bytes())

				g.Expect(response["client_id"]).To(Equal("mcp-oauth2-proxy"))
				g.Expect(response["token_endpoint_auth_method"]).To(Equal(constants.AuthorizationServerTokenEndpointAuthMethod))

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
		st                       store.Store
		config                   *config.Config
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
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://evil.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusBadRequest,
			expectedErrorMessage: "Invalid parameters: redirect_uri is not in the allow list: https://evil.com/callback",
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{Host: "example.com"},
					},
					AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
				},
				Server: config.ServerConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:                 "session store error",
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusInternalServerError,
			expectedErrorMessage: "Failed to generate state",
			st:                   &mockStore{Store: store.NewMemoryStore(), storeTransactionError: errors.New("session store failure")},
		},
		{
			name:           "valid authorize request",
			queryParams:    fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus: http.StatusSeeOther,
			expectRedirect: true,
		},
		{
			name:                     "no scope selection when endpoint is empty",
			queryParams:              fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:           http.StatusSeeOther,
			expectRedirect:           true,
			expectScopeSelectionPage: false,
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{
							Host: "example.com",
							// No endpoint configured - should not fetch scopes
						},
					},
				},
				Server: config.ServerConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:                 "failed to fetch supported scopes from invalid MCP endpoint",
			queryParams:          fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:       http.StatusInternalServerError,
			expectError:          true,
			expectedErrorMessage: "Failed to get supported scopes",
			config: &config.Config{
				Provider: config.ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: config.ProxyConfig{
					Hosts: []*config.HostConfig{
						{
							Host:     "example.com",
							Endpoint: "http://invalid-endpoint-that-does-not-exist:99999",
						},
					},
				},
				Server: config.ServerConfig{
					Addr: "localhost:8080",
				},
			},
		},
		{
			name:                     "scope selection page rendered",
			queryParams:              fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:           http.StatusOK,
			expectRedirect:           false,
			expectScopeSelectionPage: true,
			config: func() *config.Config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]config.ScopeConfig{
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
				return &config.Config{
					Provider: config.ProviderConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: config.ProxyConfig{
						Hosts: []*config.HostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
					},
					Server: config.ServerConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
		{
			name:                   "authorize with selected scopes",
			queryParams:            fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state&scope=read%%20write&skip_scope_selection=true", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:         http.StatusSeeOther,
			expectRedirect:         true,
			expectScopeTransaction: true,
			config: func() *config.Config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]config.ScopeConfig{
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
				return &config.Config{
					Provider: config.ProviderConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: config.ProxyConfig{
						Hosts: []*config.HostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
					},
					Server: config.ServerConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
		{
			name:                   "scope validation filters unsupported scopes",
			queryParams:            fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state&scope=read%%20invalid%%20write&skip_scope_selection=true", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:         http.StatusSeeOther,
			expectRedirect:         true,
			expectScopeTransaction: true,
			expectValidatedScopes:  true,
			expectedFilteredScopes: []string{"read", "write"},
			config: func() *config.Config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]config.ScopeConfig{
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
				return &config.Config{
					Provider: config.ProviderConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: config.ProxyConfig{
						Hosts: []*config.HostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
					},
					Server: config.ServerConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
		{
			name:                     "consent screen disabled with DisableConsentScreen",
			queryParams:              fmt.Sprintf("response_type=code&code_challenge_method=%s&redirect_uri=https://example.com/callback&state=test-state", constants.AuthorizationServerCodeChallengeMethod),
			expectedStatus:           http.StatusSeeOther,
			expectRedirect:           true,
			expectScopeSelectionPage: false,
			config: func() *config.Config {
				// Create mock MCP server with scopes
				mockMCP := createMockMCPServer([]config.ScopeConfig{
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
				return &config.Config{
					Provider: config.ProviderConfig{
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
					},
					Proxy: config.ProxyConfig{
						Hosts: []*config.HostConfig{
							{
								Host:     "example.com",
								Endpoint: mockMCP.URL,
							},
						},
						DisableConsentScreen: true,
					},
					Server: config.ServerConfig{
						Addr: "localhost:8080",
					},
				}
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer := newTestTokenIssuer(nil)
			mockProv := &mockProvider{}
			conf := setupConfig(g, tt.config)
			st := tt.st
			if st == nil {
				st = store.NewMemoryStore()
			}

			api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

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
				tx, found := st.RetrieveTransaction(stateValue)
				g.Expect(found).To(BeTrue())
				g.Expect(tx.ClientParams.Scopes).To(Equal(tt.expectedFilteredScopes))
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
		st               store.Store
		csrfMismatch     bool
		retrieveError    bool
		needsTokenServer bool
		issueError       bool
		requestHost      string
		transactionHost  string // Host to use in the stored transaction
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
			name:           "host not allowed",
			setupSession:   true,
			setCookie:      true,
			queryParams:    "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			expectedStatus: http.StatusMisdirectedRequest,
			requestHost:    "not-allowed.com",
		},
		{
			name:            "host mismatch with transaction",
			setupSession:    true,
			setCookie:       true,
			queryParams:     "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			expectedStatus:  http.StatusBadRequest,
			requestHost:     "example.com",       // This host is allowed, but doesn't match the transaction host
			transactionHost: "other.example.com", // Different host in the transaction
		},
		{
			name:             "session store error in callback",
			setupSession:     true,
			setCookie:        true,
			queryParams:      "code=auth-code&state=SESSION_KEY_PLACEHOLDER",
			tokens:           map[string]string{"access_token": "token"},
			expectedStatus:   http.StatusInternalServerError,
			st:               &mockStore{Store: store.NewMemoryStore(), storeError: errors.New("session store failure in callback")},
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
				verifyUserResult: &provider.UserInfo{Username: "test-user@example.com"},
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
			st := tt.st
			if st == nil {
				st = store.NewMemoryStore()
			}

			// Setup token issuer with potential error
			var issueErr error
			if tt.issueError {
				issueErr = errors.New("key generation failed")
			}
			tokenIssuer := newTestTokenIssuer(issueErr)
			api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

			// For successful callback test, we need the session key to match the cookie value
			var sessionKey string
			if tt.setupSession {
				tx := newTestTransaction()
				// Override transaction host if specified
				if tt.transactionHost != "" {
					tx.Host = tt.transactionHost
				}
				var err error
				sessionKey, err = st.StoreTransaction(tx)
				g.Expect(err).ToNot(HaveOccurred())

				// For session not found test, replace session store after setting up session
				if tt.retrieveError {
					st = &mockStore{Store: st, retrieveError: true}
					// Need to recreate API with updated session store
					var issueErr error
					if tt.issueError {
						issueErr = errors.New("key generation failed")
					}
					tokenIssuer = newTestTokenIssuer(issueErr)
					api = newAPI(tokenIssuer, mockProv, conf, st, time.Now)
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
		name            string
		setupSession    bool
		formData        string
		expectedStatus  int
		checkResponse   bool
		requestHost     string
		transactionHost string // Host to use in the stored transaction/session
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
			name:           "host not allowed",
			setupSession:   true,
			formData:       "code=valid-code&code_verifier=test-verifier",
			expectedStatus: http.StatusMisdirectedRequest,
			requestHost:    "not-allowed.com",
		},
		{
			name:            "host mismatch with session",
			setupSession:    true,
			formData:        "code=valid-code&code_verifier=test-verifier",
			expectedStatus:  http.StatusBadRequest,
			requestHost:     "example.com",       // This host is allowed, but doesn't match the session's transaction host
			transactionHost: "other.example.com", // Different host in the transaction
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
			st := store.NewMemoryStore()

			api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

			var authzCode string
			var jwtToken string
			if tt.setupSession {
				tx := newTestTransaction()
				// Override transaction host if specified
				if tt.transactionHost != "" {
					tx.Host = tt.transactionHost
				}

				// Issue a real JWT token for this test
				now := time.Now()
				var exp time.Time
				var err error
				jwtToken, exp, err = tokenIssuer.Issue("https://example.com", "test-user@example.com", "mcp-oauth2-proxy", now, nil, nil)
				g.Expect(err).ToNot(HaveOccurred())

				// Create outcome with real JWT token
				outcome := &oauth2.Token{
					AccessToken: jwtToken,
					TokenType:   "Bearer",
					Expiry:      exp,
				}
				s := &store.Session{TX: tx, Outcome: outcome}
				authzCode, err = st.StoreSession(s)
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
				publicKeys := tokenIssuer.PublicKeys(time.Now())
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
	st := store.NewMemoryStore()

	api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

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
	g.Expect(signingAlgs[0]).To(Equal(issuer.Algorithm().String()))
}

func TestJWKS(t *testing.T) {
	g := NewWithT(t)

	// Create a token issuer with known keys for testing
	tokenIssuer, _, publicKey := newTestTokenIssuerWithSharedKeys()
	mockProv := &mockProvider{}
	conf := newTestConfig()
	st := store.NewMemoryStore()

	api := newAPI(tokenIssuer, mockProv, conf, st, time.Now)

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
		g.Expect(alg).To(Equal(issuer.Algorithm().String()))
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

// createMockMCPServer creates a test MCP server with scopes metadata
func createMockMCPServer(scopes []config.ScopeConfig) *httptest.Server {
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-mcp-server",
		Version: "1.0.0",
	}, &mcp.ServerOptions{
		HasTools: true,
	})
	mcpServer.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (result mcp.Result, err error) {
			res, err := next(ctx, method, req)
			if method == "tools/list" && err == nil {
				listToolsRes := res.(*mcp.ListToolsResult)
				if listToolsRes.Meta == nil {
					listToolsRes.Meta = make(mcp.Meta)
				}
				listToolsRes.Meta["scopes"] = scopes
			}
			return res, err
		}
	})
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	return httptest.NewServer(handler)
}

// mockProvider implements the provider interface for testing
type mockProvider struct {
	oauth2ConfigFunc func() *oauth2.Config
	verifyUserResult *provider.UserInfo
	verifyUserError  error
}

func (m *mockProvider) OAuth2Config() *oauth2.Config {
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

func (m *mockProvider) VerifyUser(ctx context.Context, ts oauth2.TokenSource) (*provider.UserInfo, error) {
	if m.verifyUserError != nil {
		return nil, m.verifyUserError
	}
	if m.verifyUserResult != nil {
		return m.verifyUserResult, nil
	}
	return &provider.UserInfo{Username: "test-user@example.com"}, nil
}

// mockStore allows simulating st failures
type mockStore struct {
	store.Store
	storeError            error
	storeTransactionError error
	retrieveError         bool
}

func (m *mockStore) StoreSession(s *store.Session) (string, error) {
	if m.storeError != nil {
		return "", m.storeError
	}
	return m.Store.StoreSession(s)
}

func (m *mockStore) StoreTransaction(tx *store.Transaction) (string, error) {
	if m.storeTransactionError != nil {
		return "", m.storeTransactionError
	}
	return m.Store.StoreTransaction(tx)
}

func (m *mockStore) RetrieveSession(key string) (*store.Session, bool) {
	if m.retrieveError {
		return nil, false
	}
	return m.Store.RetrieveSession(key)
}

func (m *mockStore) RetrieveTransaction(key string) (*store.Transaction, bool) {
	if m.retrieveError {
		return nil, false
	}
	return m.Store.RetrieveTransaction(key)
}

func newTestConfig() *config.Config {
	return &config.Config{
		Provider: config.ProviderConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		},
		Proxy: config.ProxyConfig{
			Hosts: []*config.HostConfig{
				{
					Host: "example.com",
				},
				{
					Host: "other.example.com",
				},
			},
		},
		Server: config.ServerConfig{
			Addr: "localhost:8080",
		},
	}
}

func setupConfig(g *WithT, conf *config.Config) *config.Config {
	if conf == nil {
		conf = newTestConfig()
	}
	conf.Provider.Name = "mock"
	err := conf.ValidateAndInitialize()
	g.Expect(err).ToNot(HaveOccurred())
	return conf
}

func parseJSONResponse(g *WithT, body []byte) map[string]any {
	var response map[string]any
	err := json.Unmarshal(body, &response)
	g.Expect(err).ToNot(HaveOccurred())
	return response
}

func newTestTransaction() *store.Transaction {
	return &store.Transaction{
		ClientParams: store.TransactionClientParams{
			CodeChallenge: oauth2.S256ChallengeFromVerifier("test-verifier"),
			RedirectURL:   "https://example.com/callback",
			State:         "test-state",
		},
		CodeVerifier: "test-verifier",
		Host:         "example.com",
	}
}

// mockIssuer implements the issuer.Issuer interface for testing
type mockIssuer struct {
	issueFunc      func(iss, sub, aud string, now time.Time, groups, scopes []string) (string, time.Time, error)
	verifyFunc     func(bearerToken string, now time.Time, iss, aud string) bool
	publicKeysFunc func(now time.Time) []jwk.Key
	privateKey     jwk.Key
	publicKey      jwk.Key
}

func (m *mockIssuer) Issue(iss, sub, aud string, now time.Time, groups, scopes []string) (string, time.Time, error) {
	if m.issueFunc != nil {
		return m.issueFunc(iss, sub, aud, now, groups, scopes)
	}
	// Default implementation using the test keys
	if m.privateKey == nil {
		return "", time.Time{}, errors.New("no private key configured")
	}

	exp := now.Add(time.Hour)
	tok, err := jwt.NewBuilder().
		Issuer(iss).
		Subject(sub).
		Audience([]string{aud}).
		IssuedAt(now).
		NotBefore(now).
		Expiration(exp).
		JwtID("test-jwt-id").
		Build()
	if err != nil {
		return "", time.Time{}, err
	}

	b, err := jwt.Sign(tok, jwt.WithKey(issuer.Algorithm(), m.privateKey))
	if err != nil {
		return "", time.Time{}, err
	}

	return string(b), exp, nil
}

func (m *mockIssuer) Verify(bearerToken string, now time.Time, iss, aud string) bool {
	if m.verifyFunc != nil {
		return m.verifyFunc(bearerToken, now, iss, aud)
	}
	// Default implementation using the test public key
	if m.publicKey == nil {
		return false
	}

	_, err := jwt.Parse([]byte(bearerToken),
		jwt.WithKey(issuer.Algorithm(), m.publicKey),
		jwt.WithIssuer(iss),
		jwt.WithAudience(aud),
		jwt.WithValidate(true))
	return err == nil
}

func (m *mockIssuer) PublicKeys(now time.Time) []jwk.Key {
	if m.publicKeysFunc != nil {
		return m.publicKeysFunc(now)
	}
	if m.publicKey != nil {
		return []jwk.Key{m.publicKey}
	}
	return nil
}

func newTestTokenIssuer(issueError error) issuer.Issuer {
	// Create a working test issuer with the same key for signing and verifying
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey, _ := jwk.Import(priv)
	publicKey, _ := privateKey.PublicKey()

	// Add key ID to both keys
	thumbprint, _ := publicKey.Thumbprint(crypto.SHA256)
	keyID := fmt.Sprintf("%x", thumbprint)
	privateKey.Set(jwk.KeyIDKey, keyID)
	publicKey.Set(jwk.KeyIDKey, keyID)

	mock := &mockIssuer{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	if issueError != nil {
		mock.issueFunc = func(iss, sub, aud string, now time.Time, groups, scopes []string) (string, time.Time, error) {
			return "", time.Time{}, issueError
		}
	}

	return mock
}

// newTestTokenIssuerWithSharedKeys creates a token issuer that uses the same keys for all tests
func newTestTokenIssuerWithSharedKeys() (issuer.Issuer, jwk.Key, jwk.Key) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKey, _ := jwk.Import(priv)
	publicKey, _ := privateKey.PublicKey()

	// Add key ID to both keys
	thumbprint, _ := publicKey.Thumbprint(crypto.SHA256)
	keyID := fmt.Sprintf("%x", thumbprint)
	privateKey.Set(jwk.KeyIDKey, keyID)
	publicKey.Set(jwk.KeyIDKey, keyID)

	mock := &mockIssuer{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
	return mock, privateKey, publicKey
}

// parseJWT parses and validates a JWT token using the given public key
func parseJWT(g *WithT, tokenString string, publicKey jwk.Key) jwt.Token {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(issuer.Algorithm(), publicKey), jwt.WithValidate(true))
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
