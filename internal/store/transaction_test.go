package store

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
	"github.com/matheuscscp/mcp-oauth2-proxy/internal/constants"
)

func TestNewTransaction(t *testing.T) {
	tests := []struct {
		name          string
		queryParams   map[string]string
		codeVerifier  string
		hostScopes    []string
		proxyConfig   *config.ProxyConfig
		expectedError string
		expectedTx    *Transaction
		requestHost   string
	}{
		{
			name: "valid transaction with all parameters",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://example.com/callback",
				constants.QueryParamState:               "test-state",
				constants.QueryParamScopes:              "read write delete",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{"read", "write", "admin"},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedTx: &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "test-challenge",
					RedirectURL:   "https://example.com/callback",
					Scopes:        []string{"read", "write"}, // delete is filtered out
					State:         "test-state",
				},
				CodeVerifier: "test-verifier",
				Host:         "test.example.com",
			},
			requestHost: "test.example.com",
		},
		{
			name: "unsupported response type",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        "token", // wrong type
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://example.com/callback",
				constants.QueryParamState:               "test-state",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedError: "'token' is not supported for response_type, only code is allowed",
			requestHost:   "test.example.com",
		},
		{
			name: "unsupported code challenge method",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: "plain", // wrong method
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://example.com/callback",
				constants.QueryParamState:               "test-state",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedError: "'plain' is not supported for code_challenge_method, only S256 is allowed",
			requestHost:   "test.example.com",
		},
		{
			name: "missing code challenge method",
			queryParams: map[string]string{
				constants.QueryParamResponseType:  constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallenge: "test-challenge",
				constants.QueryParamRedirectURI:   "https://example.com/callback",
				constants.QueryParamState:         "test-state",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedError: "'' is not supported for code_challenge_method, only S256 is allowed",
			requestHost:   "test.example.com",
		},
		{
			name: "invalid redirect URL not in allow list",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://evil.com/callback", // not allowed
				constants.QueryParamState:               "test-state",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedError: "redirect_uri is not in the allow list: https://evil.com/callback",
			requestHost:   "test.example.com",
		},
		{
			name: "empty redirect URL not allowed",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamState:               "test-state",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				// No AllowedRedirectURLs configured
			},
			expectedError: "redirect_uri is not in the allow list: ",
			requestHost:   "test.example.com",
		},
		{
			name: "scope filtering - only supported scopes included",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://example.com/callback",
				constants.QueryParamState:               "test-state",
				constants.QueryParamScopes:              "read write admin delete unknown",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{"read", "write", "admin"}, // Only these are supported
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedTx: &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "test-challenge",
					RedirectURL:   "https://example.com/callback",
					Scopes:        []string{"read", "write", "admin"}, // delete and unknown are filtered out
					State:         "test-state",
				},
				CodeVerifier: "test-verifier",
				Host:         "test.example.com",
			},
			requestHost: "test.example.com",
		},
		{
			name: "empty scopes",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://example.com/callback",
				constants.QueryParamState:               "test-state",
				constants.QueryParamScopes:              "",
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{"read", "write"},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedTx: &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "test-challenge",
					RedirectURL:   "https://example.com/callback",
					Scopes:        []string{},
					State:         "test-state",
				},
				CodeVerifier: "test-verifier",
				Host:         "test.example.com",
			},
			requestHost: "test.example.com",
		},
		{
			name: "scopes with multiple spaces",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamCodeChallenge:       "test-challenge",
				constants.QueryParamRedirectURI:         "https://example.com/callback",
				constants.QueryParamState:               "test-state",
				constants.QueryParamScopes:              "read  write   admin", // multiple spaces
			},
			codeVerifier: "test-verifier",
			hostScopes:   []string{"read", "write", "admin"},
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "test.example.com",
					},
				},
				AllowedRedirectURLs: []string{"^https://example\\.com/.*"},
			},
			expectedTx: &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "test-challenge",
					RedirectURL:   "https://example.com/callback",
					Scopes:        []string{"read", "write", "admin"},
					State:         "test-state",
				},
				CodeVerifier: "test-verifier",
				Host:         "test.example.com",
			},
			requestHost: "test.example.com",
		},
		{
			name: "minimal valid transaction with redirect URL",
			queryParams: map[string]string{
				constants.QueryParamResponseType:        constants.AuthorizationServerResponseType,
				constants.QueryParamCodeChallengeMethod: constants.AuthorizationServerCodeChallengeMethod,
				constants.QueryParamRedirectURI:         "https://minimal.example.com/callback",
			},
			codeVerifier: "",
			hostScopes:   nil,
			proxyConfig: &config.ProxyConfig{
				Hosts: []*config.HostConfig{
					{
						Host: "minimal.example.com",
					},
				},
				// No AllowedRedirectURLs means any non-empty URL is allowed
			},
			expectedTx: &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "",
					RedirectURL:   "https://minimal.example.com/callback",
					Scopes:        []string{},
					State:         "",
				},
				CodeVerifier: "",
				Host:         "minimal.example.com",
			},
			requestHost: "minimal.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Initialize the proxy config by creating a full Config
			fullConfig := &config.Config{
				Provider: config.ProviderConfig{
					Name:         "mock",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: *tt.proxyConfig,
			}
			err := fullConfig.ValidateAndInitialize()
			g.Expect(err).ToNot(HaveOccurred())
			tt.proxyConfig = &fullConfig.Proxy

			// Build request URL with query parameters
			params := url.Values{}
			for key, value := range tt.queryParams {
				params.Set(key, value)
			}
			reqURL := fmt.Sprintf("http://%s/authorize?%s", tt.requestHost, params.Encode())
			req := httptest.NewRequest(http.MethodGet, reqURL, nil)
			req.Host = tt.requestHost

			// Call NewTransaction
			tx, err := NewTransaction(tt.proxyConfig, req, tt.codeVerifier, tt.hostScopes)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(Equal(tt.expectedError))
				g.Expect(tx).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(tx).To(Equal(tt.expectedTx))
			}
		})
	}
}
