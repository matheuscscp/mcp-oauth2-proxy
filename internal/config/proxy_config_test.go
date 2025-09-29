package config

import (
	"context"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	. "github.com/onsi/gomega"
)

func TestProxyConfig_AcceptsHost(t *testing.T) {
	tests := []struct {
		name           string
		proxyConfig    ProxyConfig
		host           string
		expectedResult bool
	}{
		{
			name: "host in list",
			proxyConfig: ProxyConfig{
				Hosts: []*HostConfig{
					{Host: "example.com"},
					{Host: "test.com"},
				},
			},
			host:           "example.com",
			expectedResult: true,
		},
		{
			name: "host not in list",
			proxyConfig: ProxyConfig{
				Hosts: []*HostConfig{
					{Host: "example.com"},
					{Host: "test.com"},
				},
			},
			host:           "notallowed.com",
			expectedResult: false,
		},
		{
			name:           "empty hosts list",
			proxyConfig:    ProxyConfig{},
			host:           "example.com",
			expectedResult: false,
		},
		{
			name: "empty host string",
			proxyConfig: ProxyConfig{
				Hosts: []*HostConfig{
					{Host: "example.com"},
				},
			},
			host:           "",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			result := tt.proxyConfig.AcceptsHost(tt.host)
			g.Expect(result).To(Equal(tt.expectedResult))
		})
	}
}

func TestProxyConfig_ValidateRedirectURL(t *testing.T) {
	tests := []struct {
		name     string
		proxy    ProxyConfig
		url      string
		expected bool
	}{
		{
			name: "empty URL",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{},
			},
			url:      "",
			expected: false,
		},
		{
			name: "no allowed URLs - should allow all non-empty",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{},
			},
			url:      "https://example.com/callback",
			expected: true,
		},
		{
			name: "valid URL with matching pattern",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`https://example\.com/.*`),
					regexp.MustCompile(`https://test\.org/.*`),
				},
			},
			url:      "https://example.com/callback",
			expected: true,
		},
		{
			name: "valid URL with non-matching pattern",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`https://example\.com/.*`),
					regexp.MustCompile(`https://test\.org/.*`),
				},
			},
			url:      "https://other.com/callback",
			expected: false,
		},
		{
			name: "partial match with regex",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
				},
			},
			url:      "https://example.com/path",
			expected: true,
		},
		{
			name: "exact pattern match",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`^https://example\.com/callback$`),
				},
			},
			url:      "https://example.com/callback",
			expected: true,
		},
		{
			name: "exact pattern no match",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`^https://example\.com/callback$`),
				},
			},
			url:      "https://example.com/callback/extra",
			expected: false,
		},
		{
			name: "multiple patterns - first matches",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`https://example\.com/.*`),
					regexp.MustCompile(`https://test\.org/.*`),
				},
			},
			url:      "https://example.com/auth",
			expected: true,
		},
		{
			name: "multiple patterns - second matches",
			proxy: ProxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`https://example\.com/.*`),
					regexp.MustCompile(`https://test\.org/.*`),
				},
			},
			url:      "https://test.org/callback",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			result := tt.proxy.ValidateRedirectURL(tt.url)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestProxyConfig_SupportedScopes(t *testing.T) {
	// Since supportedScopes now fetches from an MCP endpoint,
	// we'll test just the basic logic with mock data
	tests := []struct {
		name           string
		proxy          ProxyConfig
		host           string
		expected       []string
		expectedConfig []ScopeConfig
		expectError    bool
	}{
		{
			name: "no hosts configured - returns default scope",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{},
			},
			host:     "example.com",
			expected: []string{"mcp-oauth2-proxy"},
		},
		{
			name: "host not found - returns default scope",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{
					{
						Host:     "other.com",
						Endpoint: "http://localhost:8080",
					},
				},
			},
			host:     "example.com",
			expected: []string{"mcp-oauth2-proxy"},
		},
		{
			name: "host found but endpoint is empty - returns default scope",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{
					{
						Host:     "example.com",
						Endpoint: "", // Empty endpoint should not fetch scopes
					},
				},
			},
			host:     "example.com",
			expected: []string{"mcp-oauth2-proxy"},
		},
		{
			name: "host found but MCP returns empty scopes - returns default scope",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{
					{
						Host: "example.com",
						Endpoint: func() string {
							// Create mock MCP server that returns empty scopes
							mockMCP := createMockMCPServer([]ScopeConfig{})
							return mockMCP.URL
						}(),
					},
				},
			},
			host:     "example.com",
			expected: []string{"mcp-oauth2-proxy"},
		},
		{
			name: "host found with valid endpoint and scopes - returns extracted scope names",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{
					{
						Host: "example.com",
						Endpoint: func() string {
							// Create mock MCP server that returns multiple scopes
							mockScopes := []ScopeConfig{
								{Name: "scope1", Description: "First scope", Tools: []string{"tool1"}},
								{Name: "scope2", Description: "Second scope", Tools: []string{"tool2", "tool3"}},
								{Name: "scope3", Description: "Third scope", Tools: []string{}},
							}
							mockMCP := createMockMCPServer(mockScopes)
							return mockMCP.URL
						}(),
					},
				},
			},
			host:     "example.com",
			expected: []string{"scope1", "scope2", "scope3"},
			expectedConfig: []ScopeConfig{
				{Name: "scope1", Description: "First scope", Tools: []string{"tool1"}},
				{Name: "scope2", Description: "Second scope", Tools: []string{"tool2", "tool3"}},
				{Name: "scope3", Description: "Third scope", Tools: []string{}},
			},
		},
		{
			name: "host found but invalid MCP endpoint URL - returns error",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{
					{
						Host:     "example.com",
						Endpoint: "http://invalid\x00url\x01with\x02control\x03characters",
					},
				},
			},
			host:        "example.com",
			expectError: true,
		},
		{
			name: "host found but MCP returns invalid JSON metadata - returns error",
			proxy: ProxyConfig{
				Hosts: []*HostConfig{
					{
						Host: "example.com",
						Endpoint: func() string {
							// Create mock MCP server that returns invalid JSON in metadata
							mockMCP := createMockMCPServerWithBogusJSON()
							return mockMCP.URL
						}(),
					},
				},
			},
			host:        "example.com",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			// Use a context for the new signature
			ctx := context.Background()
			result, resultConfig, err := tt.proxy.SupportedScopes(ctx, tt.host)
			if tt.expectError {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(result).To(Equal(tt.expected))
				g.Expect(resultConfig).To(Equal(tt.expectedConfig))
			}
		})
	}
}

func TestProxyConfig_getSupportedScopes(t *testing.T) {
	g := NewWithT(t)

	mockScopes := []ScopeConfig{
		{
			Name:        "test-scope",
			Description: "Test scope description",
			Tools:       []string{"tool1", "tool2"},
		},
	}
	mockServer := createMockMCPServer(mockScopes)
	defer mockServer.Close()

	proxy := &ProxyConfig{}
	host := &HostConfig{
		Host:     "example.com",
		Endpoint: mockServer.URL,
	}

	ctx := context.Background()
	now := time.Now()

	// First call should fetch from server
	scopes, err := proxy.getSupportedScopes(ctx, host, now)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(scopes).To(Equal(mockScopes))
	g.Expect(host.scopes).To(Equal(mockScopes))
	g.Expect(host.scopesDeadline.After(now)).To(BeTrue())

	// Second call within cache window should return cached data
	cachedScopes, err := proxy.getSupportedScopes(ctx, host, now.Add(5*time.Second))
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(cachedScopes).To(Equal(mockScopes))

	// Call after cache expiry should fetch fresh data
	newNow := now.Add(15 * time.Second)
	freshScopes, err := proxy.getSupportedScopes(ctx, host, newNow)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(freshScopes).To(Equal(mockScopes))
	g.Expect(host.scopesDeadline.After(newNow)).To(BeTrue())
}

// createMockMCPServer creates a test MCP server with scopes metadata
func createMockMCPServer(scopes []ScopeConfig) *httptest.Server {
	mcpServer := server.NewMCPServer("test-mcp-server", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithHooks(&server.Hooks{
			OnAfterListTools: []server.OnAfterListToolsFunc{
				func(ctx context.Context, id any, message *mcp.ListToolsRequest, result *mcp.ListToolsResult) {
					// Add scopes to the metadata
					if result.Meta == nil {
						result.Meta = &mcp.Meta{
							AdditionalFields: make(map[string]any),
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
							AdditionalFields: make(map[string]any),
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
