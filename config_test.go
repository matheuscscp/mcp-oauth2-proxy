package main

import (
	"context"
	"regexp"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestConfig_validateAndInitialize(t *testing.T) {
	tests := []struct {
		name           string
		config         config
		wantErr        bool
		expectedErrMsg string
		expectedConfig config
	}{
		{
			name: "empty provider name",
			config: config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr:        true,
			expectedErrMsg: "provider.name must be set",
		},
		{
			name: "valid config with all fields",
			config: config{
				Provider: providerConfig{
					Name:                "google",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{"example\\.com", "test\\.org"},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{"https://example\\.com/.*", "https://test\\.org/.*"},
					CORS:                true,
				},
				Server: serverConfig{
					Addr: ":9090",
				},
			},
			wantErr: false,
			expectedConfig: config{
				Provider: providerConfig{
					Name:                "google",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{"example\\.com", "test\\.org"},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{"https://example\\.com/.*", "https://test\\.org/.*"},
					Hosts:               []*hostConfig{},
					CORS:                true,
				},
				Server: serverConfig{
					Addr: ":9090",
				},
			},
		},
		{
			name: "config with defaults applied",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr: false,
			expectedConfig: config{
				Provider: providerConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts:               []*hostConfig{},
				},
				Server: serverConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "missing client ID",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr:        true,
			expectedErrMsg: "provider.clientID must be set",
		},
		{
			name: "missing client secret",
			config: config{
				Provider: providerConfig{
					Name:     "test-provider",
					ClientID: "test-client-id",
				},
			},
			wantErr:        true,
			expectedErrMsg: "provider.clientSecret must be set",
		},
		{
			name: "invalid regex in allowed email domains",
			config: config{
				Provider: providerConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{"[invalid-regex"},
				},
			},
			wantErr:        true,
			expectedErrMsg: "failed to build regex list for allowed email domains",
		},
		{
			name: "invalid regex in allowed redirect URLs",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{"[invalid-regex"},
				},
			},
			wantErr:        true,
			expectedErrMsg: "failed to build regex list for allowed redirect URLs",
		},
		{
			name: "config with nil hosts - initializes empty slice",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					Hosts: nil,
				},
			},
			wantErr: false,
			expectedConfig: config{
				Provider: providerConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts:               []*hostConfig{},
				},
				Server: serverConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "config with hosts having valid endpoints",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					Hosts: []*hostConfig{
						{
							Host:     "example.com",
							Endpoint: "http://localhost:8080",
						},
						{
							Host:     "test.org",
							Endpoint: "http://localhost:8081",
						},
					},
				},
			},
			wantErr: false,
			expectedConfig: config{
				Provider: providerConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts: []*hostConfig{
						{
							Host:     "example.com",
							Endpoint: "http://localhost:8080",
						},
						{
							Host:     "test.org",
							Endpoint: "http://localhost:8081",
						},
					},
				},
				Server: serverConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "config with hosts missing endpoint - should be valid now",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					Hosts: []*hostConfig{
						{
							Host:     "example.com",
							Endpoint: "", // Missing endpoint is now valid
						},
					},
				},
			},
			wantErr: false,
			expectedConfig: config{
				Provider: providerConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts: []*hostConfig{
						{
							Host:     "example.com",
							Endpoint: "",
						},
					},
				},
				Server: serverConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "config with hosts missing host - validation error",
			config: config{
				Provider: providerConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: proxyConfig{
					Hosts: []*hostConfig{
						{
							Host:     "", // Missing host
							Endpoint: "http://example.com",
						},
					},
				},
			},
			wantErr:        true,
			expectedErrMsg: "host is empty for proxy.hosts[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			err := tt.config.validateAndInitialize()

			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedErrMsg))
				return
			}

			g.Expect(err).ToNot(HaveOccurred())

			// Verify defaults were applied correctly
			g.Expect(tt.config.Provider.Name).To(Equal(tt.expectedConfig.Provider.Name))
			g.Expect(tt.config.Server.Addr).To(Equal(tt.expectedConfig.Server.Addr))
			g.Expect(tt.config.Provider.AllowedEmailDomains).To(Equal(tt.expectedConfig.Provider.AllowedEmailDomains))
			g.Expect(tt.config.Proxy.AllowedRedirectURLs).To(Equal(tt.expectedConfig.Proxy.AllowedRedirectURLs))
			g.Expect(tt.config.Proxy.Hosts).To(Equal(tt.expectedConfig.Proxy.Hosts))

			// Verify nil slice initialization worked
			g.Expect(tt.config.Proxy.Hosts).ToNot(BeNil())

			// Verify regex compilation worked when applicable
			if len(tt.config.Provider.AllowedEmailDomains) > 0 {
				g.Expect(tt.config.Provider.regexAllowedEmailDomains).To(HaveLen(len(tt.config.Provider.AllowedEmailDomains)))
			}
			if len(tt.config.Proxy.AllowedRedirectURLs) > 0 {
				g.Expect(tt.config.Proxy.regexAllowedRedirectURLs).To(HaveLen(len(tt.config.Proxy.AllowedRedirectURLs)))
			}
		})
	}
}

func TestProviderConfig_validateEmailDomain(t *testing.T) {
	tests := []struct {
		name     string
		provider providerConfig
		email    string
		expected bool
	}{
		{
			name: "no allowed domains - should allow all",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{},
			},
			email:    "test@example.com",
			expected: true,
		},
		{
			name: "valid email with matching domain",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@example.com",
			expected: true,
		},
		{
			name: "valid email with non-matching domain",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@other.com",
			expected: false,
		},
		{
			name: "invalid email format - no @",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
				},
			},
			email:    "invalid-email",
			expected: false,
		},
		{
			name: "invalid email format - multiple @",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
				},
			},
			email:    "user@domain@example.com",
			expected: false,
		},
		{
			name: "regex pattern matching subdomain",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`.*\.example\.com`),
				},
			},
			email:    "user@sub.example.com",
			expected: true,
		},
		{
			name: "regex pattern not matching subdomain",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`^example\.com$`),
				},
			},
			email:    "user@sub.example.com",
			expected: false,
		},
		{
			name: "multiple patterns - first matches",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@example.com",
			expected: true,
		},
		{
			name: "multiple patterns - second matches",
			provider: providerConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@test.org",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			result := tt.provider.validateEmailDomain(tt.email)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestProxyConfig_acceptsHost(t *testing.T) {
	tests := []struct {
		name           string
		proxyConfig    proxyConfig
		host           string
		expectedResult bool
	}{
		{
			name: "host in list",
			proxyConfig: proxyConfig{
				Hosts: []*hostConfig{
					{Host: "example.com"},
					{Host: "test.com"},
				},
			},
			host:           "example.com",
			expectedResult: true,
		},
		{
			name: "host not in list",
			proxyConfig: proxyConfig{
				Hosts: []*hostConfig{
					{Host: "example.com"},
					{Host: "test.com"},
				},
			},
			host:           "notallowed.com",
			expectedResult: false,
		},
		{
			name:           "empty hosts list",
			proxyConfig:    proxyConfig{},
			host:           "example.com",
			expectedResult: false,
		},
		{
			name: "empty host string",
			proxyConfig: proxyConfig{
				Hosts: []*hostConfig{
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
			result := tt.proxyConfig.acceptsHost(tt.host)
			g.Expect(result).To(Equal(tt.expectedResult))
		})
	}
}

func TestProxyConfig_validateRedirectURL(t *testing.T) {
	tests := []struct {
		name     string
		proxy    proxyConfig
		url      string
		expected bool
	}{
		{
			name: "empty URL",
			proxy: proxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{},
			},
			url:      "",
			expected: false,
		},
		{
			name: "no allowed URLs - should allow all non-empty",
			proxy: proxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{},
			},
			url:      "https://example.com/callback",
			expected: true,
		},
		{
			name: "valid URL with matching pattern",
			proxy: proxyConfig{
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
			proxy: proxyConfig{
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
			proxy: proxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
				},
			},
			url:      "https://example.com/path",
			expected: true,
		},
		{
			name: "exact pattern match",
			proxy: proxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`^https://example\.com/callback$`),
				},
			},
			url:      "https://example.com/callback",
			expected: true,
		},
		{
			name: "exact pattern no match",
			proxy: proxyConfig{
				regexAllowedRedirectURLs: []*regexp.Regexp{
					regexp.MustCompile(`^https://example\.com/callback$`),
				},
			},
			url:      "https://example.com/callback/extra",
			expected: false,
		},
		{
			name: "multiple patterns - first matches",
			proxy: proxyConfig{
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
			proxy: proxyConfig{
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
			result := tt.proxy.validateRedirectURL(tt.url)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestProxyConfig_supportedScopes(t *testing.T) {
	// Since supportedScopes now fetches from an MCP endpoint,
	// we'll test just the basic logic with mock data
	tests := []struct {
		name           string
		proxy          proxyConfig
		host           string
		expected       []string
		expectedConfig []scopeConfig
		expectError    bool
	}{
		{
			name: "no hosts configured - returns default scope",
			proxy: proxyConfig{
				Hosts: []*hostConfig{},
			},
			host:     "example.com",
			expected: []string{"mcp-oauth2-proxy"},
		},
		{
			name: "host not found - returns default scope",
			proxy: proxyConfig{
				Hosts: []*hostConfig{
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
			proxy: proxyConfig{
				Hosts: []*hostConfig{
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
			proxy: proxyConfig{
				Hosts: []*hostConfig{
					{
						Host: "example.com",
						Endpoint: func() string {
							// Create mock MCP server that returns empty scopes
							mockMCP := createMockMCPServer([]scopeConfig{})
							return mockMCP.URL
						}(),
					},
				},
			},
			host:     "example.com",
			expected: []string{"mcp-oauth2-proxy"},
		},
		{
			name: "host found but invalid MCP endpoint URL - returns error",
			proxy: proxyConfig{
				Hosts: []*hostConfig{
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
			proxy: proxyConfig{
				Hosts: []*hostConfig{
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
			result, resultConfig, err := tt.proxy.supportedScopes(ctx, tt.host)
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

func TestHostConfig_getSupportedScopes(t *testing.T) {
	g := NewWithT(t)

	mockScopes := []scopeConfig{
		{
			Name:        "test-scope",
			Description: "Test scope description",
			Tools:       []string{"tool1", "tool2"},
		},
	}
	mockServer := createMockMCPServer(mockScopes)
	defer mockServer.Close()

	proxy := &proxyConfig{}
	host := &hostConfig{
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
