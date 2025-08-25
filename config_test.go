package main

import (
	"regexp"
	"testing"

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
				},
				Server: serverConfig{
					Addr: ":9090",
					CORS: true,
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
				},
				Server: serverConfig{
					Addr: ":9090",
					CORS: true,
				},
			},
		},
		{
			name: "config with defaults applied",
			config: config{
				Provider: providerConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr: false,
			expectedConfig: config{
				Provider: providerConfig{
					Name:                "google",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: proxyConfig{
					AllowedRedirectURLs: []string{},
				},
				Server: serverConfig{
					Addr: ":8080",
					CORS: false,
				},
			},
		},
		{
			name: "missing client ID",
			config: config{
				Provider: providerConfig{
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
