package config

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestConfig_ValidateAndInitialize(t *testing.T) {
	tests := []struct {
		name           string
		config         Config
		wantErr        bool
		expectedErrMsg string
		expectedConfig Config
	}{
		{
			name: "empty provider name",
			config: Config{
				Provider: ProviderConfig{
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr:        true,
			expectedErrMsg: "provider.name must be set",
		},
		{
			name: "valid config with all fields",
			config: Config{
				Provider: ProviderConfig{
					Name:                "google",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{"example\\.com", "test\\.org"},
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{"https://example\\.com/.*", "https://test\\.org/.*"},
					CORS:                true,
				},
				Server: ServerConfig{
					Addr: ":9090",
				},
			},
			wantErr: false,
			expectedConfig: Config{
				Provider: ProviderConfig{
					Name:                "google",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{"example\\.com", "test\\.org"},
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{"https://example\\.com/.*", "https://test\\.org/.*"},
					Hosts:               []*HostConfig{},
					CORS:                true,
				},
				Server: ServerConfig{
					Addr: ":9090",
				},
			},
		},
		{
			name: "config with defaults applied",
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr: false,
			expectedConfig: Config{
				Provider: ProviderConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts:               []*HostConfig{},
				},
				Server: ServerConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "missing client ID",
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientSecret: "test-client-secret",
				},
			},
			wantErr:        true,
			expectedErrMsg: "provider.clientID must be set",
		},
		{
			name: "missing client secret",
			config: Config{
				Provider: ProviderConfig{
					Name:     "test-provider",
					ClientID: "test-client-id",
				},
			},
			wantErr:        true,
			expectedErrMsg: "provider.clientSecret must be set",
		},
		{
			name: "invalid regex in allowed email domains",
			config: Config{
				Provider: ProviderConfig{
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
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{"[invalid-regex"},
				},
			},
			wantErr:        true,
			expectedErrMsg: "failed to build regex list for allowed redirect URLs",
		},
		{
			name: "config with nil hosts - initializes empty slice",
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: ProxyConfig{
					Hosts: nil,
				},
			},
			wantErr: false,
			expectedConfig: Config{
				Provider: ProviderConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts:               []*HostConfig{},
				},
				Server: ServerConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "config with hosts having valid endpoints",
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: ProxyConfig{
					Hosts: []*HostConfig{
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
			expectedConfig: Config{
				Provider: ProviderConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts: []*HostConfig{
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
				Server: ServerConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "config with hosts missing endpoint - should be valid now",
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: ProxyConfig{
					Hosts: []*HostConfig{
						{
							Host:     "example.com",
							Endpoint: "", // Missing endpoint is now valid
						},
					},
				},
			},
			wantErr: false,
			expectedConfig: Config{
				Provider: ProviderConfig{
					Name:                "test-provider",
					ClientID:            "test-client-id",
					ClientSecret:        "test-client-secret",
					AllowedEmailDomains: []string{},
				},
				Proxy: ProxyConfig{
					AllowedRedirectURLs: []string{},
					Hosts: []*HostConfig{
						{
							Host:     "example.com",
							Endpoint: "",
						},
					},
				},
				Server: ServerConfig{
					Addr: ":8080",
				},
			},
		},
		{
			name: "config with hosts missing host - validation error",
			config: Config{
				Provider: ProviderConfig{
					Name:         "test-provider",
					ClientID:     "test-client-id",
					ClientSecret: "test-client-secret",
				},
				Proxy: ProxyConfig{
					Hosts: []*HostConfig{
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

			err := tt.config.ValidateAndInitialize()

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
