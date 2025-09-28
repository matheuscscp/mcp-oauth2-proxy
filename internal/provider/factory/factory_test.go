package factory

import (
	"testing"

	. "github.com/onsi/gomega"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		config       *config.ProviderConfig
		expectError  bool
		expectedType string
	}{
		{
			name: "google provider",
			config: &config.ProviderConfig{
				Name: "google",
			},
			expectError:  false,
			expectedType: "*main.googleProvider",
		},
		{
			name: "github provider",
			config: &config.ProviderConfig{
				Name: "github",
			},
			expectError:  false,
			expectedType: "main.githubProvider",
		},
		{
			name: "unsupported provider",
			config: &config.ProviderConfig{
				Name: "unsupported",
			},
			expectError: true,
		},
		{
			name: "empty provider name",
			config: &config.ProviderConfig{
				Name: "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			provider, err := New(tt.config)

			if tt.expectError {
				g.Expect(err).To(HaveOccurred())
				g.Expect(provider).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(provider).ToNot(BeNil())
			}
		})
	}
}
