package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name         string
		config       *config
		expectError  bool
		expectedType string
	}{
		{
			name: "google provider",
			config: &config{
				Provider: providerConfig{
					Name: "google",
				},
			},
			expectError:  false,
			expectedType: "*main.googleProvider",
		},
		{
			name: "github provider",
			config: &config{
				Provider: providerConfig{
					Name: "github",
				},
			},
			expectError:  false,
			expectedType: "main.githubProvider",
		},
		{
			name: "unsupported provider",
			config: &config{
				Provider: providerConfig{
					Name: "unsupported",
				},
			},
			expectError: true,
		},
		{
			name: "empty provider name",
			config: &config{
				Provider: providerConfig{
					Name: "",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			provider, err := newProvider(tt.config)

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

// mockTransport is a custom HTTP transport for testing
type mockTransport struct {
	server     *httptest.Server
	shouldFail bool
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.shouldFail {
		return nil, http.ErrServerClosed // Simulate network error
	}

	// Redirect Google userinfo calls to our test server
	if req.URL.Host == "openidconnect.googleapis.com" {
		// Parse the test server URL to get the correct host
		testURL := m.server.URL + req.URL.Path
		newReq := req.Clone(req.Context())
		newReq.URL, _ = newReq.URL.Parse(testURL)
		return http.DefaultTransport.RoundTrip(newReq)
	}

	// Redirect GitHub API calls to our test server
	if req.URL.Host == "api.github.com" {
		// Parse the test server URL to get the correct host
		testURL := m.server.URL + req.URL.Path
		newReq := req.Clone(req.Context())
		newReq.URL, _ = newReq.URL.Parse(testURL)
		return http.DefaultTransport.RoundTrip(newReq)
	}

	return http.DefaultTransport.RoundTrip(req)
}
