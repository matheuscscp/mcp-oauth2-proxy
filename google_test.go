package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestGoogleProvider_oauth2Config(t *testing.T) {
	g := NewWithT(t)

	provider := &googleProvider{}
	config := provider.oauth2Config()

	g.Expect(config).ToNot(BeNil())
	g.Expect(config.Endpoint).To(Equal(google.Endpoint))
	g.Expect(config.Scopes).To(Equal([]string{"email"}))
}

func TestGoogleProvider_verifyUser(t *testing.T) {
	tests := []struct {
		name             string
		userInfoResponse map[string]any
		rawJSON          string // For testing malformed JSON
		userInfoStatus   int
		validateEmail    func(email string) bool
		expectedUser     string
		expectedError    string
	}{
		{
			name: "valid verified user",
			userInfoResponse: map[string]any{
				"email":          "user@example.com",
				"email_verified": true,
			},
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return email == "user@example.com"
			},
			expectedUser: "user@example.com",
		},
		{
			name: "unverified email",
			userInfoResponse: map[string]any{
				"email":          "user@example.com",
				"email_verified": false,
			},
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return true
			},
			expectedError: "google email 'user@example.com' is not verified",
		},
		{
			name: "domain not allowed",
			userInfoResponse: map[string]any{
				"email":          "user@forbidden.com",
				"email_verified": true,
			},
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return email == "user@example.com" // Only allow example.com
			},
			expectedError: "the domain of the email 'user@forbidden.com' is not allowed",
		},
		{
			name:           "userinfo API error",
			userInfoStatus: http.StatusInternalServerError,
			validateEmail: func(email string) bool {
				return true
			},
			expectedError: "userinfo: 500 Internal Server Error",
		},
		{
			name: "missing fields JSON response",
			userInfoResponse: map[string]any{
				"invalid": "json",
			},
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return true
			},
			// This will succeed but with empty email, which will fail email verification
			expectedError: "google email '' is not verified",
		},
		{
			name:           "malformed JSON response",
			rawJSON:        `{"email": "user@example.com", "email_verified": true, invalid json`,
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return true
			},
			expectedError: "error unmarshaling claims from google id token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Create a mock server for the userinfo endpoint
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check that we're calling the right endpoint path
				g.Expect(r.URL.Path).To(Equal("/v1/userinfo"))

				// Check authorization header
				auth := r.Header.Get("Authorization")
				g.Expect(auth).To(Equal("Bearer test-token"))

				w.WriteHeader(tt.userInfoStatus)
				if tt.rawJSON != "" {
					w.Write([]byte(tt.rawJSON))
				} else if tt.userInfoResponse != nil {
					json.NewEncoder(w).Encode(tt.userInfoResponse)
				}
			}))
			defer server.Close()

			// Create a mock token source
			tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: "test-token",
				TokenType:   "Bearer",
			})

			// Create provider with mock validation function
			provider := &googleProvider{
				validateEmailDomain: tt.validateEmail,
			}

			// Override the Google userinfo URL to use our test server
			// We need to create a custom HTTP client that redirects the userinfo call
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &mockTransport{
					server: server,
				},
			})

			user, err := provider.verifyUser(ctx, tokenSource)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(user).To(Equal(tt.expectedUser))
			}
		})
	}
}

func TestGoogleProvider_verifyUser_NetworkError(t *testing.T) {
	g := NewWithT(t)

	// Create provider
	provider := &googleProvider{
		validateEmailDomain: func(email string) bool {
			return true
		},
	}

	// Create a mock token source
	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
	})

	// Use a context with a client that will fail
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &mockTransport{
			shouldFail: true,
		},
	})

	_, err := provider.verifyUser(ctx, tokenSource)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("userinfo request failed"))
}

func TestGoogleProvider_Integration(t *testing.T) {
	g := NewWithT(t)

	// Test the integration between newProvider and googleProvider
	config := &config{
		Provider: providerConfig{
			Name:                "google",
			AllowedEmailDomains: []string{"example\\.com"},
		},
	}

	// Initialize the regex patterns (normally done by validateAndInitialize)
	config.Provider.regexAllowedEmailDomains = make([]*regexp.Regexp, 0)
	for _, pattern := range config.Provider.AllowedEmailDomains {
		regex, err := regexp.Compile(pattern)
		g.Expect(err).ToNot(HaveOccurred())
		config.Provider.regexAllowedEmailDomains = append(config.Provider.regexAllowedEmailDomains, regex)
	}

	provider, err := newProvider(config)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(provider).ToNot(BeNil())

	// Test oauth2Config
	oauth2Config := provider.oauth2Config()
	g.Expect(oauth2Config.Endpoint).To(Equal(google.Endpoint))
	g.Expect(oauth2Config.Scopes).To(Equal([]string{"email"}))

	// Test verifyUser with mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"email":          "user@example.com",
			"email_verified": true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
	})

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &mockTransport{server: server},
	})

	user, err := provider.verifyUser(ctx, tokenSource)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(user).To(Equal("user@example.com"))
}
