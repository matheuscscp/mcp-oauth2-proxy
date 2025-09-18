package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func TestGitHubProvider_oauth2Config(t *testing.T) {
	g := NewWithT(t)

	provider := githubProvider{}
	config := provider.oauth2Config()

	g.Expect(config).ToNot(BeNil())
	g.Expect(config.Endpoint).To(Equal(github.Endpoint))
}

func TestGitHubProvider_verifyUser(t *testing.T) {
	tests := []struct {
		name          string
		userResponse  map[string]any
		rawJSON       string // For testing malformed JSON
		userStatus    int
		tokenError    bool
		expectedUser  *userInfo
		expectedError string
	}{
		{
			name: "valid user",
			userResponse: map[string]any{
				"login": "testuser",
				"id":    12345,
				"name":  "Test User",
			},
			userStatus:   http.StatusOK,
			expectedUser: &userInfo{username: "testuser"},
		},
		{
			name: "user with nil login",
			userResponse: map[string]any{
				"id":   12345,
				"name": "Test User",
				// no login field
			},
			userStatus:   http.StatusOK,
			expectedUser: &userInfo{username: ""}, // GetLogin() returns empty string for nil
		},
		{
			name:          "token source error",
			tokenError:    true,
			expectedError: "token source error",
		},
		{
			name:          "GitHub API error",
			userStatus:    http.StatusUnauthorized,
			expectedError: "user: 401 Unauthorized",
		},
		{
			name:          "malformed JSON response",
			rawJSON:       `{"login": "testuser", "id": 12345, invalid json`,
			userStatus:    http.StatusOK,
			expectedError: "invalid character 'i'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Create a mock server for the GitHub user endpoint
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check that we're calling the right endpoint path
				g.Expect(r.URL.Path).To(Equal("/user"))

				// Check authorization header
				auth := r.Header.Get("Authorization")
				g.Expect(auth).To(Equal("Bearer test-token"))

				w.WriteHeader(tt.userStatus)
				if tt.rawJSON != "" {
					w.Write([]byte(tt.rawJSON))
				} else if tt.userResponse != nil {
					json.NewEncoder(w).Encode(tt.userResponse)
				}
			}))
			defer server.Close()

			// Create a mock token source
			var tokenSource oauth2.TokenSource
			if tt.tokenError {
				tokenSource = &errorTokenSource{err: &oauth2.RetrieveError{
					ErrorCode:        "invalid_grant",
					ErrorDescription: "token source error",
				}}
			} else {
				tokenSource = oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: "test-token",
					TokenType:   "Bearer",
				})
			}

			// Create provider
			provider := githubProvider{}

			// Override the GitHub API URL to use our test server
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

func TestGitHubProvider_verifyUser_NetworkError(t *testing.T) {
	g := NewWithT(t)

	// Create provider
	provider := githubProvider{}

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
	g.Expect(err.Error()).To(ContainSubstring("http: Server closed"))
}

func TestGitHubProvider_Integration(t *testing.T) {
	g := NewWithT(t)

	// Test the integration between newProvider and githubProvider
	config := &config{
		Provider: providerConfig{
			Name: "github",
		},
	}

	provider, err := newProvider(&config.Provider)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(provider).ToNot(BeNil())

	// Test oauth2Config
	oauth2Config := provider.oauth2Config()
	g.Expect(oauth2Config.Endpoint).To(Equal(github.Endpoint))

	// Test verifyUser with mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"login": "testuser",
			"id":    12345,
			"name":  "Test User",
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
	g.Expect(user).To(Equal(&userInfo{username: "testuser"}))
}

// errorTokenSource is a helper for testing token source errors
type errorTokenSource struct {
	err error
}

func (e *errorTokenSource) Token() (*oauth2.Token, error) {
	return nil, e.err
}
