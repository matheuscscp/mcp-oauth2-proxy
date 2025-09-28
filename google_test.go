package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
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
		name                string
		userInfoResponse    map[string]any
		rawJSON             string // For testing malformed JSON
		userInfoStatus      int
		validateEmail       func(email string) bool
		setupMetadataServer bool // Whether to setup a metadata server
		metadataServerFails bool // Whether metadata server should fail
		expectedUser        *userInfo
		expectedError       string
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
			expectedUser: &userInfo{username: "user@example.com"},
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
			expectedError: "the Google email 'user@example.com' is not verified",
		},
		{
			name: "domain not allowed",
			userInfoResponse: map[string]any{
				"email":          "user@forbidden.com",
				"email_verified": true,
			},
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return email == "user@example.com"
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
			expectedError: "the Google email '' is not verified",
		},
		{
			name:           "malformed JSON response",
			rawJSON:        `{"email": "user@example.com", "email_verified": true, invalid json`,
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return true
			},
			expectedError: "failed to unmarshal claims from Google userinfo response",
		},
		{
			name: "valid user with metadata server failure during workspace verification",
			userInfoResponse: map[string]any{
				"email":          "user@example.com",
				"email_verified": true,
			},
			userInfoStatus: http.StatusOK,
			validateEmail: func(email string) bool {
				return email == "user@example.com"
			},
			setupMetadataServer: true,
			metadataServerFails: true,
			expectedError:       "failed to verify Google Workspace user info: failed to get Google Service Account email from environment: failed to get default Service Account email from metadata server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Setup mock metadata server if needed
			if tt.setupMetadataServer {
				metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Check for expected metadata server headers
					if r.Header.Get("Metadata-Flavor") != "Google" {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					// Handle the OnGCE check endpoint
					if r.URL.Path == "/" {
						w.Header().Set("Metadata-Flavor", "Google")
						w.WriteHeader(http.StatusOK)
						return
					}

					// Handle the email endpoint
					if r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/email" {
						if tt.metadataServerFails {
							w.WriteHeader(http.StatusInternalServerError)
						} else {
							w.WriteHeader(http.StatusOK)
							w.Write([]byte("test-sa@project.iam.gserviceaccount.com"))
						}
						return
					}

					// Default to 404 for unexpected paths
					w.WriteHeader(http.StatusNotFound)
				}))
				defer metadataServer.Close()

				// Set the GCE_METADATA_HOST environment variable to our mock server
				gceMetadataHost := strings.TrimPrefix(metadataServer.URL, "http://")
				t.Setenv("GCE_METADATA_HOST", gceMetadataHost)
			}

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

func TestGoogleProvider_getServiceAccountEmailFromEnv(t *testing.T) {
	tests := []struct {
		name                string
		setupMetadataServer bool   // Whether to setup a GCE metadata server
		metadataEmail       string // Email returned by metadata server
		metadataStatus      int    // HTTP status from metadata server
		setupADC            bool   // Whether to setup Application Default Credentials
		adcContent          string // Content of the ADC JSON file
		changeHome          bool   // Whether to change HOME to avoid real credentials
		expectedEmail       string
		expectedError       string
	}{
		// GCE Metadata Server scenarios
		{
			name:                "GCE metadata - valid email",
			setupMetadataServer: true,
			metadataEmail:       "test-sa@project.iam.gserviceaccount.com",
			metadataStatus:      http.StatusOK,
			expectedEmail:       "test-sa@project.iam.gserviceaccount.com",
		},
		{
			name:                "GCE metadata - invalid email format",
			setupMetadataServer: true,
			metadataEmail:       "not-an-email",
			metadataStatus:      http.StatusOK,
			expectedEmail:       "",
		},
		{
			name:                "GCE metadata - server error",
			setupMetadataServer: true,
			metadataStatus:      http.StatusInternalServerError,
			expectedError:       "failed to get default Service Account email from metadata server",
		},
		{
			name:                "GCE metadata - not found",
			setupMetadataServer: true,
			metadataStatus:      http.StatusNotFound,
			expectedError:       "failed to get default Service Account email from metadata server",
		},
		// Application Default Credentials scenarios
		{
			name:     "ADC - service account with client_email",
			setupADC: true,
			adcContent: `{
				"type": "service_account",
				"project_id": "test-project",
				"private_key_id": "key-id",
				"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0K0NboKIKyaVuPzk6R5CnUlpGPi\nDxpBaKthDXuBevXJdlROvRVbqioXBwKhZ7MqVRaLdcJoKvfMNfJQhw2hgDxLEyK8\nOL0BJ7Xqd5CxiRuO7ukqIfTO11s/xvqFiWIULXOQKnRYKKT7MxDvH8FIg8Xn6DYY\nKKaw8SxoGz+9yCO4BbdEeClj9xikale9i2rCzoaeH2gHCGJzaSUvTgBj06v8U7xr\nhzmN7F3lwbZGpVKnGgKGmDgzVNb8GUWL4iJCuSjUHvBXlMUDp0qkWyA0mHJjJGH0\ngDgT5XJ3BJksNEzCJ9SOMWnYHgzYRtkgNGnT6QIDAQABAoIBAQDI6vXXpNlLFeKC\nqTBTSI/YJehJODKmUEsuFH6sMGR/qJ9lwH0fS2et+mVkP5pQZKpRAqajsVq7wq13\nj/xBsMhXjviLJBTqGQAqlFomgqEHU5DEKQGVPxfKOSfzG3vs5KJqo1FPGxSS8moZ\nkfQV9iPJTTLJC2VLzELpMVFTNKvY0gxSN8xZqupCwcCLwI8KJVQdwbUwQRSJXJ7b\nBSfCPXmU4UQOW3HJAWbBQKJJWzPQJ6nEP5YxEfqUc1dAYL5KaBxhFXLpGLFNJ+Zg\nj8gfKKDNIJgenvgZnxphEladG1mi1qdjcOTJbGqkqVG3u7BhNRaOFpnXzuqJEtX0\njc5awolJAoGBAPJpCwMqHyETKMj8HwfNSI6r/7fgM2Cq7bXtGN8tBOIiMXKmT4MA\nBWmz1lc2CEPBpCeBfsCSdMXEkzD6BA8KW+qKmJx6GShqvQt6CGPdkjOFSVaK7y/i\njpqxQR4cH6IffJ4PuRG+Hhgr5M9bOApyqoscQ4h9mliG5xfTLxzK/9VvAoGBANzz\nGoij/HLdRO3mCrj9jTMbrHaBzIuAYXKsFfqVYP2cTVCn0vrq4v6VmeXpGblAC4yP\nvC1hGjJJxMrPWJaSKNMfaSkBj8UEFDz0kzJ3hMkVGNU1kRH6wSpKGQxYwInm5VKJ\nNlMTBZ3BBA8SbF5q3QYvfp8k7XYGJxMvW5PghmuXAoGBAOSYvPCCLJq4QQCJlfo/\nEZ2+xBgAMjsrQNfVvgqUG2cE4AKSenoVGKxwa5CDG4zz+omx3lLxGAoC+nPKqVDB\nfQvF7tJ5IIYMQE2dITkKdS0MhRfs8xJM/mLqHZOPLQkpGxPfGCOWKHKUOPf9+e7j\n7qLEfOJ4KCT2gQcAZ5VvevNPAoGAc9OfrGATr5sb4EgXEFblwWRDNtwt3kZOr8xm\n5Zf5ppam1Ba5m8JOJY3qgGnYFQFRthWJ4dBOMkNZNXwNMM/vGcfLKk/KTPQG2REw\ntTzVLLbmtRjL1OhVxnMT+T8L1AvdX9iG5QEJaZGQYcsZ6jdJqXg9DiKSkZPA9tN8\nISAhuJUCgYBwLVWp+X8cBLgs/1IeD3fNBHkrLAgp8WL/YZDNFuDEQGIXiKK1QrTX\nDB2BlXLp5mxANqvKz8Q0mGlQpEKHbVMj0MvYRkAgjwDNiDdcrAL/8BvIJPReT/lJ\nmve1Em4TLwO2GebLQRvNLVPGBLz4bPgTVGcXYMpbPFNNfBPmgg4nDA==\n-----END RSA PRIVATE KEY-----\n",
				"client_email": "test-sa@test-project.iam.gserviceaccount.com",
				"client_id": "123456789",
				"auth_uri": "https://accounts.google.com/o/oauth2/auth",
				"token_uri": "https://oauth2.googleapis.com/token"
			}`,
			expectedEmail: "test-sa@test-project.iam.gserviceaccount.com",
		},
		{
			name:     "ADC - workload identity with impersonation URL",
			setupADC: true,
			adcContent: `{
				"type": "external_account",
				"audience": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
				"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
				"token_url": "https://sts.googleapis.com/v1/token",
				"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/impersonated-sa@test-project.iam.gserviceaccount.com:generateAccessToken",
				"credential_source": {
					"file": "/var/run/secrets/tokens/gcp-ksa/token"
				}
			}`,
			expectedEmail: "impersonated-sa@test-project.iam.gserviceaccount.com",
		},
		{
			name:     "ADC - authorized user credentials (no service account)",
			setupADC: true,
			adcContent: `{
				"type": "authorized_user",
				"client_id": "client-id.apps.googleusercontent.com",
				"client_secret": "client-secret",
				"refresh_token": "refresh-token"
			}`,
			expectedEmail: "",
		},
		{
			name:     "ADC - invalid impersonation URL format",
			setupADC: true,
			adcContent: `{
				"type": "external_account",
				"audience": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
				"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
				"token_url": "https://sts.googleapis.com/v1/token",
				"service_account_impersonation_url": "https://invalid.url/format",
				"credential_source": {
					"file": "/var/run/secrets/tokens/gcp-ksa/token"
				}
			}`,
			expectedError: "invalid Service Account impersonation URL",
		},
		{
			name:          "ADC - malformed JSON",
			setupADC:      true,
			adcContent:    `{"type": "service_account", invalid json`,
			expectedError: "failed to find default credentials",
		},
		{
			name:          "ADC - empty JSON",
			setupADC:      true,
			adcContent:    ``,
			expectedError: "failed to find default credentials",
		},
		// No credentials scenario
		{
			name:          "no credentials available",
			expectedEmail: "",
			changeHome:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			g.Expect(tt.setupADC && tt.setupMetadataServer).To(BeFalse())

			// Setup mock metadata server if needed
			if tt.setupMetadataServer {
				metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Check for expected metadata server headers
					if r.Header.Get("Metadata-Flavor") != "Google" {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					// Handle the OnGCE check endpoint
					if r.URL.Path == "/" {
						w.Header().Set("Metadata-Flavor", "Google")
						w.WriteHeader(http.StatusOK)
						return
					}

					// Handle the email endpoint
					if r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/email" {
						w.WriteHeader(tt.metadataStatus)
						if tt.metadataStatus == http.StatusOK {
							w.Write([]byte(tt.metadataEmail))
						}
						return
					}

					// Default to 404 for unexpected paths
					w.WriteHeader(http.StatusNotFound)
				}))
				defer metadataServer.Close()

				// Set the GCE_METADATA_HOST environment variable to our mock server
				gceMetadataHost := strings.TrimPrefix(metadataServer.URL, "http://")
				t.Setenv("GCE_METADATA_HOST", gceMetadataHost)
			}

			// Setup Application Default Credentials if needed
			if tt.setupADC {
				// Create a temporary JSON file
				tmpFile, err := os.CreateTemp("", "test-creds-*.json")
				g.Expect(err).ToNot(HaveOccurred())
				defer os.Remove(tmpFile.Name())

				// Write the JSON content
				_, err = tmpFile.WriteString(tt.adcContent)
				g.Expect(err).ToNot(HaveOccurred())
				tmpFile.Close()

				// Set GOOGLE_APPLICATION_CREDENTIALS to point to the temp file
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile.Name())
			}

			if tt.changeHome {
				t.Setenv("HOME", t.TempDir())
			}

			provider := &googleProvider{}
			email, err := provider.getServiceAccountEmailFromEnv(context.Background())

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(email).To(Equal(tt.expectedEmail))
			}
		})
	}
}

func TestGoogleProvider_newUserClient(t *testing.T) {
	tests := []struct {
		name                  string
		userEmail             string
		serviceAccountEmail   string
		iamSignJWTStatus      int
		iamSignJWTResponse    map[string]any
		tokenExchangeStatus   int
		tokenExchangeResponse map[string]any
		transportFailOnHost   string // Simulate transport failures for specific hosts
		cancelContext         bool   // Whether to cancel the context before the call
		expectedError         string
	}{
		{
			name:                "successful client creation",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			iamSignJWTResponse: map[string]any{
				"signedJwt": "signed.jwt.token",
			},
			tokenExchangeStatus: http.StatusOK,
			tokenExchangeResponse: map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			},
		},
		{
			name:                "IAM SignJWT API failure",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusForbidden,
			expectedError:       "failed to sign JWT using Google IAM Credentials API",
		},
		{
			name:                "token exchange failure - bad status",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			iamSignJWTResponse: map[string]any{
				"signedJwt": "signed.jwt.token",
			},
			tokenExchangeStatus: http.StatusUnauthorized,
			expectedError:       "failed to exchange signed JWT for OAuth2 token: 401 Unauthorized",
		},
		{
			name:                "malformed token JSON response",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			iamSignJWTResponse: map[string]any{
				"signedJwt": "signed.jwt.token",
			},
			tokenExchangeStatus: http.StatusOK,
			// tokenExchangeResponse is nil - will send malformed JSON
			expectedError: "failed to decode OAuth2 token response",
		},
		{
			name:                "network error during token exchange",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			iamSignJWTResponse: map[string]any{
				"signedJwt": "signed.jwt.token",
			},
			// Special status code to trigger network error
			tokenExchangeStatus: -1,
			expectedError:       "failed to exchange signed JWT for OAuth2 token",
		},
		{
			name:                "token response without access_token",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			iamSignJWTResponse: map[string]any{
				"signedJwt": "signed.jwt.token",
			},
			tokenExchangeStatus: http.StatusOK,
			tokenExchangeResponse: map[string]any{
				// Missing access_token makes the token invalid
				"token_type": "Bearer",
				"expires_in": 3600,
			},
			expectedError: "received invalid OAuth2 token",
		},
		{
			name:                "context cancelled before call",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			cancelContext:       true,
			expectedError:       "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Track which APIs have been called
			var iamCalled, tokenExchangeCalled bool

			// Create a test server to mock Google APIs
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				// Mock IAM SignJWT API
				case strings.Contains(r.URL.Path, "/v1/projects/-/serviceAccounts/") && strings.Contains(r.URL.Path, ":signJwt"):
					iamCalled = true

					// Handle special case for network error simulation
					if tt.iamSignJWTStatus == -1 {
						// Abruptly close the connection to simulate network error
						hj, ok := w.(http.Hijacker)
						if ok {
							conn, _, _ := hj.Hijack()
							conn.Close()
						}
						return
					}

					// Verify the request
					g.Expect(r.Method).To(Equal(http.MethodPost))

					var reqBody map[string]any
					json.NewDecoder(r.Body).Decode(&reqBody)
					g.Expect(reqBody).To(HaveKey("payload"))

					// Parse and verify JWT claims
					var claims map[string]any
					json.Unmarshal([]byte(reqBody["payload"].(string)), &claims)
					g.Expect(claims["iss"]).To(Equal(tt.serviceAccountEmail))
					g.Expect(claims["sub"]).To(Equal(tt.userEmail))
					g.Expect(claims["aud"]).To(Equal("https://oauth2.googleapis.com/token"))
					g.Expect(claims).To(HaveKey("jti"))
					g.Expect(claims).To(HaveKey("iat"))
					g.Expect(claims).To(HaveKey("nbf"))
					g.Expect(claims).To(HaveKey("exp"))
					// The actual order is user.readonly then group.readonly
					g.Expect(claims["scope"]).To(Equal("https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.readonly"))

					w.WriteHeader(tt.iamSignJWTStatus)
					if tt.iamSignJWTResponse != nil {
						json.NewEncoder(w).Encode(tt.iamSignJWTResponse)
					}

				// Mock OAuth2 token exchange
				case r.URL.Path == "/token":
					tokenExchangeCalled = true

					// Handle special case for network error simulation
					if tt.tokenExchangeStatus == -1 {
						// Abruptly close the connection to simulate network error
						hj, ok := w.(http.Hijacker)
						if ok {
							conn, _, _ := hj.Hijack()
							conn.Close()
						}
						return
					}

					// Verify the request
					g.Expect(r.Method).To(Equal(http.MethodPost))
					g.Expect(r.Header.Get("Content-Type")).To(Equal("application/x-www-form-urlencoded"))

					r.ParseForm()
					g.Expect(r.Form.Get("grant_type")).To(Equal("urn:ietf:params:oauth:grant-type:jwt-bearer"))
					if tt.iamSignJWTResponse != nil && tt.iamSignJWTResponse["signedJwt"] != nil {
						g.Expect(r.Form.Get("assertion")).To(Equal(tt.iamSignJWTResponse["signedJwt"]))
					}

					w.WriteHeader(tt.tokenExchangeStatus)
					if tt.tokenExchangeResponse != nil {
						json.NewEncoder(w).Encode(tt.tokenExchangeResponse)
					} else if tt.tokenExchangeStatus == http.StatusOK {
						// Send malformed JSON for testing decode errors
						w.Write([]byte("{invalid json"))
					}

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Create a mock HTTP client that redirects to our test server
			mockClient := &http.Client{
				Transport: &googleMockTransport{
					testServer: server,
					failOnHost: tt.transportFailOnHost,
				},
			}

			// Create context with mock HTTP client
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, mockClient)

			// Cancel the context if requested
			if tt.cancelContext {
				cancelCtx, cancel := context.WithCancel(ctx)
				cancel() // Cancel immediately
				ctx = cancelCtx
			}

			// Call the method under test
			provider := &googleProvider{}
			client, err := provider.newUserClient(ctx, tt.userEmail, tt.serviceAccountEmail)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
				g.Expect(client).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(client).ToNot(BeNil())

				// Verify that the expected APIs were called
				g.Expect(iamCalled).To(BeTrue())
				g.Expect(tokenExchangeCalled).To(BeTrue())
			}
		})
	}
}

// googleMockTransport is a custom transport for testing Google API calls
type googleMockTransport struct {
	testServer *httptest.Server
	failOnHost string // If set, fail when this host is accessed
}

func (t *googleMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if we should fail on this specific host
	if t.failOnHost != "" && strings.Contains(req.URL.Host, t.failOnHost) {
		return nil, fmt.Errorf("simulated transport failure for %s", req.URL.Host)
	}

	// Redirect all Google API calls to our test server
	if strings.Contains(req.URL.Host, "googleapis.com") ||
		strings.Contains(req.URL.Host, "oauth2.googleapis.com") ||
		strings.Contains(req.URL.Host, "iamcredentials.googleapis.com") {
		// Parse the test server URL and update the request
		testURL, _ := url.Parse(t.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}

	return http.DefaultTransport.RoundTrip(req)
}

func TestGoogleProvider_verifyGoogleWorkspaceUser(t *testing.T) {
	tests := []struct {
		name                string
		userEmail           string
		serviceAccountEmail string // Empty means no service account
		setupMetadataServer bool
		metadataEmail       string
		userAPIResponse     map[string]any
		userAPIStatus       int
		groupsAPIResponse   map[string]any
		groupsAPIStatus     int
		iamSignJWTStatus    int
		tokenExchangeStatus int
		expectedGroups      []string
		expectedError       string
	}{
		{
			name:                "no service account configured",
			userEmail:           "user@example.com",
			serviceAccountEmail: "", // No service account
			expectedGroups:      nil,
		},
		{
			name:                "successful workspace verification with groups",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    false,
				"archived":     false,
			},
			groupsAPIStatus: http.StatusOK,
			groupsAPIResponse: map[string]any{
				"groups": []map[string]any{
					{"email": "group1@example.com"},
					{"email": "group2@example.com"},
					{"email": "admins@example.com"},
				},
			},
			expectedGroups: []string{"group1@example.com", "group2@example.com", "admins@example.com"},
		},
		{
			name:                "successful workspace verification no groups",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    false,
				"archived":     false,
			},
			groupsAPIStatus: http.StatusOK,
			groupsAPIResponse: map[string]any{
				"groups": []map[string]any{},
			},
			expectedGroups: nil, // No groups returns nil, not empty slice
		},
		{
			name:                "user suspended",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    true,
				"archived":     false,
			},
			expectedError: "the Google user 'user@example.com' is archived, suspended or deleted",
		},
		{
			name:                "user archived",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    false,
				"archived":     true,
			},
			expectedError: "the Google user 'user@example.com' is archived, suspended or deleted",
		},
		{
			name:                "user deleted",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    false,
				"archived":     false,
				"deletionTime": "2024-01-01T00:00:00Z",
			},
			expectedError: "the Google user 'user@example.com' is archived, suspended or deleted",
		},
		{
			name:                "user not found",
			userEmail:           "nonexistent@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusNotFound,
			expectedError:       "failed to get Google user 'nonexistent@example.com'",
		},
		{
			name:                "groups API failure",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    false,
				"archived":     false,
			},
			groupsAPIStatus: http.StatusInternalServerError,
			expectedError:   "failed to list groups for Google user 'user@example.com'",
		},
		{
			name:                "newUserClient failure",
			userEmail:           "user@example.com",
			serviceAccountEmail: "sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusForbidden,
			expectedError:       "failed to create Google Admin API client for user user@example.com",
		},
		{
			name:                "service account from metadata server",
			userEmail:           "user@example.com",
			setupMetadataServer: true,
			metadataEmail:       "metadata-sa@project.iam.gserviceaccount.com",
			iamSignJWTStatus:    http.StatusOK,
			tokenExchangeStatus: http.StatusOK,
			userAPIStatus:       http.StatusOK,
			userAPIResponse: map[string]any{
				"primaryEmail": "user@example.com",
				"suspended":    false,
				"archived":     false,
			},
			groupsAPIStatus: http.StatusOK,
			groupsAPIResponse: map[string]any{
				"groups": []map[string]any{
					{"email": "developers@example.com"},
				},
			},
			expectedGroups: []string{"developers@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Setup mock metadata server if needed
			if tt.setupMetadataServer {
				metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Metadata-Flavor") != "Google" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if r.URL.Path == "/" {
						w.Header().Set("Metadata-Flavor", "Google")
						w.WriteHeader(http.StatusOK)
						return
					}
					if r.URL.Path == "/computeMetadata/v1/instance/service-accounts/default/email" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(tt.metadataEmail))
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer metadataServer.Close()

				gceMetadataHost := strings.TrimPrefix(metadataServer.URL, "http://")
				t.Setenv("GCE_METADATA_HOST", gceMetadataHost)
			}

			// Create test server to mock Google APIs
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				// Mock IAM SignJWT API
				case strings.Contains(r.URL.Path, "/v1/projects/-/serviceAccounts/") && strings.Contains(r.URL.Path, ":signJwt"):
					w.WriteHeader(tt.iamSignJWTStatus)
					if tt.iamSignJWTStatus == http.StatusOK {
						json.NewEncoder(w).Encode(map[string]any{
							"signedJwt": "signed.jwt.token",
						})
					}

				// Mock OAuth2 token exchange
				case r.URL.Path == "/token":
					w.WriteHeader(tt.tokenExchangeStatus)
					if tt.tokenExchangeStatus == http.StatusOK {
						json.NewEncoder(w).Encode(map[string]any{
							"access_token": "test-access-token",
							"token_type":   "Bearer",
							"expires_in":   3600,
						})
					}

				// Mock Admin API - Get User
				case strings.Contains(r.URL.Path, "/admin/directory/v1/users/"):
					w.WriteHeader(tt.userAPIStatus)
					if tt.userAPIResponse != nil {
						json.NewEncoder(w).Encode(tt.userAPIResponse)
					}

				// Mock Admin API - List Groups
				case strings.Contains(r.URL.Path, "/admin/directory/v1/groups"):
					w.WriteHeader(tt.groupsAPIStatus)
					if tt.groupsAPIResponse != nil {
						json.NewEncoder(w).Encode(tt.groupsAPIResponse)
					}

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Create mock HTTP client
			mockClient := &http.Client{
				Transport: &googleMockTransport{
					testServer: server,
				},
			}
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, mockClient)

			// Setup environment for service account configuration
			if tt.serviceAccountEmail != "" && !tt.setupMetadataServer {
				// Create temporary credentials file for ADC
				tmpFile, err := os.CreateTemp("", "test-creds-*.json")
				g.Expect(err).ToNot(HaveOccurred())
				defer os.Remove(tmpFile.Name())

				credentialsJSON := fmt.Sprintf(`{
					"type": "service_account",
					"project_id": "test-project",
					"private_key_id": "key-id",
					"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0K0NboKIKyaVuPzk6R5CnUlpGPi\nDxpBaKthDXuBevXJdlROvRVbqioXBwKhZ7MqVRaLdcJoKvfMNfJQhw2hgDxLEyK8\nOL0BJ7Xqd5CxiRuO7ukqIfTO11s/xvqFiWIULXOQKnRYKKT7MxDvH8FIg8Xn6DYY\nKKaw8SxoGz+9yCO4BbdEeClj9xikale9i2rCzoaeH2gHCGJzaSUvTgBj06v8U7xr\nhzmN7F3lwbZGpVKnGgKGmDgzVNb8GUWL4iJCuSjUHvBXlMUDp0qkWyA0mHJjJGH0\ngDgT5XJ3BJksNEzCJ9SOMWnYHgzYRtkgNGnT6QIDAQABAoIBAQDI6vXXpNlLFeKC\nqTBTSI/YJehJODKmUEsuFH6sMGR/qJ9lwH0fS2et+mVkP5pQZKpRAqajsVq7wq13\nj/xBsMhXjviLJBTqGQAqlFomgqEHU5DEKQGVPxfKOSfzG3vs5KJqo1FPGxSS8moZ\nkfQV9iPJTTLJC2VLzELpMVFTNKvY0gxSN8xZqupCwcCLwI8KJVQdwbUwQRSJXJ7b\nBSfCPXmU4UQOW3HJAWbBQKJJWzPQJ6nEP5YxEfqUc1dAYL5KaBxhFXLpGLFNJ+Zg\nj8gfKKDNIJgenvgZnxphEladG1mi1qdjcOTJbGqkqVG3u7BhNRaOFpnXzuqJEtX0\njc5awolJAoGBAPJpCwMqHyETKMj8HwfNSI6r/7fgM2Cq7bXtGN8tBOIiMXKmT4MA\nBWmz1lc2CEPBpCeBfsCSdMXEkzD6BA8KW+qKmJx6GShqvQt6CGPdkjOFSVaK7y/i\njpqxQR4cH6IffJ4PuRG+Hhgr5M9bOApyqoscQ4h9mliG5xfTLxzK/9VvAoGBANzz\nGoij/HLdRO3mCrj9jTMbrHaBzIuAYXKsFfqVYP2cTVCn0vrq4v6VmeXpGblAC4yP\nvC1hGjJJxMrPWJaSKNMfaSkBj8UEFDz0kzJ3hMkVGNU1kRH6wSpKGQxYwInm5VKJ\nNlMTBZ3BBA8SbF5q3QYvfp8k7XYGJxMvW5PghmuXAoGBAOSYvPCCLJq4QQCJlfo/\nEZ2+xBgAMjsrQNfVvgqUG2cE4AKSenoVGKxwa5CDG4zz+omx3lLxGAoC+nPKqVDB\nfQvF7tJ5IIYMQE2dITkKdS0MhRfs8xJM/mLqHZOPLQkpGxPfGCOWKHKUOPf9+e7j\n7qLEfOJ4KCT2gQcAZ5VvevNPAoGAc9OfrGATr5sb4EgXEFblwWRDNtwt3kZOr8xm\n5Zf5ppam1Ba5m8JOJY3qgGnYFQFRthWJ4dBOMkNZNXwNMM/vGcfLKk/KTPQG2REw\ntTzVLLbmtRjL1OhVxnMT+T8L1AvdX9iG5QEJaZGQYcsZ6jdJqXg9DiKSkZPA9tN8\nISAhuJUCgYBwLVWp+X8cBLgs/1IeD3fNBHkrLAgp8WL/YZDNFuDEQGIXiKK1QrTX\nDB2BlXLp5mxANqvKz8Q0mGlQpEKHbVMj0MvYRkAgjwDNiDdcrAL/8BvIJPReT/lJ\nmve1Em4TLwO2GebLQRvNLVPGBLz4bPgTVGcXYMpbPFNNfBPmgg4nDA==\n-----END RSA PRIVATE KEY-----\n",
					"client_email": "%s",
					"client_id": "123456789",
					"auth_uri": "https://accounts.google.com/o/oauth2/auth",
					"token_uri": "https://oauth2.googleapis.com/token"
				}`, tt.serviceAccountEmail)

				_, err = tmpFile.WriteString(credentialsJSON)
				g.Expect(err).ToNot(HaveOccurred())
				tmpFile.Close()

				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile.Name())
			}

			if tt.serviceAccountEmail == "" && !tt.setupMetadataServer {
				// Clear environment to simulate no service account
				t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
				t.Setenv("GCE_METADATA_HOST", "")
				t.Setenv("HOME", t.TempDir())
			}

			// Create provider and call method
			provider := &googleProvider{}
			groups, err := provider.verifyGoogleWorkspaceUser(ctx, tt.userEmail)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
				g.Expect(groups).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				if tt.expectedGroups == nil {
					g.Expect(groups).To(BeNil())
				} else {
					g.Expect(groups).To(Equal(tt.expectedGroups))
				}
			}
		})
	}
}

func TestGoogleProvider_Integration(t *testing.T) {
	g := NewWithT(t)

	// Test the integration between newProvider and googleProvider
	config := &config.Config{
		Provider: config.ProviderConfig{
			Name:                "google",
			ClientID:            "mock",
			ClientSecret:        "mock",
			AllowedEmailDomains: []string{"example\\.com"},
		},
	}

	err := config.ValidateAndInitialize()
	g.Expect(err).ToNot(HaveOccurred())

	provider, err := newProvider(&config.Provider)
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
	g.Expect(user).To(Equal(&userInfo{username: "user@example.com"}))
}
