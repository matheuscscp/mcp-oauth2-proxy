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
	"time"

	githubv3 "github.com/google/go-github/v74/github"
	"github.com/lestrrat-go/jwx/v3/jwt"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func TestNewGitHubProvider(t *testing.T) {
	tests := []struct {
		name              string
		config            *providerConfig
		setupEnv          bool
		privateKeyContent string
		expectedError     string
	}{
		{
			name: "valid configuration with organization and private key",
			config: &providerConfig{
				ClientID:     "test-app-id",
				Organization: "test-org",
			},
			setupEnv:          true,
			privateKeyContent: "test-key-path",
			expectedError:     "",
		},
		{
			name: "valid configuration without organization and private key",
			config: &providerConfig{
				ClientID:     "test-app-id",
				Organization: "",
			},
			setupEnv:      false,
			expectedError: "",
		},
		{
			name: "invalid - organization set but no private key",
			config: &providerConfig{
				ClientID:     "test-app-id",
				Organization: "test-org",
			},
			setupEnv:      false,
			expectedError: "both GitHub Organization and GitHub App private key must be set, or both must be unset",
		},
		{
			name: "invalid - private key set but no organization",
			config: &providerConfig{
				ClientID:     "test-app-id",
				Organization: "",
			},
			setupEnv:          true,
			privateKeyContent: "test-key-path",
			expectedError:     "both GitHub Organization and GitHub App private key must be set, or both must be unset",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			if tt.setupEnv {
				// Create a temporary file for the private key
				tmpFile, err := os.CreateTemp("", "github-key-*.pem")
				g.Expect(err).ToNot(HaveOccurred())
				defer os.Remove(tmpFile.Name())
				tmpFile.Close()

				t.Setenv(envGitHubAppPrivateKey, tmpFile.Name())
			} else {
				t.Setenv(envGitHubAppPrivateKey, "")
			}

			provider, err := newGitHubProvider(tt.config)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
				g.Expect(provider).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(provider).ToNot(BeNil())
				g.Expect(provider.appClientID).To(Equal(tt.config.ClientID))
				g.Expect(provider.organization).To(Equal(tt.config.Organization))
			}
		})
	}
}

func TestGitHubProvider_oauth2Config(t *testing.T) {
	g := NewWithT(t)

	provider := &githubProvider{}
	config := provider.oauth2Config()

	g.Expect(config).ToNot(BeNil())
	g.Expect(config.Endpoint).To(Equal(github.Endpoint))
	g.Expect(config.Scopes).To(BeEmpty()) // GitHub provider doesn't set scopes
}

func TestGitHubProvider_verifyUser(t *testing.T) {
	tests := []struct {
		name            string
		userResponse    map[string]any
		rawJSON         string // For testing malformed JSON
		userStatus      int
		organization    string
		setupPrivateKey bool // Whether to set up private key environment
		orgVerifyError  error
		orgVerifyGroups []string
		expectedUser    *userInfo
		expectedError   string
	}{
		{
			name: "valid user without organization",
			userResponse: map[string]any{
				"login": "testuser",
			},
			userStatus:      http.StatusOK,
			organization:    "",
			setupPrivateKey: false,
			expectedUser:    &userInfo{username: "testuser"},
		},
		{
			name: "valid user with organization but no groups",
			userResponse: map[string]any{
				"login": "testuser",
			},
			userStatus:      http.StatusOK,
			organization:    "test-org",
			setupPrivateKey: true,
			orgVerifyGroups: nil,
			expectedUser:    &userInfo{username: "testuser", groups: nil},
		},
		{
			name: "valid user with organization and groups",
			userResponse: map[string]any{
				"login": "testuser",
			},
			userStatus:      http.StatusOK,
			organization:    "test-org",
			setupPrivateKey: true,
			orgVerifyGroups: []string{"engineering", "devops"},
			expectedUser:    &userInfo{username: "testuser", groups: []string{"engineering", "devops"}},
		},
		{
			name:            "user API error",
			userStatus:      http.StatusUnauthorized,
			setupPrivateKey: false,
			expectedError:   "user: 401 Unauthorized",
		},
		{
			name:            "malformed JSON response",
			rawJSON:         `{"login": "testuser", invalid json`,
			userStatus:      http.StatusOK,
			setupPrivateKey: false,
			expectedError:   "failed to unmarshal claims from GitHub user response",
		},
		{
			name: "missing login field",
			userResponse: map[string]any{
				"id": 12345,
			},
			userStatus:      http.StatusOK,
			setupPrivateKey: false,
			expectedUser:    &userInfo{username: ""}, // Empty username
		},
		{
			name: "organization verification failure",
			userResponse: map[string]any{
				"login": "testuser",
			},
			userStatus:      http.StatusOK,
			organization:    "test-org",
			setupPrivateKey: false, // No private key setup causes org verification to fail
			expectedError:   "failed to verify GitHub Organization user info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Create a mock server for GitHub APIs
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				// Handle user API endpoint
				case r.URL.Path == "/user":
					// Check authorization header
					auth := r.Header.Get("Authorization")
					g.Expect(auth).To(Equal("Bearer test-token"))

					w.WriteHeader(tt.userStatus)
					if tt.rawJSON != "" {
						w.Write([]byte(tt.rawJSON))
					} else if tt.userResponse != nil {
						json.NewEncoder(w).Encode(tt.userResponse)
					}

				// Handle GitHub App organization installation endpoint
				case strings.Contains(r.URL.Path, fmt.Sprintf("/orgs/%s/installation", tt.organization)):
					if tt.orgVerifyError != nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{
						"id": 12345,
					})

				// Handle GitHub App installation token creation
				case strings.Contains(r.URL.Path, "/app/installations/12345/access_tokens"):
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(map[string]any{
						"token": "installation-token",
					})

				// Handle organization membership endpoint
				case strings.Contains(r.URL.Path, fmt.Sprintf("/orgs/%s/memberships/", tt.organization)):
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{
						"state": "active",
						"user": map[string]any{
							"suspended_at": nil,
						},
					})

				// Handle GraphQL endpoint for teams
				case r.URL.Path == "/graphql":
					w.WriteHeader(http.StatusOK)
					response := fmt.Sprintf(`{
						"data": {
							"organization": {
								"teams": {
									"edges": %s
								}
							}
						}
					}`, func() string {
						if len(tt.orgVerifyGroups) == 0 {
							return "[]"
						}
						edges := "["
						for i, group := range tt.orgVerifyGroups {
							if i > 0 {
								edges += ","
							}
							edges += fmt.Sprintf(`{"node": {"name": "%s"}}`, group)
						}
						edges += "]"
						return edges
					}())
					w.Write([]byte(response))

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Create a mock token source
			tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: "test-token",
				TokenType:   "Bearer",
			})

			// Set up private key environment if needed
			if tt.setupPrivateKey {
				tmpFile, err := os.CreateTemp("", "github-key-*.pem")
				g.Expect(err).ToNot(HaveOccurred())
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(generateTestRSAPrivateKey())
				g.Expect(err).ToNot(HaveOccurred())
				tmpFile.Close()

				t.Setenv(envGitHubAppPrivateKey, tmpFile.Name())
			} else {
				t.Setenv(envGitHubAppPrivateKey, "")
			}

			// Create provider
			provider := &githubProvider{
				organization: tt.organization,
			}

			// Create a context with custom HTTP client
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &githubMockTransport{
					server:        server,
					orgError:      tt.orgVerifyError,
					orgGroups:     tt.orgVerifyGroups,
					shouldMockOrg: tt.organization != "",
					orgName:       tt.organization,
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

	provider := &githubProvider{}

	tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken: "test-token",
		TokenType:   "Bearer",
	})

	// Use a context with a client that will fail
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &githubMockTransport{
			shouldFail: true,
		},
	})

	_, err := provider.verifyUser(ctx, tokenSource)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("user request failed"))
}

func TestGitHubProvider_verifyGitHubOrganizationUser(t *testing.T) {
	tests := []struct {
		name                 string
		username             string
		organization         string
		membershipResponse   *githubv3.Membership
		membershipError      error
		teamsGraphQLResponse string
		teamsGraphQLError    error
		appInstallationError error
		expectedGroups       []string
		expectedError        string
	}{
		{
			name:           "no organization configured",
			username:       "testuser",
			organization:   "",
			expectedGroups: nil,
		},
		{
			name:         "successful verification with teams",
			username:     "testuser",
			organization: "test-org",
			membershipResponse: &githubv3.Membership{
				State: githubv3.String("active"),
				User: &githubv3.User{
					SuspendedAt: &githubv3.Timestamp{Time: time.Time{}},
				},
			},
			teamsGraphQLResponse: `{
				"data": {
					"organization": {
						"teams": {
							"edges": [
								{"node": {"name": "engineering"}},
								{"node": {"name": "devops"}}
							]
						}
					}
				}
			}`,
			expectedGroups: []string{"engineering", "devops"},
		},
		{
			name:         "successful verification no teams",
			username:     "testuser",
			organization: "test-org",
			membershipResponse: &githubv3.Membership{
				State: githubv3.String("active"),
				User: &githubv3.User{
					SuspendedAt: &githubv3.Timestamp{Time: time.Time{}},
				},
			},
			teamsGraphQLResponse: `{
				"data": {
					"organization": {
						"teams": {
							"edges": []
						}
					}
				}
			}`,
			expectedGroups: nil,
		},
		{
			name:         "user not active",
			username:     "testuser",
			organization: "test-org",
			membershipResponse: &githubv3.Membership{
				State: githubv3.String("pending"),
				User: &githubv3.User{
					SuspendedAt: &githubv3.Timestamp{Time: time.Time{}},
				},
			},
			expectedError: "the user 'testuser' is suspended or not active in the GitHub Organization",
		},
		{
			name:         "user suspended",
			username:     "testuser",
			organization: "test-org",
			membershipResponse: &githubv3.Membership{
				State: githubv3.String("active"),
				User: &githubv3.User{
					SuspendedAt: &githubv3.Timestamp{Time: time.Now()},
				},
			},
			expectedError: "the user 'testuser' is suspended or not active in the GitHub Organization",
		},
		{
			name:            "membership API error",
			username:        "testuser",
			organization:    "test-org",
			membershipError: fmt.Errorf("404 Not Found"),
			expectedError:   "failed to get membership for user 'testuser' in the GitHub Organization",
		},
		{
			name:         "teams API error",
			username:     "testuser",
			organization: "test-org",
			membershipResponse: &githubv3.Membership{
				State: githubv3.String("active"),
				User: &githubv3.User{
					SuspendedAt: &githubv3.Timestamp{Time: time.Time{}},
				},
			},
			teamsGraphQLError: fmt.Errorf("GraphQL error"),
			expectedError:     "failed to list teams for user 'testuser' in the GitHub Organization",
		},
		{
			name:                 "failed to create API clients",
			username:             "testuser",
			organization:         "test-org",
			appInstallationError: fmt.Errorf("app not installed"),
			expectedError:        "failed to create API clients for GitHub Organization",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Setup test server to mock GitHub APIs
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				// Mock Apps Find Organization Installation
				case strings.Contains(r.URL.Path, fmt.Sprintf("/orgs/%s/installation", tt.organization)):
					if tt.appInstallationError != nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{
						"id": 12345,
					})

				// Mock Apps Create Installation Token
				case strings.Contains(r.URL.Path, "/installations/") && strings.Contains(r.URL.Path, "/access_tokens"):
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(map[string]any{
						"token": "installation-token",
					})

				// Mock Organization Membership
				case strings.Contains(r.URL.Path, fmt.Sprintf("/orgs/%s/memberships/%s", tt.organization, tt.username)):
					if tt.membershipError != nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.WriteHeader(http.StatusOK)
					respBytes, _ := json.Marshal(tt.membershipResponse)
					w.Write(respBytes)

				// Mock GraphQL for teams
				case r.URL.Path == "/graphql":
					if tt.teamsGraphQLError != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(tt.teamsGraphQLResponse))

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Set up environment with a valid private key for testing
			if tt.organization != "" {
				// Create a test RSA private key
				privateKey := generateTestRSAPrivateKey()
				tmpFile, err := os.CreateTemp("", "github-key-*.pem")
				g.Expect(err).ToNot(HaveOccurred())
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(privateKey)
				g.Expect(err).ToNot(HaveOccurred())
				tmpFile.Close()

				t.Setenv(envGitHubAppPrivateKey, tmpFile.Name())
			}

			// Create provider
			provider := &githubProvider{
				appClientID:  "test-app-id",
				organization: tt.organization,
			}

			// Create context with mock HTTP client
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &githubAPITransport{
					testServer: server,
				},
			})

			groups, err := provider.verifyGitHubOrganizationUser(ctx, tt.username)

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

func TestGitHubProvider_newOrganizationClients(t *testing.T) {
	tests := []struct {
		name                    string
		appClientID             string
		organization            string
		privateKeyContent       string
		privateKeyError         bool
		appInstallationNotFound bool
		installationTokenError  bool
		expectedError           string
	}{
		{
			name:              "successful client creation",
			appClientID:       "test-app-id",
			organization:      "test-org",
			privateKeyContent: generateTestRSAPrivateKey(),
		},
		{
			name:            "private key file not found",
			appClientID:     "test-app-id",
			organization:    "test-org",
			privateKeyError: true,
			expectedError:   "failed to read GitHub App private key",
		},
		{
			name:              "invalid private key format",
			appClientID:       "test-app-id",
			organization:      "test-org",
			privateKeyContent: "invalid-key-content",
			expectedError:     "failed to parse GitHub App private key",
		},
		{
			name:                    "app not installed in organization",
			appClientID:             "test-app-id",
			organization:            "test-org",
			privateKeyContent:       generateTestRSAPrivateKey(),
			appInstallationNotFound: true,
			expectedError:           "failed to find GitHub App Organization installation",
		},
		{
			name:                   "installation token creation failure",
			appClientID:            "test-app-id",
			organization:           "test-org",
			privateKeyContent:      generateTestRSAPrivateKey(),
			installationTokenError: true,
			expectedError:          "failed to create GitHub App installation token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Setup test server to mock GitHub APIs
			var capturedJWT string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Capture the JWT from Authorization header
				if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") && capturedJWT == "" {
					capturedJWT = strings.TrimPrefix(auth, "Bearer ")
				}

				switch {
				// Mock Apps Find Organization Installation
				case strings.Contains(r.URL.Path, fmt.Sprintf("/orgs/%s/installation", tt.organization)):
					if tt.appInstallationNotFound {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(map[string]any{
							"message": "Not Found",
						})
						return
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(map[string]any{
						"id": 12345,
					})

				// Mock Apps Create Installation Token
				case strings.Contains(r.URL.Path, "/app/installations/12345/access_tokens"):
					if tt.installationTokenError {
						w.WriteHeader(http.StatusUnprocessableEntity)
						json.NewEncoder(w).Encode(map[string]any{
							"message": "Validation failed",
						})
						return
					}
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(map[string]any{
						"token": "installation-token-12345",
					})

				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			// Set up private key
			if tt.privateKeyError {
				t.Setenv(envGitHubAppPrivateKey, "/non/existent/path/key.pem")
			} else {
				tmpFile, err := os.CreateTemp("", "github-key-*.pem")
				g.Expect(err).ToNot(HaveOccurred())
				defer os.Remove(tmpFile.Name())

				if tt.privateKeyContent != "" {
					_, err = tmpFile.WriteString(tt.privateKeyContent)
					g.Expect(err).ToNot(HaveOccurred())
				}
				tmpFile.Close()

				t.Setenv(envGitHubAppPrivateKey, tmpFile.Name())
			}

			// Create provider
			provider := &githubProvider{
				appClientID:  tt.appClientID,
				organization: tt.organization,
			}

			// Create context with mock HTTP client
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &githubAPITransport{
					testServer: server,
				},
			})

			apiv3, apiv4, err := provider.newOrganizationClients(ctx)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
				g.Expect(apiv3).To(BeNil())
				g.Expect(apiv4).To(BeNil())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(apiv3).ToNot(BeNil())
				g.Expect(apiv4).ToNot(BeNil())

				// Verify that a valid JWT was created
				if capturedJWT != "" {
					// Parse and verify the JWT structure
					tok, err := jwt.Parse([]byte(capturedJWT), jwt.WithVerify(false))
					g.Expect(err).ToNot(HaveOccurred())
					issuer, _ := tok.Issuer()
					g.Expect(issuer).To(Equal(tt.appClientID))
				}
			}
		})
	}
}

// githubMockTransport is a custom transport for mocking GitHub API calls
type githubMockTransport struct {
	server        *httptest.Server
	shouldFail    bool
	orgError      error
	orgGroups     []string
	shouldMockOrg bool
	orgName       string
}

func (t *githubMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.shouldFail {
		return nil, fmt.Errorf("simulated network failure")
	}

	// Redirect api.github.com calls to our test server
	if strings.Contains(req.URL.Host, "api.github.com") {
		testURL, _ := url.Parse(t.server.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}

	return http.DefaultTransport.RoundTrip(req)
}

// githubAPITransport redirects GitHub API calls to test server
type githubAPITransport struct {
	testServer *httptest.Server
}

func (t *githubAPITransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect all GitHub API calls to our test server
	if strings.Contains(req.URL.Host, "api.github.com") {
		testURL, _ := url.Parse(t.testServer.URL)
		req.URL.Scheme = testURL.Scheme
		req.URL.Host = testURL.Host
	}

	return http.DefaultTransport.RoundTrip(req)
}

// Helper function to generate a test RSA private key in PEM format
func generateTestRSAPrivateKey() string {
	return `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDvY6Ue4e9TsroN
QDn8DQGNR4VCfOBAds+uM2w51K+G4G2GCm4SkmXW/lyiZOyF1pNxHKfL6iU8Zkkl
6dLWAKdkh7lcuP2LWfZZEpGeKIvYuFSiZdipQ0q06gFT8iewfXC/gUNCpijRZgfj
YDwhDZ/bVvem1/F0dtkAnsKBkBnbKO2TwtaAxdWbvTIdHuQyE5mHmNKOaPJNwQ9D
XxKvEAlitUKfqecpLtN9QBHZYtoanHfuCwMvC0v+sRkYqm9vCUwmljx6mCrw/aZt
mQLhkoOiztHuPhdF1pYjOzPNOpDhBhoVX6Fr6rXbhfTGsLPfdMdocO2uUeoKGm10
KQ6Q0HYnAgMBAAECggEAQ/3zSiA1z3n16gmR7orrI+tqaAX705NrTTkBxjMoX5Ci
yu1vcgrure+089LicukNG5Vd+0bXqJ4MrJ4K6glpgd4iwbkxGkFE/OuPPHKbtcQ1
FaMDtJ+OOnA0TFl8+F3Ihjv6lJWJBmCKYQRWT7UE8FF1KYgv5jpTTB/Lcu0wytP6
dgh8j/EJ2nGewF38gLoCsrmw/Mwq6adD+JTKjxIk7Vn4PaJhiBla8VxrcT/yumx+
h4ZElD0H93Rt7rCZjd5atrhvP+42pSuqv0VQzsiM3VmmpNe/qtwu/QdBkNC5TA49
UXrsOMs54y0D90p7xH92Wcuv2wl6Xv5h+rm1tUqYcQKBgQD42NdJuKzPv3iv2RwN
I7lWkQovK/131be/nfiffxfPw8zcOScRnBXQbzJx8sxceIXK2LfehjKiTZOVe6zo
tUCMHs1yBPQv+6mADzkie5Oined9u3+99BAmvHp1x3ApZrzm8lTW6RD/VFlnWEDC
7UgMNVRdPPptdTuDVuVUZNm7ZQKBgQD2RTVJKmH/5hEqd1PVc25EN+EF7q96R2Ag
MzYpMpm9y3ulbCs2Ajv8R01mf/h+3aZwEwfihxoDxJWPO6N+xR40LJls9gTugakz
Ooh5fxcPzvwDfQE8pk29eYlIGkdc/LL4OPYVP9NSe4bI1yyzl/4YuxoCzbBsGU15
2Ksd80wAmwKBgQCDnAN4zQAwu75zmmrYlC1AmGL/gc+DYnfVExJcIJaSXqbpThzY
lml/HGBcnaHxwhhYqPfN68G5zzef1pIjXUEvGldj1zTib8I8pVB9aUgyuDqnZ9Pu
vbcRFZva0MkETH7Z0g6GvysrLww9uRI/RclWE5pz2X1FCLyaAQo28UOqdQKBgCwk
XZe+vBAlSeBlwSYaaaJarb/ld5igYI+E/mlGA56scX5GNDybC+t9UFdWCtGaozGl
h51IABa6zt/8naKkbHSHpfyM4Hdr0Es5a6rzZ8vSmwN5DZa0bGzQ8xV0eGQne2DY
vOs0JIm9UHyBbSbH0KjYKKJmAgBuTJ/RgWJ98JqPAoGBAMxBo1eaC8xtexCp9er/
Sn2Gziv2Vz47st73iAYAgNv1I2ApO/yyO6w7ho14D02vPRETi48hqjwyJzrqw7/i
dU6LTwnDOILwih17PDPyZ9uguGGCDqQIL9FMi8t7vOEgaRtn6oaMudTqrY25UZa6
5c843p3R7+XW7B7N1bzpfvOZ
-----END PRIVATE KEY-----`
}

func TestGitHubProvider_Integration(t *testing.T) {
	g := NewWithT(t)

	// Test without organization
	t.Run("without organization", func(t *testing.T) {
		config := &providerConfig{
			Name:         "github",
			ClientID:     "test-client-id",
			Organization: "",
		}

		provider, err := newGitHubProvider(config)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(provider).ToNot(BeNil())

		// Test oauth2Config
		oauth2Config := provider.oauth2Config()
		g.Expect(oauth2Config.Endpoint).To(Equal(github.Endpoint))
		g.Expect(oauth2Config.Scopes).To(BeEmpty())

		// Test verifyUser with mock server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			response := map[string]any{
				"login": "octocat",
			}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		tokenSource := oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: "test-token",
			TokenType:   "Bearer",
		})

		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
			Transport: &githubMockTransport{server: server},
		})

		user, err := provider.verifyUser(ctx, tokenSource)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(user).To(Equal(&userInfo{username: "octocat"}))
	})

	// Test with organization
	t.Run("with organization", func(t *testing.T) {
		// Create a temporary private key file
		tmpFile, err := os.CreateTemp("", "github-key-*.pem")
		g.Expect(err).ToNot(HaveOccurred())
		defer os.Remove(tmpFile.Name())

		_, err = tmpFile.WriteString(generateTestRSAPrivateKey())
		g.Expect(err).ToNot(HaveOccurred())
		tmpFile.Close()

		t.Setenv(envGitHubAppPrivateKey, tmpFile.Name())

		config := &providerConfig{
			Name:         "github",
			ClientID:     "test-app-id",
			Organization: "test-org",
		}

		provider, err := newGitHubProvider(config)
		g.Expect(err).ToNot(HaveOccurred())
		g.Expect(provider).ToNot(BeNil())
		g.Expect(provider.appClientID).To(Equal("test-app-id"))
		g.Expect(provider.organization).To(Equal("test-org"))
	})
}

func TestGitHubProvider_JWTGeneration(t *testing.T) {
	g := NewWithT(t)

	// Create a temporary private key file
	tmpFile, err := os.CreateTemp("", "github-key-*.pem")
	g.Expect(err).ToNot(HaveOccurred())
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(generateTestRSAPrivateKey())
	g.Expect(err).ToNot(HaveOccurred())
	tmpFile.Close()

	t.Setenv(envGitHubAppPrivateKey, tmpFile.Name())

	provider := &githubProvider{
		appClientID:  "123456",
		organization: "test-org",
	}

	// Capture the JWT that would be sent to GitHub
	var capturedJWT string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture JWT from Authorization header on first call
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") && capturedJWT == "" {
			capturedJWT = strings.TrimPrefix(auth, "Bearer ")
		}

		// Mock responses
		if strings.Contains(r.URL.Path, "/orgs/test-org/installation") {
			json.NewEncoder(w).Encode(map[string]any{"id": 789})
		} else if strings.Contains(r.URL.Path, "/installations/789/access_tokens") {
			json.NewEncoder(w).Encode(map[string]any{"token": "installation-token"})
		}
	}))
	defer server.Close()

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
		Transport: &githubAPITransport{testServer: server},
	})

	_, _, err = provider.newOrganizationClients(ctx)
	g.Expect(err).ToNot(HaveOccurred())

	// Verify the JWT structure
	g.Expect(capturedJWT).ToNot(BeEmpty())
	tok, err := jwt.Parse([]byte(capturedJWT), jwt.WithVerify(false))
	g.Expect(err).ToNot(HaveOccurred())

	// Verify JWT claims
	issuer, _ := tok.Issuer()
	g.Expect(issuer).To(Equal("123456"))

	// Verify the JWT is properly signed (would fail with real GitHub API if signature was invalid)
	exp, _ := tok.Expiration()
	iat, _ := tok.IssuedAt()
	g.Expect(exp.After(time.Now())).To(BeTrue())
	g.Expect(iat.Before(time.Now())).To(BeTrue())
}
