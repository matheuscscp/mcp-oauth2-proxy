package store

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

func TestSession_size(t *testing.T) {
	tests := []struct {
		name         string
		session      *Session
		expectedSize uint
	}{
		{
			name: "empty session",
			session: &Session{
				expiresAt: time.Now(),
			},
			expectedSize: 0,
		},
		{
			name: "session with transaction only",
			session: &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						CodeChallenge: "challenge123",                     // 12 chars
						RedirectURL:   "https://test.com",                 // 16 chars
						State:         "state",                            // 5 chars
						Scopes:        []string{"read", "write", "admin"}, // 4+5+5 = 14 chars
					},
					CodeVerifier: "verifier", // 8 chars
					Host:         "host.com", // 8 chars
				},
				expiresAt: time.Now(),
			},
			expectedSize: 12 + 16 + 5 + 14 + 8 + 8, // = 63
		},
		{
			name: "session with outcome only",
			session: &Session{
				Outcome: &oauth2.Token{
					AccessToken:  "access_token_123", // 16 chars
					TokenType:    "Bearer",           // 6 chars
					RefreshToken: "refresh_456",      // 11 chars
				},
				expiresAt: time.Now(),
			},
			expectedSize: 16 + 6 + 11, // = 33
		},
		{
			name: "session with both transaction and outcome",
			session: &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						CodeChallenge: "challenge",                  // 9 chars
						RedirectURL:   "url",                        // 3 chars
						State:         "st",                         // 2 chars
						Scopes:        []string{"scope1", "scope2"}, // 6+6 = 12 chars
					},
					CodeVerifier: "verify", // 6 chars
					Host:         "host",   // 4 chars
				},
				Outcome: &oauth2.Token{
					AccessToken:  "token", // 5 chars
					TokenType:    "type",  // 4 chars
					RefreshToken: "ref",   // 3 chars
				},
				expiresAt: time.Now(),
			},
			expectedSize: 9 + 3 + 2 + 12 + 6 + 4 + 5 + 4 + 3, // = 48
		},
		{
			name: "session with empty strings",
			session: &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						CodeChallenge: "",
						RedirectURL:   "",
						State:         "",
						Scopes:        []string{},
					},
					CodeVerifier: "",
					Host:         "",
				},
				Outcome: &oauth2.Token{
					AccessToken:  "",
					TokenType:    "",
					RefreshToken: "",
				},
				expiresAt: time.Now(),
			},
			expectedSize: 0,
		},
		{
			name: "session with nil transaction and outcome",
			session: &Session{
				TX:        nil,
				Outcome:   nil,
				expiresAt: time.Now(),
			},
			expectedSize: 0,
		},
		{
			name: "session with many scopes",
			session: &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						CodeChallenge: "x", // 1 char
						RedirectURL:   "y", // 1 char
						State:         "z", // 1 char
						Scopes: []string{
							"read",      // 4 chars
							"write",     // 5 chars
							"delete",    // 6 chars
							"update",    // 6 chars
							"admin",     // 5 chars
							"superuser", // 9 chars
						}, // total: 35 chars
					},
					CodeVerifier: "a", // 1 char
					Host:         "b", // 1 char
				},
				expiresAt: time.Now(),
			},
			expectedSize: 1 + 1 + 1 + 35 + 1 + 1, // = 40
		},
		{
			name: "session with large tokens",
			session: &Session{
				Outcome: &oauth2.Token{
					AccessToken:  "very_long_access_token_that_could_be_a_jwt_with_many_claims_and_signatures", // 77 chars
					TokenType:    "Bearer",                                                                     // 6 chars
					RefreshToken: "another_long_refresh_token_for_refreshing_access",                           // 45 chars
				},
				expiresAt: time.Now(),
			},
			expectedSize: 77 + 6 + 45, // = 128
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			size := tt.session.size()

			g.Expect(size).To(Equal(tt.expectedSize))
		})
	}
}
