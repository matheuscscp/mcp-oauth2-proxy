package main

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	. "github.com/onsi/gomega"
)

func TestTokenIssuer_issue(t *testing.T) {
	tests := []struct {
		name          string
		issuer        string
		subject       string
		audience      string
		scopes        []string
		keySource     privateKeySource
		expectedError string
	}{
		{
			name:     "valid token issuance",
			issuer:   "https://example.com",
			subject:  "user@example.com",
			audience: "mcp-oauth2-proxy",
		},
		{
			name:     "valid token with scopes",
			issuer:   "https://example.com",
			subject:  "user@example.com",
			audience: "mcp-oauth2-proxy",
			scopes:   []string{"read", "write", "admin"},
		},
		{
			name:     "empty issuer",
			issuer:   "",
			subject:  "user@example.com",
			audience: "mcp-oauth2-proxy",
		},
		{
			name:     "empty subject",
			issuer:   "https://example.com",
			subject:  "",
			audience: "mcp-oauth2-proxy",
		},
		{
			name:     "empty audience",
			issuer:   "https://example.com",
			subject:  "user@example.com",
			audience: "",
		},
		{
			name:     "private key error",
			issuer:   "https://example.com",
			subject:  "user@example.com",
			audience: "mcp-oauth2-proxy",
			keySource: &mockPrivateKeySource{
				currentError: errors.New("key generation failed"),
			},
			expectedError: "failed to get current private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			tokenIssuer := &tokenIssuer{tt.keySource}
			if tt.keySource == nil {
				tokenIssuer = newTestTokenIssuer(nil)
			}

			now := time.Now()

			tokenString, exp, err := tokenIssuer.issue(tt.issuer, tt.subject, tt.audience, now, nil, tt.scopes)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(tokenString).ToNot(BeEmpty())
				g.Expect(exp).To(BeTemporally("~", now.Add(issuerTokenDuration), time.Second))

				// Verify the token can be parsed and has correct claims
				publicKeys := tokenIssuer.publicKeys(now)
				g.Expect(publicKeys).To(HaveLen(1))
				token := parseJWT(g, tokenString, publicKeys[0])

				// Check all claims
				issuer, ok := token.Issuer()
				g.Expect(ok).To(BeTrue())
				g.Expect(issuer).To(Equal(tt.issuer))

				subject, ok := token.Subject()
				g.Expect(ok).To(BeTrue())
				g.Expect(subject).To(Equal(tt.subject))

				audiences, ok := token.Audience()
				g.Expect(ok).To(BeTrue())
				g.Expect(audiences).To(HaveLen(1))
				g.Expect(audiences[0]).To(Equal(tt.audience))

				expTime, ok := token.Expiration()
				g.Expect(ok).To(BeTrue())
				g.Expect(expTime).To(BeTemporally("~", exp, time.Second))

				nbf, ok := token.NotBefore()
				g.Expect(ok).To(BeTrue())
				g.Expect(nbf).To(BeTemporally("~", now, time.Second))

				iat, ok := token.IssuedAt()
				g.Expect(ok).To(BeTrue())
				g.Expect(iat).To(BeTemporally("~", now, time.Second))

				jti, ok := token.JwtID()
				g.Expect(ok).To(BeTrue())
				// JTI should be a valid UUID
				_, err := uuid.Parse(jti)
				g.Expect(err).ToNot(HaveOccurred())

				// Check scopes claim
				var tokenScopes []any
				scopesErr := token.Get("scopes", &tokenScopes)
				if tt.scopes == nil {
					g.Expect(scopesErr).To(HaveOccurred()) // No scopes claim should be present
				} else {
					g.Expect(scopesErr).ToNot(HaveOccurred())
					g.Expect(tokenScopes).To(HaveLen(len(tt.scopes)))
					for i, scope := range tt.scopes {
						g.Expect(tokenScopes[i]).To(Equal(scope))
					}
				}
			}
		})
	}
}

func TestTokenIssuer_verify(t *testing.T) {
	tests := []struct {
		name          string
		setupToken    func(ti *tokenIssuer, now time.Time) string
		keySource     privateKeySource
		iss           string
		aud           string
		expectedValid bool
	}{
		{
			name: "valid token",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				token, _, err := ti.issue("https://example.com", "user@example.com", "mcp-oauth2-proxy", now, nil, nil)
				if err != nil {
					panic(err)
				}
				return token
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: true,
		},
		{
			name: "invalid token format",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				return "invalid-token"
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "empty token",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				return ""
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "expired token",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				// Issue token in the past
				pastTime := now.Add(-2 * issuerTokenDuration)
				token, _, err := ti.issue("https://example.com", "user@example.com", "mcp-oauth2-proxy", pastTime, nil, nil)
				if err != nil {
					panic(err)
				}
				return token
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "token signed with wrong key",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				// Create a different key for signing
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				wrongKey, _ := jwk.Import(priv)

				tok, _ := jwt.NewBuilder().
					Issuer("https://example.com").
					Subject("user@example.com").
					Audience([]string{"mcp-oauth2-proxy"}).
					Expiration(now.Add(issuerTokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				b, _ := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), wrongKey))
				return string(b)
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "no public keys available",
			keySource: &mockPrivateKeySource{
				publicKeyList: []jwk.Key{}, // No public keys
			},
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				return "any-token"
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "wrong issuer",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				token, _, err := ti.issue("https://wrong-issuer.com", "user@example.com", "mcp-oauth2-proxy", now, nil, nil)
				if err != nil {
					panic(err)
				}
				return token
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "wrong audience",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				token, _, err := ti.issue("https://example.com", "user@example.com", "wrong-audience", now, nil, nil)
				if err != nil {
					panic(err)
				}
				return token
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "multiple audiences - valid",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				// Create token with multiple audiences
				tok, _ := jwt.NewBuilder().
					Issuer("https://example.com").
					Subject("user@example.com").
					Audience([]string{"other-service", "mcp-oauth2-proxy"}).
					Expiration(now.Add(issuerTokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), cur))
				return string(b)
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: true,
		},
		{
			name: "token without issuer claim",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				// Create token without issuer
				tok, _ := jwt.NewBuilder().
					Subject("user@example.com").
					Audience([]string{"mcp-oauth2-proxy"}).
					Expiration(now.Add(issuerTokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), cur))
				return string(b)
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "token without audience claim",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				// Create token without audience
				tok, _ := jwt.NewBuilder().
					Issuer("https://example.com").
					Subject("user@example.com").
					Expiration(now.Add(issuerTokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), cur))
				return string(b)
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
		{
			name: "token without expiration claim",
			setupToken: func(ti *tokenIssuer, now time.Time) string {
				// Create token without expiration
				tok, _ := jwt.NewBuilder().
					Issuer("https://example.com").
					Subject("user@example.com").
					Audience([]string{"mcp-oauth2-proxy"}).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), cur))
				return string(b)
			},
			iss:           "https://example.com",
			aud:           "mcp-oauth2-proxy",
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			// Create shared tokenIssuer for consistency
			var ti *tokenIssuer
			if tt.keySource != nil {
				ti = &tokenIssuer{tt.keySource}
			} else {
				ti = newTestTokenIssuer(nil) // This creates consistent keys
			}

			now := time.Now()

			token := tt.setupToken(ti, now)
			isValid := ti.verify(token, now, tt.iss, tt.aud)

			g.Expect(isValid).To(Equal(tt.expectedValid))
		})
	}
}

func TestSigningKey_expiredForIssuingTokens(t *testing.T) {
	tests := []struct {
		name     string
		key      *signingKey
		now      time.Time
		expected bool
	}{
		{
			name:     "nil key",
			key:      nil,
			expected: true,
		},
		{
			name: "not expired",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name: "exactly at deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name: "past deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			result := tt.key.expiredForIssuingTokens(tt.now)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestSigningKey_expiredForVerifyingTokens(t *testing.T) {
	tests := []struct {
		name     string
		key      *signingKey
		now      time.Time
		expected bool
	}{
		{
			name:     "nil key",
			key:      nil,
			expected: true,
		},
		{
			name: "not expired - within grace period",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 30, 0, 0, time.UTC), // 30 minutes after deadline
			expected: false,
		},
		{
			name: "exactly at verification deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // 1 hour after deadline (issuerTokenDuration)
			expected: false,
		},
		{
			name: "past verification deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 14, 0, 0, 0, time.UTC), // 2 hours after deadline
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			result := tt.key.expiredForVerifyingTokens(tt.now)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestAutomaticPrivateKeySource_current(t *testing.T) {
	tests := []struct {
		name          string
		setupSource   func() *automaticPrivateKeySource
		now           time.Time
		expectedError string
		checkKeyGen   bool
	}{
		{
			name: "generate first key",
			setupSource: func() *automaticPrivateKeySource {
				return &automaticPrivateKeySource{}
			},
			now:         time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			checkKeyGen: true,
		},
		{
			name: "use existing valid key",
			setupSource: func() *automaticPrivateKeySource {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey, _ := jwk.Import(priv)
				publicKey, _ := privateKey.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKey,
						public:   publicKey,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // 1 hour in future
					},
				}
			},
			now: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "rotate expired key",
			setupSource: func() *automaticPrivateKeySource {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey, _ := jwk.Import(priv)
				publicKey, _ := privateKey.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKey,
						public:   publicKey,
						deadline: time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC), // 1 hour in past
					},
				}
			},
			now:         time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			checkKeyGen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			source := tt.setupSource()
			key, err := source.current(tt.now)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(key).ToNot(BeNil())

				if tt.checkKeyGen {
					// Verify that a new key was generated
					g.Expect(source.cur).ToNot(BeNil())
					g.Expect(source.cur.private).To(Equal(key))
					g.Expect(source.cur.deadline).To(Equal(tt.now.Add(issuerTokenDuration)))
				}
			}
		})
	}
}

func TestAutomaticPrivateKeySource_publicKeys(t *testing.T) {
	tests := []struct {
		name         string
		setupSource  func() *automaticPrivateKeySource
		now          time.Time
		expectedKeys int
	}{
		{
			name: "no keys initialized",
			setupSource: func() *automaticPrivateKeySource {
				return &automaticPrivateKeySource{}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedKeys: 0,
		},
		{
			name: "only current key valid",
			setupSource: func() *automaticPrivateKeySource {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey, _ := jwk.Import(priv)
				publicKey, _ := privateKey.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKey,
						public:   publicKey,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // Valid for verifying
					},
				}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedKeys: 1,
		},
		{
			name: "both current and previous keys valid",
			setupSource: func() *automaticPrivateKeySource {
				// Current key
				privCur, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyCur, _ := jwk.Import(privCur)
				publicKeyCur, _ := privateKeyCur.PublicKey()

				// Previous key
				privPrev, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyPrev, _ := jwk.Import(privPrev)
				publicKeyPrev, _ := privateKeyPrev.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKeyCur,
						public:   publicKeyCur,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // Valid for verifying
					},
					prev: &signingKey{
						private:  privateKeyPrev,
						public:   publicKeyPrev,
						deadline: time.Date(2023, 1, 1, 12, 30, 0, 0, time.UTC), // Still within grace period
					},
				}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedKeys: 2,
		},
		{
			name: "previous key expired for verification",
			setupSource: func() *automaticPrivateKeySource {
				// Current key
				privCur, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyCur, _ := jwk.Import(privCur)
				publicKeyCur, _ := privateKeyCur.PublicKey()

				// Previous key (expired for verification)
				privPrev, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyPrev, _ := jwk.Import(privPrev)
				publicKeyPrev, _ := privateKeyPrev.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKeyCur,
						public:   publicKeyCur,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // Valid for verifying
					},
					prev: &signingKey{
						private:  privateKeyPrev,
						public:   publicKeyPrev,
						deadline: time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC), // Expired for verifying
					},
				}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC), // 2 hours after prev deadline
			expectedKeys: 1,                                            // Only current key
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			source := tt.setupSource()
			keys := source.publicKeys(tt.now)

			g.Expect(keys).To(HaveLen(tt.expectedKeys))
		})
	}
}

func TestNewTokenIssuer(t *testing.T) {
	g := NewWithT(t)

	issuer := newTokenIssuer()

	g.Expect(issuer).ToNot(BeNil())
	g.Expect(issuer.privateKeySource).ToNot(BeNil())

	// Should be an automaticPrivateKeySource
	_, ok := issuer.privateKeySource.(*automaticPrivateKeySource)
	g.Expect(ok).To(BeTrue())
}
