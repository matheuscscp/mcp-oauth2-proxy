package issuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	. "github.com/onsi/gomega"
)

func TestNewTokenIssuer(t *testing.T) {
	g := NewWithT(t)

	issuer := New()
	ti := issuer.(*tokenIssuer)

	g.Expect(ti).ToNot(BeNil())
	g.Expect(ti.privateKeySource).ToNot(BeNil())

	// Should be an automaticPrivateKeySource
	_, ok := ti.privateKeySource.(*automaticPrivateKeySource)
	g.Expect(ok).To(BeTrue())
}

func TestIssuer_Issue(t *testing.T) {
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

			tokenString, exp, err := tokenIssuer.Issue(tt.issuer, tt.subject, tt.audience, now, nil, tt.scopes)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(tokenString).ToNot(BeEmpty())
				g.Expect(exp).To(BeTemporally("~", now.Add(tokenDuration), time.Second))

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

func TestIssuer_Verify(t *testing.T) {
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
				token, _, err := ti.Issue("https://example.com", "user@example.com", "mcp-oauth2-proxy", now, nil, nil)
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
				pastTime := now.Add(-2 * tokenDuration)
				token, _, err := ti.Issue("https://example.com", "user@example.com", "mcp-oauth2-proxy", pastTime, nil, nil)
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
					Expiration(now.Add(tokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				b, _ := jwt.Sign(tok, jwt.WithKey(Algorithm(), wrongKey))
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
				token, _, err := ti.Issue("https://wrong-issuer.com", "user@example.com", "mcp-oauth2-proxy", now, nil, nil)
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
				token, _, err := ti.Issue("https://example.com", "user@example.com", "wrong-audience", now, nil, nil)
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
					Expiration(now.Add(tokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(Algorithm(), cur))
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
					Expiration(now.Add(tokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(Algorithm(), cur))
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
					Expiration(now.Add(tokenDuration)).
					NotBefore(now).
					IssuedAt(now).
					JwtID(uuid.NewString()).
					Build()

				cur, _ := ti.current(now)
				b, _ := jwt.Sign(tok, jwt.WithKey(Algorithm(), cur))
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
				b, _ := jwt.Sign(tok, jwt.WithKey(Algorithm(), cur))
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
			isValid := ti.Verify(token, now, tt.iss, tt.aud)

			g.Expect(isValid).To(Equal(tt.expectedValid))
		})
	}
}

// mockPrivateKeySource implements the privateKeySource interface for testing
type mockPrivateKeySource struct {
	currentError  error
	privateKey    jwk.Key
	publicKeyList []jwk.Key
}

func (m *mockPrivateKeySource) current(now time.Time) (private jwk.Key, err error) {
	if m.currentError != nil {
		return nil, m.currentError
	}
	defer func() {
		public, _ := private.PublicKey()
		thumbprint, _ := public.Thumbprint(crypto.SHA256)
		keyID := fmt.Sprintf("%x", thumbprint)
		private.Set(jwk.KeyIDKey, keyID)
		public.Set(jwk.KeyIDKey, keyID)
	}()
	if m.privateKey != nil {
		return m.privateKey, nil
	}
	// Generate a test key if none provided
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	private, _ = jwk.Import(priv)
	return private, nil
}

func (m *mockPrivateKeySource) publicKeys(now time.Time) []jwk.Key {
	return m.publicKeyList
}

func newTestTokenIssuer(keySource privateKeySource) *tokenIssuer {
	if keySource == nil {
		// Create a working test key source with the same key for signing and verifying
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		privateKey, _ := jwk.Import(priv)
		publicKey, _ := privateKey.PublicKey()
		keySource = &mockPrivateKeySource{
			privateKey:    privateKey,
			publicKeyList: []jwk.Key{publicKey},
		}
	}
	return &tokenIssuer{keySource}
}

// parseJWT parses and validates a JWT token using the given public key
func parseJWT(g *WithT, tokenString string, publicKey jwk.Key) jwt.Token {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKey(Algorithm(), publicKey), jwt.WithValidate(true))
	g.Expect(err).ToNot(HaveOccurred())
	return token
}
