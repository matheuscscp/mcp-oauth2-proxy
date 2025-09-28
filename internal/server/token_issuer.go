package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sirupsen/logrus"
)

const (
	issuerTokenDuration = time.Hour
)

var (
	issuerAlgorithm = jwa.RS256
)

type tokenIssuer struct{ privateKeySource }

type privateKeySource interface {
	current(now time.Time) (jwk.Key, error)
	publicKeys(now time.Time) []jwk.Key
}

type automaticPrivateKeySource struct {
	cur  *signingKey
	prev *signingKey
	mu   sync.RWMutex
}

type signingKey struct {
	keyID    string
	private  jwk.Key
	public   jwk.Key
	deadline time.Time
}

func (s *signingKey) expiredForIssuingTokens(now time.Time) bool {
	return s == nil || s.deadline.Before(now)
}

func (s *signingKey) expiredForVerifyingTokens(now time.Time) bool {
	return s == nil || s.deadline.Add(issuerTokenDuration).Before(now)
}

func newTokenIssuer() *tokenIssuer {
	return &tokenIssuer{&automaticPrivateKeySource{}}
}

func (t *tokenIssuer) issue(iss, sub, aud string, now time.Time, groups, scopes []string) (string, time.Time, error) {
	cur, err := t.current(now)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get current private key: %w", err)
	}
	keyID, ok := cur.KeyID()
	if !ok {
		return "", time.Time{}, fmt.Errorf("private key has no key ID")
	}

	exp := now.Add(issuerTokenDuration)
	nbf := now
	iat := now
	jti := uuid.NewString()

	tok, err := jwt.NewBuilder().
		Issuer(iss).
		Subject(sub).
		Audience([]string{aud}).
		Expiration(exp).
		NotBefore(nbf).
		IssuedAt(iat).
		JwtID(jti).
		Claim("groups", groups).
		Claim("scopes", scopes).
		Build()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to build token: %w", err)
	}

	b, err := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), cur))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}
	signedJWT := string(b)

	// Log the token issuance.
	b, _ = json.Marshal(tok)
	var claims map[string]any
	_ = json.Unmarshal(b, &claims)
	logData := logrus.Fields{
		jwk.KeyIDKey: keyID,
		"claims":     claims,
	}
	logrus.WithField("token", logData).Info("token issued")

	return signedJWT, exp, nil
}

func (t *tokenIssuer) verify(bearerToken string, now time.Time, iss, aud string) bool {
	for _, key := range t.publicKeys(now) {

		token, err := jwt.ParseString(bearerToken,
			jwt.WithKey(issuerAlgorithm(), key),
			jwt.WithIssuer(iss),
			jwt.WithAudience(aud))
		if err != nil {
			continue
		}

		if exp, ok := token.Expiration(); !ok || now.After(exp) {
			continue
		}

		return true
	}
	return false
}

func (a *automaticPrivateKeySource) current(now time.Time) (jwk.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cur.expiredForIssuingTokens(now) {
		cur, err := a.generateNew(now)
		if err != nil {
			return nil, err
		}

		a.prev = a.cur
		a.cur = cur
	}

	return a.cur.private, nil
}

func (a *automaticPrivateKeySource) publicKeys(now time.Time) []jwk.Key {
	a.mu.RLock()
	cur, prev := a.cur, a.prev
	a.mu.RUnlock()

	var keys []jwk.Key
	if !cur.expiredForVerifyingTokens(now) {
		keys = append(keys, cur.public)
	}
	if !prev.expiredForVerifyingTokens(now) {
		keys = append(keys, prev.public)
	}
	return keys
}

func (a *automaticPrivateKeySource) generateNew(now time.Time) (*signingKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %w", err)
	}

	private, err := jwk.Import(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rsa key to jwk: %w", err)
	}

	public, err := private.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from jwk: %w", err)
	}

	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to get thumbprint from public key: %w", err)
	}

	keyID := fmt.Sprintf("%x", thumbprint)
	private.Set(jwk.KeyIDKey, keyID)
	public.Set(jwk.KeyIDKey, keyID)

	deadline := now.Add(issuerTokenDuration)

	logData := logrus.Fields{
		jwk.KeyIDKey: keyID,
		"deadline":   deadline,
	}
	logrus.WithField("key", logData).Info("key generated")

	return &signingKey{
		keyID:    keyID,
		private:  private,
		public:   public,
		deadline: deadline,
	}, nil
}
