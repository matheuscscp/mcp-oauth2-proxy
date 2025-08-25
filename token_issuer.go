package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
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

func (t *tokenIssuer) issue(iss, sub, aud string, now time.Time) (string, time.Time, error) {
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
		Build()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error building token: %w", err)
	}

	cur, err := t.current(now)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error getting current private key: %w", err)
	}

	b, err := jwt.Sign(tok, jwt.WithKey(issuerAlgorithm(), cur))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("error signing token: %w", err)
	}

	return string(b), exp, nil
}

func (t *tokenIssuer) verify(bearerToken string, now time.Time, iss, aud string) bool {
	for _, key := range t.publicKeys(now) {
		token, err := jwt.Parse([]byte(bearerToken),
			jwt.WithKey(issuerAlgorithm(), key),
			jwt.WithValidate(true))
		if err != nil {
			continue
		}
		tokenIssuer, ok := token.Issuer()
		if !ok || tokenIssuer != iss {
			continue
		}
		tokenAudience, ok := token.Audience()
		if !ok || !slices.Contains(tokenAudience, aud) {
			continue
		}
		tokenExpiration, ok := token.Expiration()
		if !ok || tokenExpiration.Before(now) {
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
		return nil, fmt.Errorf("error generating rsa key: %w", err)
	}

	private, err := jwk.Import(priv)
	if err != nil {
		return nil, fmt.Errorf("error converting rsa key to jwk: %w", err)
	}

	public, err := private.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting public key from jwk: %w", err)
	}

	return &signingKey{
		private:  private,
		public:   public,
		deadline: now.Add(issuerTokenDuration),
	}, nil
}
