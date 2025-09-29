package issuer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sirupsen/logrus"
)

const (
	tokenDuration = time.Hour
)

func Algorithm() jwa.SignatureAlgorithm { return jwa.RS256() }

type Issuer interface {
	Issue(iss, sub, aud string, now time.Time, groups, scopes []string) (string, time.Time, error)
	Verify(bearerToken string, now time.Time, iss, aud string) bool
	PublicKeys(now time.Time) []jwk.Key
}

type tokenIssuer struct{ privateKeySource }

func New() Issuer {
	return &tokenIssuer{&automaticPrivateKeySource{}}
}

func (t *tokenIssuer) Issue(iss, sub, aud string, now time.Time, groups, scopes []string) (string, time.Time, error) {
	cur, err := t.current(now)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get current private key: %w", err)
	}
	keyID, ok := cur.KeyID()
	if !ok {
		return "", time.Time{}, fmt.Errorf("private key has no key ID")
	}

	exp := now.Add(tokenDuration)
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

	b, err := jwt.Sign(tok, jwt.WithKey(Algorithm(), cur))
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

func (t *tokenIssuer) Verify(bearerToken string, now time.Time, iss, aud string) bool {
	for _, key := range t.publicKeys(now) {

		token, err := jwt.ParseString(bearerToken,
			jwt.WithKey(Algorithm(), key),
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

func (t *tokenIssuer) PublicKeys(now time.Time) []jwk.Key {
	return t.publicKeys(now)
}
