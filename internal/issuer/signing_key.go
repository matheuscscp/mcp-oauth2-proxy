package issuer

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

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
	return s == nil || s.deadline.Add(tokenDuration).Before(now)
}
