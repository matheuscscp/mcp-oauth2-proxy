package issuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sirupsen/logrus"
)

type privateKeySource interface {
	current(now time.Time) (jwk.Key, error)
	publicKeys(now time.Time) []jwk.Key
}

type automaticPrivateKeySource struct {
	cur  *signingKey
	prev *signingKey
	mu   sync.RWMutex
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

	deadline := now.Add(tokenDuration)

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
