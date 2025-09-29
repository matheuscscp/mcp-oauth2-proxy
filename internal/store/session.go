package store

import (
	"time"

	"golang.org/x/oauth2"
)

const (
	sessionMaxSize = 10000 // in bytes
)

type Session struct {
	TX      *Transaction
	Outcome *oauth2.Token

	expiresAt time.Time
}

type sessionKey string

func (s *Session) size() uint {
	var size uint

	// Measure transaction fields if present
	if s.TX != nil {
		// transactionClientParams fields
		size += uint(len(s.TX.ClientParams.CodeChallenge))
		size += uint(len(s.TX.ClientParams.RedirectURL))
		size += uint(len(s.TX.ClientParams.State))

		// Count scopes
		for _, scope := range s.TX.ClientParams.Scopes {
			size += uint(len(scope))
		}

		// transaction fields
		size += uint(len(s.TX.CodeVerifier))
		size += uint(len(s.TX.Host))
	}

	// Measure oauth2.Token fields if present
	if s.Outcome != nil {
		size += uint(len(s.Outcome.AccessToken))
		size += uint(len(s.Outcome.TokenType))
		size += uint(len(s.Outcome.RefreshToken))
	}

	return size
}
