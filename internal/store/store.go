package store

import (
	"time"

	"github.com/matheuscscp/mcp-oauth2-proxy/internal/config"
)

const (
	timeout = config.StateCookieMaxAge * time.Second
)

type Store interface {
	StoreTransaction(tx *Transaction) (string, error)
	StoreSession(s *Session) (string, error)
	RetrieveTransaction(key string) (*Transaction, bool)
	RetrieveSession(key string) (*Session, bool)
}
