package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	sessionStoreTimeout = stateCookieMaxAge * time.Second
)

type sessionStore interface {
	storeTransaction(tx *transaction) (string, error)
	store(s *session) (string, error)
	retrieveTransaction(key string) (*transaction, bool)
	retrieve(key string) (*session, bool)
}

type memorySessionStore struct {
	mp map[string]*session
	mu sync.Mutex
}

type session struct {
	tx        *transaction
	outcome   *oauth2.Token
	expiresAt time.Time
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		mp: make(map[string]*session),
	}
}

func (m *memorySessionStore) storeTransaction(tx *transaction) (string, error) {
	return m.store(&session{tx: tx})
}

func (m *memorySessionStore) store(s *session) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		// The algorithm below for generating the key makes it usable both as
		// as an authorization code or as a CSRF state.
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return "", fmt.Errorf("error generating key for session: %w", err)
		}
		key := base64.RawURLEncoding.EncodeToString(keyBytes)

		if cur, ok := m.mp[key]; !ok || cur.expiresAt.Before(time.Now()) {
			s.expiresAt = time.Now().Add(sessionStoreTimeout)
			m.mp[key] = s
			return key, nil
		}
	}
}

func (m *memorySessionStore) retrieveTransaction(key string) (*transaction, bool) {
	s, ok := m.retrieve(key)
	if !ok {
		return nil, false
	}
	return s.tx, true
}

func (m *memorySessionStore) retrieve(key string) (*session, bool) {
	m.mu.Lock()
	s, ok := m.mp[key]
	delete(m.mp, key)
	for k, v := range m.mp {
		if v.expiresAt.Before(time.Now()) {
			delete(m.mp, k)
		}
	}
	m.mu.Unlock()

	if !ok || s.expiresAt.Before(time.Now()) {
		return nil, false
	}
	return s, true
}
