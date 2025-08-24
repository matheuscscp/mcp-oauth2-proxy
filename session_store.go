package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"sync"
	"time"
)

const (
	sessionStoreTimeout = stateCookieMaxAge * time.Second
)

type sessionStore interface {
	store(tx url.Values, tokens any) (string, error)
	retrieve(key string) (url.Values, any, bool)
}

type memorySessionStore struct {
	mu sync.Mutex
	m  map[string]*session
}

type session struct {
	tx        url.Values
	tokens    any
	expiresAt time.Time
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		m: make(map[string]*session),
	}
}

func (m *memorySessionStore) store(tx url.Values, tokens any) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		// The algorithm below for generating the key makes it usable both as
		// as an authorization code or as a CSRF token.
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return "", fmt.Errorf("error generating key for session store: %w", err)
		}
		key := base64.RawURLEncoding.EncodeToString(keyBytes)

		if s, ok := m.m[key]; !ok || s.expiresAt.Before(time.Now()) {
			expiresAt := time.Now().Add(sessionStoreTimeout)
			m.m[key] = &session{tx, tokens, expiresAt}
			return key, nil
		}
	}
}

func (m *memorySessionStore) retrieve(key string) (url.Values, any, bool) {
	m.mu.Lock()
	s, ok := m.m[key]
	delete(m.m, key)
	for k, v := range m.m {
		if v.expiresAt.Before(time.Now()) {
			delete(m.m, k)
		}
	}
	m.mu.Unlock()

	if !ok || s.expiresAt.Before(time.Now()) {
		return nil, nil, false
	}
	return s.tx, s.tokens, true
}
