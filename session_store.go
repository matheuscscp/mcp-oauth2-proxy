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

type sessionStore struct {
	mu sync.Mutex
	m  map[string]*session
}

type session struct {
	tx        url.Values
	tokens    any
	expiresAt time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		m: make(map[string]*session),
	}
}

func (t *sessionStore) store(tx url.Values, tokens any) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for {
		// The algorithm below for generating the key makes it usable both as
		// as an authorization code or as a CSRF token.
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return "", fmt.Errorf("error generating key for session store: %w", err)
		}
		key := base64.RawURLEncoding.EncodeToString(keyBytes)

		if s, ok := t.m[key]; !ok || s.expiresAt.Before(time.Now()) {
			expiresAt := time.Now().Add(sessionStoreTimeout)
			t.m[key] = &session{tx, tokens, expiresAt}
			return key, nil
		}
	}
}

func (t *sessionStore) retrieve(key string) (url.Values, any, bool) {
	t.mu.Lock()
	s, ok := t.m[key]
	delete(t.m, key)
	for k, v := range t.m {
		if v.expiresAt.Before(time.Now()) {
			delete(t.m, k)
		}
	}
	t.mu.Unlock()

	if !ok || s.expiresAt.Before(time.Now()) {
		return nil, nil, false
	}
	return s.tx, s.tokens, true
}
