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
	sessionStoreMaxSize = 60000 // maximum number of sessions to store
	sessionMaxSize      = 10000 // in bytes
)

type sessionStore interface {
	storeTransaction(tx *transaction) (string, error)
	store(s *session) (string, error)
	retrieveTransaction(key string) (*transaction, bool)
	retrieve(key string) (*session, bool)
}

type memorySessionStore struct {
	maxSize       int
	sessions      map[sessionKey]*session
	evictionQueue []sessionKey
	mu            sync.Mutex

	generateKey func() ([32]byte, error)
}

type sessionKey string

type session struct {
	tx        *transaction
	outcome   *oauth2.Token
	expiresAt time.Time
}

func (s *session) size() uint {
	var size uint

	// Measure transaction fields if present
	if s.tx != nil {
		// transactionClientParams fields
		size += uint(len(s.tx.clientParams.codeChallenge))
		size += uint(len(s.tx.clientParams.redirectURL))
		size += uint(len(s.tx.clientParams.state))

		// Count scopes
		for _, scope := range s.tx.clientParams.scopes {
			size += uint(len(scope))
		}

		// transaction fields
		size += uint(len(s.tx.codeVerifier))
		size += uint(len(s.tx.host))
	}

	// Measure oauth2.Token fields if present
	if s.outcome != nil {
		size += uint(len(s.outcome.AccessToken))
		size += uint(len(s.outcome.TokenType))
		size += uint(len(s.outcome.RefreshToken))
	}

	return size
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{
		maxSize:  sessionStoreMaxSize,
		sessions: make(map[sessionKey]*session),
	}
}

func (m *memorySessionStore) storeTransaction(tx *transaction) (string, error) {
	return m.store(&session{tx: tx})
}

func (m *memorySessionStore) store(s *session) (string, error) {
	if size := s.size(); size > sessionMaxSize {
		return "", fmt.Errorf("session size exceeds maximum of %d bytes: %d", sessionMaxSize, size)
	}

	m.mu.Lock()
	defer func() { m.collectGarbage(); m.mu.Unlock() }()

	for {
		// The algorithm below for generating the key makes it usable both as
		// as an authorization code or as a CSRF state.
		generateKey := generateSecureCode
		if m.generateKey != nil {
			generateKey = m.generateKey
		}
		keyBytes, err := generateKey()
		if err != nil {
			return "", fmt.Errorf("failed to generate key for session: %w", err)
		}
		key := base64.RawURLEncoding.EncodeToString(keyBytes[:])
		if _, ok := m.sessions[sessionKey(key)]; ok {
			continue
		}

		// Enforce maximum size.
		for len(m.sessions) == m.maxSize {
			oldest := m.evictionQueue[0]
			m.evictionQueue = m.evictionQueue[1:]
			delete(m.sessions, oldest)
		}

		// Store the session and return the key.
		s.expiresAt = time.Now().Add(sessionStoreTimeout)
		m.sessions[sessionKey(key)] = s
		m.evictionQueue = append(m.evictionQueue, sessionKey(key))
		return key, nil
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
	s, ok := m.sessions[sessionKey(key)]
	delete(m.sessions, sessionKey(key))
	m.collectGarbage()
	m.mu.Unlock()

	if !ok || s.expiresAt.Before(time.Now()) {
		return nil, false
	}
	return s, true
}

func (m *memorySessionStore) collectGarbage() {
	var evictionQueue []sessionKey
	for _, key := range m.evictionQueue {
		s, ok := m.sessions[key]
		if !ok {
			continue
		}
		if time.Now().Before(s.expiresAt) {
			evictionQueue = append(evictionQueue, key)
		} else {
			delete(m.sessions, key)
		}
	}
	m.evictionQueue = evictionQueue
}

// generateSecureCode generates a random 32-byte key. It can be used
// as an authorization code or as a CSRF state.
func generateSecureCode() ([32]byte, error) {
	var b [32]byte
	_, err := rand.Read(b[:])
	return b, err
}
