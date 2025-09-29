package store

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const (
	memoryStoreMaxSize = 60000 // maximum number of items to store in memory
)

type memoryStore struct {
	maxSize       int
	sessions      map[sessionKey]*Session
	evictionQueue []sessionKey
	mu            sync.Mutex

	generateKey func() ([32]byte, error)
}

func NewMemoryStore() *memoryStore {
	return &memoryStore{
		maxSize:  memoryStoreMaxSize,
		sessions: make(map[sessionKey]*Session),
	}
}

func (m *memoryStore) StoreTransaction(tx *Transaction) (string, error) {
	return m.StoreSession(&Session{TX: tx})
}

func (m *memoryStore) StoreSession(s *Session) (string, error) {
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
		s.expiresAt = time.Now().Add(timeout)
		m.sessions[sessionKey(key)] = s
		m.evictionQueue = append(m.evictionQueue, sessionKey(key))
		return key, nil
	}
}

func (m *memoryStore) RetrieveTransaction(key string) (*Transaction, bool) {
	s, ok := m.RetrieveSession(key)
	if !ok {
		return nil, false
	}
	return s.TX, true
}

func (m *memoryStore) RetrieveSession(key string) (*Session, bool) {
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

func (m *memoryStore) collectGarbage() {
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
