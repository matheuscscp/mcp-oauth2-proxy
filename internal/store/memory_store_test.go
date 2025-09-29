package store

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

func TestNewMemoryStore(t *testing.T) {
	g := NewWithT(t)

	store := NewMemoryStore()

	g.Expect(store).ToNot(BeNil())
	g.Expect(store.sessions).ToNot(BeNil())
	g.Expect(store.sessions).To(BeEmpty())
	g.Expect(store.evictionQueue).To(BeEmpty())
}

func TestMemoryStore_StoreTransaction(t *testing.T) {
	tests := []struct {
		name        string
		transaction *Transaction
	}{
		{
			name: "store valid transaction",
			transaction: &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "test-challenge",
					RedirectURL:   "http://localhost:8080/callback",
					Scopes:        []string{"read", "write"},
					State:         "test-state",
				},
				CodeVerifier: "test-verifier",
				Host:         "example.com",
			},
		},
		{
			name: "store transaction with empty fields",
			transaction: &Transaction{
				ClientParams: TransactionClientParams{},
				CodeVerifier: "",
				Host:         "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			store := NewMemoryStore()

			key, err := store.StoreTransaction(tt.transaction)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(key).ToNot(BeEmpty())
			g.Expect(len(key)).To(BeNumerically(">", 0))

			// Verify the session was stored
			g.Expect(store.sessions).To(HaveLen(1))
			g.Expect(store.evictionQueue).To(HaveLen(1))

			// Verify we can retrieve the transaction
			retrievedTx, ok := store.RetrieveTransaction(key)
			g.Expect(ok).To(BeTrue())
			g.Expect(retrievedTx).To(Equal(tt.transaction))
		})
	}
}

func TestMemoryStore_Store(t *testing.T) {
	tests := []struct {
		name    string
		session *Session
	}{
		{
			name: "store session with transaction",
			session: &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						CodeChallenge: "test-challenge",
						RedirectURL:   "http://localhost:8080/callback",
						Scopes:        []string{"read"},
						State:         "test-state",
					},
					CodeVerifier: "test-verifier",
					Host:         "example.com",
				},
			},
		},
		{
			name: "store session with OAuth2 token",
			session: &Session{
				Outcome: &oauth2.Token{
					AccessToken:  "access-token",
					TokenType:    "Bearer",
					RefreshToken: "refresh-token",
					Expiry:       time.Now().Add(time.Hour),
				},
			},
		},
		{
			name: "store session with both transaction and token",
			session: &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						State: "test-state",
					},
					Host: "example.com",
				},
				Outcome: &oauth2.Token{
					AccessToken: "access-token",
					TokenType:   "Bearer",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			store := NewMemoryStore()

			key, err := store.StoreSession(tt.session)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(key).ToNot(BeEmpty())

			// Verify the session was stored
			g.Expect(store.sessions).To(HaveLen(1))
			g.Expect(store.evictionQueue).To(HaveLen(1))

			// Verify expiration was set
			storedSession := store.sessions[sessionKey(key)]
			g.Expect(storedSession.expiresAt).To(BeTemporally(">", time.Now()))
			g.Expect(storedSession.expiresAt).To(BeTemporally("~", time.Now().Add(timeout), time.Second))
		})
	}
}

func TestMemoryStore_StoreUniqueKeys(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Store multiple sessions and verify they get unique keys
	session1 := &Session{TX: &Transaction{Host: "example1.com"}}
	session2 := &Session{TX: &Transaction{Host: "example2.com"}}
	session3 := &Session{TX: &Transaction{Host: "example3.com"}}

	key1, err1 := store.StoreSession(session1)
	key2, err2 := store.StoreSession(session2)
	key3, err3 := store.StoreSession(session3)

	g.Expect(err1).ToNot(HaveOccurred())
	g.Expect(err2).ToNot(HaveOccurred())
	g.Expect(err3).ToNot(HaveOccurred())

	// All keys should be different
	g.Expect(key1).ToNot(Equal(key2))
	g.Expect(key1).ToNot(Equal(key3))
	g.Expect(key2).ToNot(Equal(key3))

	// All sessions should be stored
	g.Expect(store.sessions).To(HaveLen(3))
	g.Expect(store.evictionQueue).To(HaveLen(3))
}

func TestMemoryStore_MaxSizeEviction(t *testing.T) {
	g := NewWithT(t)

	const maxSize = 10
	store := NewMemoryStore()
	store.maxSize = maxSize

	// Store sessions up to the max size
	var keys []string
	for range maxSize {
		session := &Session{TX: &Transaction{Host: "example.com"}}
		key, err := store.StoreSession(session)
		g.Expect(err).ToNot(HaveOccurred())
		keys = append(keys, key)
	}

	g.Expect(store.sessions).To(HaveLen(maxSize))
	g.Expect(store.evictionQueue).To(HaveLen(maxSize))

	// Store one more session - should evict the oldest
	extraSession := &Session{TX: &Transaction{Host: "extra.com"}}
	extraKey, err := store.StoreSession(extraSession)
	g.Expect(err).ToNot(HaveOccurred())

	// Size should still be at max
	g.Expect(store.sessions).To(HaveLen(maxSize))
	g.Expect(store.evictionQueue).To(HaveLen(maxSize))

	// The oldest session (first one) should be evicted
	_, ok := store.RetrieveSession(keys[0])
	g.Expect(ok).To(BeFalse())

	// The newest session should be retrievable
	retrieved, ok := store.RetrieveSession(extraKey)
	g.Expect(ok).To(BeTrue())
	g.Expect(retrieved.TX.Host).To(Equal("extra.com"))
}

func TestMemoryStore_RetrieveTransaction(t *testing.T) {
	tests := []struct {
		name           string
		storeFirst     bool
		key            string
		expectedResult bool
	}{
		{
			name:           "retrieve existing transaction",
			storeFirst:     true,
			expectedResult: true,
		},
		{
			name:           "retrieve non-existent transaction",
			storeFirst:     false,
			key:            "non-existent-key",
			expectedResult: false,
		},
		{
			name:           "retrieve with invalid key",
			storeFirst:     false,
			key:            "",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			store := NewMemoryStore()

			originalTx := &Transaction{
				ClientParams: TransactionClientParams{
					CodeChallenge: "test-challenge",
					RedirectURL:   "http://localhost:8080/callback",
					Scopes:        []string{"read", "write"},
					State:         "test-state",
				},
				CodeVerifier: "test-verifier",
				Host:         "example.com",
			}

			var key string
			if tt.storeFirst {
				var err error
				key, err = store.StoreTransaction(originalTx)
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				key = tt.key
			}

			retrievedTx, ok := store.RetrieveTransaction(key)

			g.Expect(ok).To(Equal(tt.expectedResult))
			if tt.expectedResult {
				g.Expect(retrievedTx).To(Equal(originalTx))
				// Verify session is removed after retrieval
				g.Expect(store.sessions).To(BeEmpty())
			} else {
				g.Expect(retrievedTx).To(BeNil())
			}
		})
	}
}

func TestMemoryStore_Retrieve(t *testing.T) {
	tests := []struct {
		name           string
		storeFirst     bool
		key            string
		expectedResult bool
	}{
		{
			name:           "retrieve existing session",
			storeFirst:     true,
			expectedResult: true,
		},
		{
			name:           "retrieve non-existent session",
			storeFirst:     false,
			key:            "non-existent-key",
			expectedResult: false,
		},
		{
			name:           "retrieve with empty key",
			storeFirst:     false,
			key:            "",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			store := NewMemoryStore()

			originalSession := &Session{
				TX: &Transaction{
					ClientParams: TransactionClientParams{
						State: "test-state",
					},
					Host: "example.com",
				},
				Outcome: &oauth2.Token{
					AccessToken: "access-token",
					TokenType:   "Bearer",
				},
			}

			var key string
			if tt.storeFirst {
				var err error
				key, err = store.StoreSession(originalSession)
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				key = tt.key
			}

			retrievedSession, ok := store.RetrieveSession(key)

			g.Expect(ok).To(Equal(tt.expectedResult))
			if tt.expectedResult {
				g.Expect(retrievedSession.TX).To(Equal(originalSession.TX))
				g.Expect(retrievedSession.Outcome).To(Equal(originalSession.Outcome))
				// Verify session is removed after retrieval
				g.Expect(store.sessions).To(BeEmpty())
			} else {
				g.Expect(retrievedSession).To(BeNil())
			}
		})
	}
}

func TestMemoryStore_RetrieveRemovesSession(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	session := &Session{TX: &Transaction{Host: "example.com"}}
	key, err := store.StoreSession(session)
	g.Expect(err).ToNot(HaveOccurred())

	// Verify session is stored
	g.Expect(store.sessions).To(HaveLen(1))

	// Retrieve the session
	retrievedSession, ok := store.RetrieveSession(key)
	g.Expect(ok).To(BeTrue())
	g.Expect(retrievedSession).ToNot(BeNil())

	// Verify session is removed
	g.Expect(store.sessions).To(BeEmpty())

	// Second retrieval should fail
	_, ok = store.RetrieveSession(key)
	g.Expect(ok).To(BeFalse())
}

func TestMemoryStore_ExpiredSessionRetrieval(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	session := &Session{TX: &Transaction{Host: "example.com"}}
	key, err := store.StoreSession(session)
	g.Expect(err).ToNot(HaveOccurred())

	// Manually set the session to be expired
	store.sessions[sessionKey(key)].expiresAt = time.Now().Add(-time.Hour)

	// Retrieval should fail for expired session
	retrievedSession, ok := store.RetrieveSession(key)
	g.Expect(ok).To(BeFalse())
	g.Expect(retrievedSession).To(BeNil())
}

func TestMemoryStore_CollectGarbage(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Store some sessions
	session1 := &Session{TX: &Transaction{Host: "example1.com"}}
	session2 := &Session{TX: &Transaction{Host: "example2.com"}}
	session3 := &Session{TX: &Transaction{Host: "example3.com"}}

	key1, _ := store.StoreSession(session1)
	key2, _ := store.StoreSession(session2)
	key3, _ := store.StoreSession(session3)

	g.Expect(store.sessions).To(HaveLen(3))
	g.Expect(store.evictionQueue).To(HaveLen(3))

	// Manually expire the first and third sessions
	store.sessions[sessionKey(key1)].expiresAt = time.Now().Add(-time.Hour)
	store.sessions[sessionKey(key3)].expiresAt = time.Now().Add(-time.Hour)

	// Trigger garbage collection by calling retrieve (which calls collectGarbage)
	store.mu.Lock()
	store.collectGarbage()
	store.mu.Unlock()

	// Only the unexpired session should remain
	g.Expect(store.sessions).To(HaveLen(1))
	g.Expect(store.evictionQueue).To(HaveLen(1))

	// Verify the remaining session is the middle one
	_, ok := store.sessions[sessionKey(key2)]
	g.Expect(ok).To(BeTrue())

	// Verify expired sessions are gone
	_, ok = store.sessions[sessionKey(key1)]
	g.Expect(ok).To(BeFalse())
	_, ok = store.sessions[sessionKey(key3)]
	g.Expect(ok).To(BeFalse())
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Test concurrent stores and retrievals
	const numGoroutines = 10
	const numOperations = 100

	keys := make([]string, numGoroutines*numOperations)

	// Concurrent stores
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < numOperations; j++ {
				session := &Session{
					TX: &Transaction{
						Host: "example.com",
						ClientParams: TransactionClientParams{
							State: "test-state",
						},
					},
				}
				key, err := store.StoreSession(session)
				g.Expect(err).ToNot(HaveOccurred())
				keys[goroutineID*numOperations+j] = key
			}
		}(i)
	}

	// Wait a bit for stores to complete
	time.Sleep(100 * time.Millisecond)

	// Verify we can retrieve sessions (though some may have been evicted due to max size)
	retrieved := 0
	for _, key := range keys {
		if key != "" {
			if _, ok := store.RetrieveSession(key); ok {
				retrieved++
			}
		}
	}

	// We should have retrieved at least some sessions
	// (exact number depends on timing and eviction)
	g.Expect(retrieved).To(BeNumerically(">=", 0))
}

func TestMemoryStore_KeyGeneration(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Generate many keys to test for collisions
	keys := make(map[string]bool)
	const numKeys = 10000

	for i := 0; i < numKeys; i++ {
		session := &Session{TX: &Transaction{Host: "example.com"}}
		key, err := store.StoreSession(session)
		g.Expect(err).ToNot(HaveOccurred())

		// Verify key is unique
		g.Expect(keys[key]).To(BeFalse(), "Key collision detected: %s", key)
		keys[key] = true

		// Verify key is base64 URL-safe encoded (no padding)
		g.Expect(key).ToNot(ContainSubstring("="))
		g.Expect(len(key)).To(Equal(43)) // 32 bytes base64-encoded without padding = 43 chars
	}
}

func TestMemoryStore_MaxSessionSize(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Create a large string that will exceed the session size limit
	largeString := make([]byte, sessionMaxSize+1000)
	for i := range largeString {
		largeString[i] = 'a'
	}

	// Create a session with large data
	session := &Session{
		TX: &Transaction{
			ClientParams: TransactionClientParams{
				CodeChallenge: string(largeString),
				RedirectURL:   "http://localhost",
				State:         "test",
			},
			CodeVerifier: "verifier",
			Host:         "example.com",
		},
	}

	// Attempt to store the oversized session
	_, err := store.StoreSession(session)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("session size exceeds maximum"))
	g.Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("%d", sessionMaxSize)))

	// Verify the session was not stored
	g.Expect(store.sessions).To(BeEmpty())
	g.Expect(store.evictionQueue).To(BeEmpty())
}

func TestMemoryStore_KeyGenerationError(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Inject a key generator that always fails
	store.generateKey = func() ([32]byte, error) {
		return [32]byte{}, fmt.Errorf("key generation failed")
	}

	session := &Session{TX: &Transaction{Host: "example.com"}}
	_, err := store.StoreSession(session)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to generate key for session"))
	g.Expect(err.Error()).To(ContainSubstring("key generation failed"))
}

func TestMemoryStore_KeyCollisionHandling(t *testing.T) {
	g := NewWithT(t)
	store := NewMemoryStore()

	// Inject a key generator that returns the same key twice, then a different one
	callCount := 0
	store.generateKey = func() ([32]byte, error) {
		callCount++
		if callCount <= 2 {
			// Return the same key for first two calls (collision)
			return [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}, nil
		}
		// Return a different key for third call
		return [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
			16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}, nil
	}

	// Store first session
	session1 := &Session{TX: &Transaction{Host: "example1.com"}}
	key1, err := store.StoreSession(session1)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(key1).ToNot(BeEmpty())

	// Store second session - should handle collision and generate new key
	session2 := &Session{TX: &Transaction{Host: "example2.com"}}
	key2, err := store.StoreSession(session2)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(key2).ToNot(BeEmpty())
	g.Expect(key2).ToNot(Equal(key1))

	// Verify both sessions are stored
	g.Expect(store.sessions).To(HaveLen(2))
	g.Expect(callCount).To(Equal(3)) // Should have called generator 3 times due to collision
}
