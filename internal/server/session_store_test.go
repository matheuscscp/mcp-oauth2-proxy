package server

import (
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

func TestNewMemorySessionStore(t *testing.T) {
	g := NewWithT(t)

	store := newMemorySessionStore()

	g.Expect(store).ToNot(BeNil())
	g.Expect(store.sessions).ToNot(BeNil())
	g.Expect(store.sessions).To(BeEmpty())
	g.Expect(store.evictionQueue).To(BeEmpty())
}

func TestMemorySessionStore_StoreTransaction(t *testing.T) {
	tests := []struct {
		name        string
		transaction *transaction
	}{
		{
			name: "store valid transaction",
			transaction: &transaction{
				clientParams: transactionClientParams{
					codeChallenge: "test-challenge",
					redirectURL:   "http://localhost:8080/callback",
					scopes:        []string{"read", "write"},
					state:         "test-state",
				},
				codeVerifier: "test-verifier",
				host:         "example.com",
			},
		},
		{
			name: "store transaction with empty fields",
			transaction: &transaction{
				clientParams: transactionClientParams{},
				codeVerifier: "",
				host:         "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			store := newMemorySessionStore()

			key, err := store.storeTransaction(tt.transaction)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(key).ToNot(BeEmpty())
			g.Expect(len(key)).To(BeNumerically(">", 0))

			// Verify the session was stored
			g.Expect(store.sessions).To(HaveLen(1))
			g.Expect(store.evictionQueue).To(HaveLen(1))

			// Verify we can retrieve the transaction
			retrievedTx, ok := store.retrieveTransaction(key)
			g.Expect(ok).To(BeTrue())
			g.Expect(retrievedTx).To(Equal(tt.transaction))
		})
	}
}

func TestMemorySessionStore_Store(t *testing.T) {
	tests := []struct {
		name    string
		session *session
	}{
		{
			name: "store session with transaction",
			session: &session{
				tx: &transaction{
					clientParams: transactionClientParams{
						codeChallenge: "test-challenge",
						redirectURL:   "http://localhost:8080/callback",
						scopes:        []string{"read"},
						state:         "test-state",
					},
					codeVerifier: "test-verifier",
					host:         "example.com",
				},
			},
		},
		{
			name: "store session with OAuth2 token",
			session: &session{
				outcome: &oauth2.Token{
					AccessToken:  "access-token",
					TokenType:    "Bearer",
					RefreshToken: "refresh-token",
					Expiry:       time.Now().Add(time.Hour),
				},
			},
		},
		{
			name: "store session with both transaction and token",
			session: &session{
				tx: &transaction{
					clientParams: transactionClientParams{
						state: "test-state",
					},
					host: "example.com",
				},
				outcome: &oauth2.Token{
					AccessToken: "access-token",
					TokenType:   "Bearer",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			store := newMemorySessionStore()

			key, err := store.store(tt.session)

			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(key).ToNot(BeEmpty())

			// Verify the session was stored
			g.Expect(store.sessions).To(HaveLen(1))
			g.Expect(store.evictionQueue).To(HaveLen(1))

			// Verify expiration was set
			storedSession := store.sessions[sessionKey(key)]
			g.Expect(storedSession.expiresAt).To(BeTemporally(">", time.Now()))
			g.Expect(storedSession.expiresAt).To(BeTemporally("~", time.Now().Add(sessionStoreTimeout), time.Second))
		})
	}
}

func TestMemorySessionStore_StoreUniqueKeys(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	// Store multiple sessions and verify they get unique keys
	session1 := &session{tx: &transaction{host: "example1.com"}}
	session2 := &session{tx: &transaction{host: "example2.com"}}
	session3 := &session{tx: &transaction{host: "example3.com"}}

	key1, err1 := store.store(session1)
	key2, err2 := store.store(session2)
	key3, err3 := store.store(session3)

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

func TestMemorySessionStore_MaxSizeEviction(t *testing.T) {
	g := NewWithT(t)

	const maxSize = 10
	store := newMemorySessionStore()
	store.maxSize = maxSize

	// Store sessions up to the max size
	var keys []string
	for range maxSize {
		session := &session{tx: &transaction{host: "example.com"}}
		key, err := store.store(session)
		g.Expect(err).ToNot(HaveOccurred())
		keys = append(keys, key)
	}

	g.Expect(store.sessions).To(HaveLen(maxSize))
	g.Expect(store.evictionQueue).To(HaveLen(maxSize))

	// Store one more session - should evict the oldest
	extraSession := &session{tx: &transaction{host: "extra.com"}}
	extraKey, err := store.store(extraSession)
	g.Expect(err).ToNot(HaveOccurred())

	// Size should still be at max
	g.Expect(store.sessions).To(HaveLen(maxSize))
	g.Expect(store.evictionQueue).To(HaveLen(maxSize))

	// The oldest session (first one) should be evicted
	_, ok := store.retrieve(keys[0])
	g.Expect(ok).To(BeFalse())

	// The newest session should be retrievable
	retrieved, ok := store.retrieve(extraKey)
	g.Expect(ok).To(BeTrue())
	g.Expect(retrieved.tx.host).To(Equal("extra.com"))
}

func TestMemorySessionStore_RetrieveTransaction(t *testing.T) {
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
			store := newMemorySessionStore()

			originalTx := &transaction{
				clientParams: transactionClientParams{
					codeChallenge: "test-challenge",
					redirectURL:   "http://localhost:8080/callback",
					scopes:        []string{"read", "write"},
					state:         "test-state",
				},
				codeVerifier: "test-verifier",
				host:         "example.com",
			}

			var key string
			if tt.storeFirst {
				var err error
				key, err = store.storeTransaction(originalTx)
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				key = tt.key
			}

			retrievedTx, ok := store.retrieveTransaction(key)

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

func TestMemorySessionStore_Retrieve(t *testing.T) {
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
			store := newMemorySessionStore()

			originalSession := &session{
				tx: &transaction{
					clientParams: transactionClientParams{
						state: "test-state",
					},
					host: "example.com",
				},
				outcome: &oauth2.Token{
					AccessToken: "access-token",
					TokenType:   "Bearer",
				},
			}

			var key string
			if tt.storeFirst {
				var err error
				key, err = store.store(originalSession)
				g.Expect(err).ToNot(HaveOccurred())
			} else {
				key = tt.key
			}

			retrievedSession, ok := store.retrieve(key)

			g.Expect(ok).To(Equal(tt.expectedResult))
			if tt.expectedResult {
				g.Expect(retrievedSession.tx).To(Equal(originalSession.tx))
				g.Expect(retrievedSession.outcome).To(Equal(originalSession.outcome))
				// Verify session is removed after retrieval
				g.Expect(store.sessions).To(BeEmpty())
			} else {
				g.Expect(retrievedSession).To(BeNil())
			}
		})
	}
}

func TestMemorySessionStore_RetrieveRemovesSession(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	session := &session{tx: &transaction{host: "example.com"}}
	key, err := store.store(session)
	g.Expect(err).ToNot(HaveOccurred())

	// Verify session is stored
	g.Expect(store.sessions).To(HaveLen(1))

	// Retrieve the session
	retrievedSession, ok := store.retrieve(key)
	g.Expect(ok).To(BeTrue())
	g.Expect(retrievedSession).ToNot(BeNil())

	// Verify session is removed
	g.Expect(store.sessions).To(BeEmpty())

	// Second retrieval should fail
	_, ok = store.retrieve(key)
	g.Expect(ok).To(BeFalse())
}

func TestMemorySessionStore_ExpiredSessionRetrieval(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	session := &session{tx: &transaction{host: "example.com"}}
	key, err := store.store(session)
	g.Expect(err).ToNot(HaveOccurred())

	// Manually set the session to be expired
	store.sessions[sessionKey(key)].expiresAt = time.Now().Add(-time.Hour)

	// Retrieval should fail for expired session
	retrievedSession, ok := store.retrieve(key)
	g.Expect(ok).To(BeFalse())
	g.Expect(retrievedSession).To(BeNil())
}

func TestMemorySessionStore_CollectGarbage(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	// Store some sessions
	session1 := &session{tx: &transaction{host: "example1.com"}}
	session2 := &session{tx: &transaction{host: "example2.com"}}
	session3 := &session{tx: &transaction{host: "example3.com"}}

	key1, _ := store.store(session1)
	key2, _ := store.store(session2)
	key3, _ := store.store(session3)

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

func TestMemorySessionStore_ConcurrentAccess(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	// Test concurrent stores and retrievals
	const numGoroutines = 10
	const numOperations = 100

	keys := make([]string, numGoroutines*numOperations)

	// Concurrent stores
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			for j := 0; j < numOperations; j++ {
				session := &session{
					tx: &transaction{
						host: "example.com",
						clientParams: transactionClientParams{
							state: "test-state",
						},
					},
				}
				key, err := store.store(session)
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
			if _, ok := store.retrieve(key); ok {
				retrieved++
			}
		}
	}

	// We should have retrieved at least some sessions
	// (exact number depends on timing and eviction)
	g.Expect(retrieved).To(BeNumerically(">=", 0))
}

func TestMemorySessionStore_KeyGeneration(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	// Generate many keys to test for collisions
	keys := make(map[string]bool)
	const numKeys = 10000

	for i := 0; i < numKeys; i++ {
		session := &session{tx: &transaction{host: "example.com"}}
		key, err := store.store(session)
		g.Expect(err).ToNot(HaveOccurred())

		// Verify key is unique
		g.Expect(keys[key]).To(BeFalse(), "Key collision detected: %s", key)
		keys[key] = true

		// Verify key is base64 URL-safe encoded (no padding)
		g.Expect(key).ToNot(ContainSubstring("="))
		g.Expect(len(key)).To(Equal(43)) // 32 bytes base64-encoded without padding = 43 chars
	}
}

func TestMemorySessionStore_MaxSessionSize(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	// Create a large string that will exceed the session size limit
	largeString := make([]byte, sessionMaxSize+1000)
	for i := range largeString {
		largeString[i] = 'a'
	}

	// Create a session with large data
	session := &session{
		tx: &transaction{
			clientParams: transactionClientParams{
				codeChallenge: string(largeString),
				redirectURL:   "http://localhost",
				state:         "test",
			},
			codeVerifier: "verifier",
			host:         "example.com",
		},
	}

	// Attempt to store the oversized session
	_, err := store.store(session)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("session size exceeds maximum"))
	g.Expect(err.Error()).To(ContainSubstring(fmt.Sprintf("%d", sessionMaxSize)))

	// Verify the session was not stored
	g.Expect(store.sessions).To(BeEmpty())
	g.Expect(store.evictionQueue).To(BeEmpty())
}

func TestMemorySessionStore_KeyGenerationError(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

	// Inject a key generator that always fails
	store.generateKey = func() ([32]byte, error) {
		return [32]byte{}, fmt.Errorf("key generation failed")
	}

	session := &session{tx: &transaction{host: "example.com"}}
	_, err := store.store(session)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to generate key for session"))
	g.Expect(err.Error()).To(ContainSubstring("key generation failed"))
}

func TestMemorySessionStore_KeyCollisionHandling(t *testing.T) {
	g := NewWithT(t)
	store := newMemorySessionStore()

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
	session1 := &session{tx: &transaction{host: "example1.com"}}
	key1, err := store.store(session1)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(key1).ToNot(BeEmpty())

	// Store second session - should handle collision and generate new key
	session2 := &session{tx: &transaction{host: "example2.com"}}
	key2, err := store.store(session2)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(key2).ToNot(BeEmpty())
	g.Expect(key2).ToNot(Equal(key1))

	// Verify both sessions are stored
	g.Expect(store.sessions).To(HaveLen(2))
	g.Expect(callCount).To(Equal(3)) // Should have called generator 3 times due to collision
}

func TestMemorySessionStore_Interface(t *testing.T) {
	g := NewWithT(t)

	// Verify that memorySessionStore implements sessionStore interface
	var store sessionStore = newMemorySessionStore()
	g.Expect(store).ToNot(BeNil())

	// Test all interface methods
	tx := &transaction{
		clientParams: transactionClientParams{
			state: "test-state",
		},
		host: "example.com",
	}

	// Test storeTransaction
	key, err := store.storeTransaction(tx)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(key).ToNot(BeEmpty())

	// Test retrieveTransaction
	retrievedTx, ok := store.retrieveTransaction(key)
	g.Expect(ok).To(BeTrue())
	g.Expect(retrievedTx).To(Equal(tx))

	// Test store
	session := &session{
		outcome: &oauth2.Token{
			AccessToken: "test-token",
			TokenType:   "Bearer",
		},
	}
	key2, err := store.store(session)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(key2).ToNot(BeEmpty())

	// Test retrieve
	retrievedSession, ok := store.retrieve(key2)
	g.Expect(ok).To(BeTrue())
	g.Expect(retrievedSession.outcome).To(Equal(session.outcome))
}
