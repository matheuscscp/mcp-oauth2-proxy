package issuer

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	. "github.com/onsi/gomega"
)

func TestAutomaticPrivateKeySource_current(t *testing.T) {
	tests := []struct {
		name          string
		setupSource   func() *automaticPrivateKeySource
		now           time.Time
		expectedError string
		checkKeyGen   bool
	}{
		{
			name: "generate first key",
			setupSource: func() *automaticPrivateKeySource {
				return &automaticPrivateKeySource{}
			},
			now:         time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			checkKeyGen: true,
		},
		{
			name: "use existing valid key",
			setupSource: func() *automaticPrivateKeySource {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey, _ := jwk.Import(priv)
				publicKey, _ := privateKey.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKey,
						public:   publicKey,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // 1 hour in future
					},
				}
			},
			now: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "rotate expired key",
			setupSource: func() *automaticPrivateKeySource {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey, _ := jwk.Import(priv)
				publicKey, _ := privateKey.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKey,
						public:   publicKey,
						deadline: time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC), // 1 hour in past
					},
				}
			},
			now:         time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			checkKeyGen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			source := tt.setupSource()
			key, err := source.current(tt.now)

			if tt.expectedError != "" {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.expectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(key).ToNot(BeNil())

				if tt.checkKeyGen {
					// Verify that a new key was generated
					g.Expect(source.cur).ToNot(BeNil())
					g.Expect(source.cur.private).To(Equal(key))
					g.Expect(source.cur.deadline).To(Equal(tt.now.Add(tokenDuration)))
				}
			}
		})
	}
}

func TestAutomaticPrivateKeySource_publicKeys(t *testing.T) {
	tests := []struct {
		name         string
		setupSource  func() *automaticPrivateKeySource
		now          time.Time
		expectedKeys int
	}{
		{
			name: "no keys initialized",
			setupSource: func() *automaticPrivateKeySource {
				return &automaticPrivateKeySource{}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedKeys: 0,
		},
		{
			name: "only current key valid",
			setupSource: func() *automaticPrivateKeySource {
				priv, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKey, _ := jwk.Import(priv)
				publicKey, _ := privateKey.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKey,
						public:   publicKey,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // Valid for verifying
					},
				}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedKeys: 1,
		},
		{
			name: "both current and previous keys valid",
			setupSource: func() *automaticPrivateKeySource {
				// Current key
				privCur, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyCur, _ := jwk.Import(privCur)
				publicKeyCur, _ := privateKeyCur.PublicKey()

				// Previous key
				privPrev, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyPrev, _ := jwk.Import(privPrev)
				publicKeyPrev, _ := privateKeyPrev.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKeyCur,
						public:   publicKeyCur,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // Valid for verifying
					},
					prev: &signingKey{
						private:  privateKeyPrev,
						public:   publicKeyPrev,
						deadline: time.Date(2023, 1, 1, 12, 30, 0, 0, time.UTC), // Still within grace period
					},
				}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expectedKeys: 2,
		},
		{
			name: "previous key expired for verification",
			setupSource: func() *automaticPrivateKeySource {
				// Current key
				privCur, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyCur, _ := jwk.Import(privCur)
				publicKeyCur, _ := privateKeyCur.PublicKey()

				// Previous key (expired for verification)
				privPrev, _ := rsa.GenerateKey(rand.Reader, 2048)
				privateKeyPrev, _ := jwk.Import(privPrev)
				publicKeyPrev, _ := privateKeyPrev.PublicKey()

				return &automaticPrivateKeySource{
					cur: &signingKey{
						private:  privateKeyCur,
						public:   publicKeyCur,
						deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // Valid for verifying
					},
					prev: &signingKey{
						private:  privateKeyPrev,
						public:   publicKeyPrev,
						deadline: time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC), // Expired for verifying
					},
				}
			},
			now:          time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC), // 2 hours after prev deadline
			expectedKeys: 1,                                            // Only current key
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			source := tt.setupSource()
			keys := source.publicKeys(tt.now)

			g.Expect(keys).To(HaveLen(tt.expectedKeys))
		})
	}
}
