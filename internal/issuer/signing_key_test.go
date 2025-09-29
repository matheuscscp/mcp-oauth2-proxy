package issuer

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

func TestSigningKey_expiredForIssuingTokens(t *testing.T) {
	tests := []struct {
		name     string
		key      *signingKey
		now      time.Time
		expected bool
	}{
		{
			name:     "nil key",
			key:      nil,
			expected: true,
		},
		{
			name: "not expired",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name: "exactly at deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: false,
		},
		{
			name: "past deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 11, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			result := tt.key.expiredForIssuingTokens(tt.now)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}

func TestSigningKey_expiredForVerifyingTokens(t *testing.T) {
	tests := []struct {
		name     string
		key      *signingKey
		now      time.Time
		expected bool
	}{
		{
			name:     "nil key",
			key:      nil,
			expected: true,
		},
		{
			name: "not expired - within grace period",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 12, 30, 0, 0, time.UTC), // 30 minutes after deadline
			expected: false,
		},
		{
			name: "exactly at verification deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 13, 0, 0, 0, time.UTC), // 1 hour after deadline (issuerTokenDuration)
			expected: false,
		},
		{
			name: "past verification deadline",
			key: &signingKey{
				deadline: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			now:      time.Date(2023, 1, 1, 14, 0, 0, 0, time.UTC), // 2 hours after deadline
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			result := tt.key.expiredForVerifyingTokens(tt.now)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}
