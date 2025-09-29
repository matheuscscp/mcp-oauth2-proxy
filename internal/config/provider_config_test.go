package config

import (
	"regexp"
	"testing"

	. "github.com/onsi/gomega"
)

func TestProviderConfig_ValidateEmailDomain(t *testing.T) {
	tests := []struct {
		name     string
		provider ProviderConfig
		email    string
		expected bool
	}{
		{
			name: "no allowed domains - should allow all",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{},
			},
			email:    "test@example.com",
			expected: true,
		},
		{
			name: "valid email with matching domain",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@example.com",
			expected: true,
		},
		{
			name: "valid email with non-matching domain",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@other.com",
			expected: false,
		},
		{
			name: "invalid email format - no @",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
				},
			},
			email:    "invalid-email",
			expected: false,
		},
		{
			name: "invalid email format - multiple @",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
				},
			},
			email:    "user@domain@example.com",
			expected: false,
		},
		{
			name: "regex pattern matching subdomain",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`.*\.example\.com`),
				},
			},
			email:    "user@sub.example.com",
			expected: true,
		},
		{
			name: "regex pattern not matching subdomain",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`^example\.com$`),
				},
			},
			email:    "user@sub.example.com",
			expected: false,
		},
		{
			name: "multiple patterns - first matches",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@example.com",
			expected: true,
		},
		{
			name: "multiple patterns - second matches",
			provider: ProviderConfig{
				regexAllowedEmailDomains: []*regexp.Regexp{
					regexp.MustCompile(`example\.com`),
					regexp.MustCompile(`test\.org`),
				},
			},
			email:    "user@test.org",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			result := tt.provider.ValidateEmailDomain(tt.email)
			g.Expect(result).To(Equal(tt.expected))
		})
	}
}
