// policy/policy_test.go
package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyKey(t *testing.T) {
	tests := []struct {
		name     string
		policy   Policy
		expected string
	}{
		{
			name: "simple policy",
			policy: Policy{
				Subject: "user",
				Action:  "read",
				Object:  "article",
			},
			expected: "user:|read:|article:",
		},
		{
			name: "policy with scopes",
			policy: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			expected: "user:|read:own|article:",
		},
		{
			name: "all with scopes",
			policy: Policy{
				Subject: "admin",
				Action:  "read:own",
				Object:  "article:published",
			},
			expected: "admin:|read:own|article:published",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.policy.Key()
			t.Logf("Generated key: %s", key)
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestPolicyMatching(t *testing.T) {
	tests := []struct {
		name     string
		stored   Policy
		query    Policy
		strict   bool
		expected bool
	}{
		{
			name: "exact match - strict",
			stored: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			query: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			strict:   true,
			expected: true,
		},
		{
			name: "scope wildcard - non-strict",
			stored: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			query: Policy{
				Subject: "user",
				Action:  "read", // No scope = wildcard
				Object:  "article",
			},
			strict:   false,
			expected: true,
		},
		{
			name: "scope mismatch - strict",
			stored: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			query: Policy{
				Subject: "user",
				Action:  "read:shared",
				Object:  "article",
			},
			strict:   true,
			expected: false,
		},
		{
			name: "object scope match - non-strict",
			stored: Policy{
				Subject: "admin",
				Action:  "read",
				Object:  "article:published",
			},
			query: Policy{
				Subject: "admin",
				Action:  "read",
				Object:  "article", // Should match article:published in non-strict
			},
			strict:   false,
			expected: true,
		},
		{
			name: "object scope mismatch - strict",
			stored: Policy{
				Subject: "admin",
				Action:  "read",
				Object:  "article:published",
			},
			query: Policy{
				Subject: "admin",
				Action:  "read",
				Object:  "article", // Should NOT match in strict mode
			},
			strict:   true,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := tt.query.MatchPattern(tt.strict)
			matches := pattern.MatchString(tt.stored.Key())

			t.Logf("Stored key: %s", tt.stored.Key())
			t.Logf("Query pattern: %s", pattern.String())
			t.Logf("Matches: %v (expected: %v)", matches, tt.expected)

			assert.Equal(t, tt.expected, matches)
		})
	}
}

func TestParseComponent(t *testing.T) {
	tests := []struct {
		input         string
		expectedMain  string
		expectedScope string
	}{
		{"user", "user", ""},
		{"user:admin", "user", "admin"},
		{"read:own", "read", "own"},
		{"article:published", "article", "published"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			main, scope := ParseComponent(tt.input)
			assert.Equal(t, tt.expectedMain, main)
			assert.Equal(t, tt.expectedScope, scope)
		})
	}
}
