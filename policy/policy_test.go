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
			expected: "user:NULL:read:ALL:article:ANY",
		},
		{
			name: "policy with scopes",
			policy: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			expected: "user:NULL:read:own:article:ANY",
		},
		{
			name: "all with scopes",
			policy: Policy{
				Subject: "admin",
				Action:  "read:own",
				Object:  "article:published",
			},
			expected: "admin:NULL:read:own:article:published",
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

func TestPolicyStrictify(t *testing.T) {
	tests := []struct {
		name     string
		policy   Policy
		expected string
	}{
		{
			name: "strictify simple policy",
			policy: Policy{
				Subject: "user",
				Action:  "read",
				Object:  "article",
			},
			expected: "user:\\w+:read:\\w+:article:\\w+",
		},
		{
			name: "strictify with scope",
			policy: Policy{
				Subject: "user",
				Action:  "read:own",
				Object:  "article",
			},
			expected: "user:\\w+:read:\\w+:article:\\w+",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strictified := tt.policy.Strictify()
			key := strictified.Key()
			t.Logf("Strictified key: %s", key)
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{
			name: "valid policy",
			policy: Policy{
				Subject: "user",
				Action:  "read",
				Object:  "article",
			},
			wantErr: false,
		},
		{
			name: "empty subject",
			policy: Policy{
				Subject: "",
				Action:  "read",
				Object:  "article",
			},
			wantErr: true,
		},
		{
			name: "empty action",
			policy: Policy{
				Subject: "user",
				Action:  "",
				Object:  "article",
			},
			wantErr: true,
		},
		{
			name: "empty object",
			policy: Policy{
				Subject: "user",
				Action:  "read",
				Object:  "",
			},
			wantErr: true,
		},
		{
			name: "too many colons in subject",
			policy: Policy{
				Subject: "user:admin:super",
				Action:  "read",
				Object:  "article",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
