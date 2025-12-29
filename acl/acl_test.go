package acl

import (
	"testing"

	"github.com/alipourhabibi/abacl-go/driver/memory"
	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessControl_Basic(t *testing.T) {
	drv := memory.NewMemoryDriver()
	opts := Options{Strict: true}

	policies := []policy.Policy{
		{
			Subject: "user",
			Action:  "read",
			Object:  "article",
			Fields:  []string{"*", "!password"},
		},
		{
			Subject: "admin",
			Action:  "write",
			Object:  "article",
			Fields:  []string{"*"},
		},
	}

	ac, err := New(policies, opts, drv)
	require.NoError(t, err)
	require.NotNil(t, ac)

	// Test existence
	assert.True(t, ac.Exists(policies[0]))
	assert.True(t, ac.Exists(policies[1]))

	nonExistent := policy.Policy{
		Subject: "guest",
		Action:  "delete",
		Object:  "article",
	}
	assert.False(t, ac.Exists(nonExistent))
}

func TestAccessControl_Check(t *testing.T) {
	drv := memory.NewMemoryDriver()
	opts := Options{Strict: false}

	policies := []policy.Policy{
		{
			Subject: "user",
			Action:  "read:own",
			Object:  "article",
		},
		{
			Subject: "admin",
			Action:  "read",
			Object:  "article:published",
		},
		{
			Subject: "guest",
			Action:  "read",
			Object:  "article:published",
		},
	}

	ac, err := New(policies, opts, drv)
	require.NoError(t, err)

	t.Run("granted access - exact match", func(t *testing.T) {
		perm, err := ac.Check([]string{"user"}, "read:own", "article")
		require.NoError(t, err)
		assert.True(t, perm.Granted(), "user should have read:own access to article")
		assert.False(t, perm.Denied())
	})

	t.Run("denied access", func(t *testing.T) {
		perm, err := ac.Check([]string{"guest"}, "write", "article")
		require.NoError(t, err)
		assert.False(t, perm.Granted())
		assert.True(t, perm.Denied())
	})

	t.Run("multiple subjects", func(t *testing.T) {
		perm, err := ac.Check([]string{"guest", "user"}, "read:own", "article")
		require.NoError(t, err)
		assert.True(t, perm.Granted(), "should grant if any subject has access")
	})

	t.Run("strict vs non-strict", func(t *testing.T) {
		// Non-strict: "article" query should match "article:published" policy
		perm, err := ac.CheckWithOptions([]string{"admin"}, "read", "article", false)
		require.NoError(t, err)
		assert.True(t, perm.Granted(), "non-strict should match article:published")

		// Strict: exact match required - "article" != "article:published"
		perm, err = ac.CheckWithOptions([]string{"admin"}, "read", "article", true)
		require.NoError(t, err)
		assert.False(t, perm.Granted(), "strict should NOT match article:published when querying article")

		// But exact match should work
		perm, err = ac.CheckWithOptions([]string{"admin"}, "read", "article:published", true)
		require.NoError(t, err)
		assert.True(t, perm.Granted(), "strict should match with exact object scope")
	})

	t.Run("wildcard action scope", func(t *testing.T) {
		// Non-strict: querying "read" (no scope) should match "read:own"
		perm, err := ac.CheckWithOptions([]string{"user"}, "read", "article", false)
		require.NoError(t, err)
		assert.True(t, perm.Granted(), "wildcard action should match read:own")
	})
}

func TestAccessControl_CRUD(t *testing.T) {
	drv := memory.NewMemoryDriver()
	opts := Options{Strict: true}

	ac, err := New([]policy.Policy{}, opts, drv)
	require.NoError(t, err)

	p := policy.Policy{
		Subject: "user",
		Action:  "read",
		Object:  "document",
	}

	// Add
	err = ac.Add(p)
	require.NoError(t, err)
	assert.True(t, ac.Exists(p))

	// Remove
	err = ac.Remove(p)
	require.NoError(t, err)
	assert.False(t, ac.Exists(p))

	// Clear
	err = ac.Add(p)
	require.NoError(t, err)
	err = ac.Clear()
	require.NoError(t, err)
	assert.False(t, ac.Exists(p))
}

func TestAccessControl_Validation(t *testing.T) {
	drv := memory.NewMemoryDriver()
	opts := Options{Strict: true}

	ac, err := New([]policy.Policy{}, opts, drv)
	require.NoError(t, err)

	t.Run("empty subject", func(t *testing.T) {
		p := policy.Policy{
			Subject: "",
			Action:  "read",
			Object:  "article",
		}
		err := ac.Add(p)
		assert.Error(t, err)
	})

	t.Run("empty action", func(t *testing.T) {
		p := policy.Policy{
			Subject: "user",
			Action:  "",
			Object:  "article",
		}
		err := ac.Add(p)
		assert.Error(t, err)
	})

	t.Run("no subjects in Check", func(t *testing.T) {
		_, err := ac.Check([]string{}, "read", "article")
		assert.Error(t, err)
	})
}

func TestMemoryDriver_Clear(t *testing.T) {
	drv := memory.NewMemoryDriver()

	p := policy.Policy{
		Subject: "user",
		Action:  "read",
		Object:  "article",
	}

	err := drv.Set(p)
	require.NoError(t, err)
	assert.True(t, drv.Exists(p.Key()))

	// Clear should actually remove items
	err = drv.Clear()
	require.NoError(t, err)
	assert.False(t, drv.Exists(p.Key()))

	// Should be able to add after clear
	err = drv.Set(p)
	require.NoError(t, err)
	assert.True(t, drv.Exists(p.Key()))
}

func TestAccessControl_Get(t *testing.T) {
	drv := memory.NewMemoryDriver()
	opts := Options{Strict: false}

	policies := []policy.Policy{
		{
			Subject: "user",
			Action:  "read:own",
			Object:  "article",
		},
		{
			Subject: "user",
			Action:  "read:shared",
			Object:  "article",
		},
		{
			Subject: "admin",
			Action:  "read",
			Object:  "article:published",
		},
	}

	ac, err := New(policies, opts, drv)
	require.NoError(t, err)

	t.Run("find all read actions for user", func(t *testing.T) {
		searchPol := policy.Policy{
			Subject: "user",
			Action:  "read",
			Object:  "article",
		}
		results, err := ac.Get(false, searchPol)
		require.NoError(t, err)
		assert.Len(t, results, 2, "should find both read:own and read:shared")
	})

	t.Run("strict matching", func(t *testing.T) {
		searchPol := policy.Policy{
			Subject: "user",
			Action:  "read:own",
			Object:  "article",
		}
		results, err := ac.Get(true, searchPol)
		require.NoError(t, err)
		assert.Len(t, results, 1, "should only find exact match")
	})
}

func BenchmarkAccessControl_Check(b *testing.B) {
	drv := memory.NewMemoryDriver()
	opts := Options{Strict: false}

	// Create 100 policies
	policies := make([]policy.Policy, 100)
	for i := 0; i < 100; i++ {
		policies[i] = policy.Policy{
			Subject: "user",
			Action:  "read",
			Object:  "article",
		}
	}

	ac, _ := New(policies, opts, drv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ac.Check([]string{"user"}, "read", "article")
		require.NoError(b, err)
	}
}
