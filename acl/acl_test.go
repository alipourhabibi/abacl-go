package acl

import (
	"testing"

	"github.com/alipourhabibi/abacl-go/driver/memory"
	"github.com/alipourhabibi/abacl-go/mock"
	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/stretchr/testify/assert"
)

func TestAccessControl(t *testing.T) {
	drv := memory.Memory{}
	opts := AccessControlOptions{
		Strict: true,
	}

	ac, err := NewAccessControl(mock.Policies, opts, drv)
	if err != nil {
		t.Fatal(err)
	}

	// Existance
	exists := ac.Exists(mock.Policies[0])
	assert.False(t, !exists)
	p := policy.Policy{
		Subject: "noting",
		Object:  "nothing",
		Action:  "noting",
	}
	exists = ac.Exists(p)
	assert.False(t, exists)

	// Deletion
	ac.Delete(mock.Policies[1])
	exists = ac.Exists(mock.Policies[1])
	assert.False(t, exists)

	// Update
	ac.Update(mock.Policies[1])
	exists = ac.Exists(mock.Policies[1])
	assert.False(t, !exists)

	// Can
	can, err := ac.Can([]string{mock.User}, "read", "article")
	if err != nil {
		assert.Error(t, err)
	}
	assert.False(t, can.Granted())

	can, err = ac.Can([]string{mock.User}, "read:own", "article")
	if err != nil {
		assert.Error(t, err)
	}
	assert.True(t, can.Granted())

	can, err = ac.Can([]string{mock.User}, "read", "article:published")
	if err != nil {
		assert.Error(t, err)
	}
	assert.False(t, can.Granted())

	can, err = ac.Can([]string{mock.User}, "read", "article:published", true)
	if err != nil {
		assert.Error(t, err)
	}
	assert.False(t, can.Granted())

	can, err = ac.Can([]string{mock.User}, "read", "article:published", false)
	if err != nil {
		assert.Error(t, err)
	}
	assert.True(t, can.Granted())
}
