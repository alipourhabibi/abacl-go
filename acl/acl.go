// acl/acl.go
package acl

import (
	"fmt"

	"github.com/alipourhabibi/abacl-go/driver"
	"github.com/alipourhabibi/abacl-go/grant"
	"github.com/alipourhabibi/abacl-go/permission"
	"github.com/alipourhabibi/abacl-go/policy"
)

// Options configures the access control behavior
type Options struct {
	// Strict mode requires exact scope matching
	// If false, scopes are matched with wildcards
	Strict bool
}

// AccessControl manages policy-based access control
type AccessControl struct {
	opts   Options
	driver driver.Driver
}

// New creates a new AccessControl instance with the given policies
func New(policies []policy.Policy, opts Options, drv driver.Driver) (*AccessControl, error) {
	if drv == nil {
		return nil, fmt.Errorf("driver cannot be nil")
	}

	ac := &AccessControl{
		opts:   opts,
		driver: drv,
	}

	// Load initial policies
	for _, p := range policies {
		if err := ac.Add(p); err != nil {
			return nil, fmt.Errorf("failed to add policy: %w", err)
		}
	}

	return ac, nil
}

// Add adds or updates a policy
func (ac *AccessControl) Add(p policy.Policy) error {
	return ac.driver.Set(p)
}

// Remove deletes a policy
func (ac *AccessControl) Remove(p policy.Policy) error {
	return ac.driver.Delete(p.Key())
}

// Exists checks if a policy exists
func (ac *AccessControl) Exists(p policy.Policy) bool {
	return ac.driver.Exists(p.Key())
}

// Clear removes all policies
func (ac *AccessControl) Clear() error {
	return ac.driver.Clear()
}

// Query searches for policies matching the given criteria
func (ac *AccessControl) Query(subject, action, object string, strict bool) ([]policy.Policy, error) {
	queryPolicy := policy.Policy{
		Subject: subject,
		Action:  action,
		Object:  object,
	}

	return ac.driver.Match(&queryPolicy, strict)
}

// Check evaluates if the given subjects have permission to perform an action on an object
// Returns a Permission object containing the result and applicable grants
func (ac *AccessControl) Check(subjects []string, action, object string) (*permission.Permission, error) {
	return ac.CheckWithOptions(subjects, action, object, ac.opts.Strict)
}

// CheckWithOptions is like Check but allows overriding the strict mode
func (ac *AccessControl) CheckWithOptions(subjects []string, action, object string, strict bool) (*permission.Permission, error) {
	if len(subjects) == 0 {
		return nil, fmt.Errorf("at least one subject is required")
	}
	if action == "" {
		return nil, fmt.Errorf("action cannot be empty")
	}
	if object == "" {
		return nil, fmt.Errorf("object cannot be empty")
	}

	// Collect all matching policies for all subjects
	var allPolicies []policy.Policy
	for _, subject := range subjects {
		policies, err := ac.Query(subject, action, object, strict)
		if err != nil {
			return nil, fmt.Errorf("query failed for subject %s: %w", subject, err)
		}
		allPolicies = append(allPolicies, policies...)
	}

	// Create grant from matched policies
	g, err := grant.New(allPolicies, strict)
	if err != nil {
		return nil, fmt.Errorf("failed to create grant: %w", err)
	}

	// Permission is granted if we found any matching policies
	granted := len(allPolicies) > 0

	return permission.New(granted, g), nil
}

// ListAll returns all stored policies
func (ac *AccessControl) ListAll() ([]policy.Policy, error) {
	keys := ac.driver.List()
	policies := make([]policy.Policy, 0, len(keys))

	for _, key := range keys {
		if p, ok := ac.driver.Get(key); ok {
			policies = append(policies, p)
		}
	}

	return policies, nil
}
