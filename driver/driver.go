// driver/driver.go
package driver

import "github.com/alipourhabibi/abacl-go/policy"

// Driver defines the storage interface for policies
type Driver interface {
	// Set stores or updates a policy
	Set(p policy.Policy) error

	// Get retrieves a specific policy by key
	Get(key string) (policy.Policy, bool)

	// Match searches for policies matching a pattern
	Match(pattern *policy.Policy, strict bool) ([]policy.Policy, error)

	// Delete removes a policy
	Delete(key string) error

	// Exists checks if a policy exists
	Exists(key string) bool

	// Clear removes all policies
	Clear() error

	// List returns all policy keys
	List() []string
}
