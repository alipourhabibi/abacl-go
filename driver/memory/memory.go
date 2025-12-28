// driver/memory/memory.go
package memory

import (
	"fmt"
	"sync"

	"github.com/alipourhabibi/abacl-go/policy"
)

// MemoryDriver provides an in-memory implementation of the Driver interface
type MemoryDriver struct {
	mu       sync.RWMutex
	policies map[string]policy.Policy
}

// NewMemoryDriver creates a new in-memory driver
func NewMemoryDriver() *MemoryDriver {
	return &MemoryDriver{
		policies: make(map[string]policy.Policy),
	}
}

func (m *MemoryDriver) Set(p policy.Policy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.policies[p.Key()] = p
	return nil
}

func (m *MemoryDriver) Get(key string) (policy.Policy, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.policies[key]
	return p, ok
}

func (m *MemoryDriver) Match(pattern *policy.Policy, strict bool) ([]policy.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []policy.Policy

	// Generate regex pattern from the query policy
	re := pattern.MatchPattern(strict)

	// Match against all stored policies
	for _, p := range m.policies {
		if re.MatchString(p.Key()) {
			results = append(results, p)
		}
	}

	return results, nil
}

func (m *MemoryDriver) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.policies, key)
	return nil
}

func (m *MemoryDriver) Exists(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, ok := m.policies[key]
	return ok
}

func (m *MemoryDriver) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Correctly clear the map
	m.policies = make(map[string]policy.Policy)
	return nil
}

func (m *MemoryDriver) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]string, 0, len(m.policies))
	for k := range m.policies {
		keys = append(keys, k)
	}
	return keys
}
