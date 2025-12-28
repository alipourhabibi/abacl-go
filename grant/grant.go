// grant/grant.go
package grant

import (
	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/gonotation/v2/notation"
)

// Grant represents a collection of policies that were matched for an access check
type Grant struct {
	strict   bool
	policies []policy.Policy
}

// New creates a new Grant from the given policies
func New(policies []policy.Policy, strict bool) (*Grant, error) {
	return &Grant{
		policies: policies,
		strict:   strict,
	}, nil
}

// Policies returns all policies in this grant
func (g *Grant) Policies() []policy.Policy {
	return g.policies
}

// Subjects returns all unique subjects from the grant's policies
func (g *Grant) Subjects() []string {
	seen := make(map[string]bool)
	var subjects []string

	for _, p := range g.policies {
		if !seen[p.Subject] {
			seen[p.Subject] = true
			subjects = append(subjects, p.Subject)
		}
	}

	return subjects
}

// Actions returns all unique actions from the grant's policies
func (g *Grant) Actions() []string {
	seen := make(map[string]bool)
	var actions []string

	for _, p := range g.policies {
		if !seen[p.Action] {
			seen[p.Action] = true
			actions = append(actions, p.Action)
		}
	}

	return actions
}

// Objects returns all unique objects from the grant's policies
func (g *Grant) Objects() []string {
	seen := make(map[string]bool)
	var objects []string

	for _, p := range g.policies {
		if !seen[p.Object] {
			seen[p.Object] = true
			objects = append(objects, p.Object)
		}
	}

	return objects
}

// Scopes extracts unique scopes from a specific component (subject, action, or object)
func (g *Grant) Scopes(component string) []string {
	seen := make(map[string]bool)
	var scopes []string

	for _, p := range g.policies {
		var value string
		switch component {
		case "subject":
			value = p.Subject
		case "action":
			value = p.Action
		case "object":
			value = p.Object
		default:
			continue
		}

		_, scope := policy.ParseComponent(value)
		if scope != "" && !seen[scope] {
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}

	return scopes
}

// Field applies field filters from all policies to the given data
// Field filters define which fields can be accessed (e.g., ["*", "!password"])
// Returns a filtered map containing only allowed fields
func (g *Grant) Field(data any) (map[string]any, error) {
	if len(g.policies) == 0 {
		return nil, nil
	}

	// Collect all field patterns from policies
	var patterns []string
	for _, p := range g.policies {
		if len(p.Fields) > 0 {
			patterns = append(patterns, p.Fields...)
		} else {
			// If a policy has no field restrictions, allow all
			patterns = append(patterns, "*")
		}
	}

	// If no field patterns specified, allow all
	if len(patterns) == 0 {
		patterns = []string{"*"}
	}

	// Remove duplicates
	uniquePatterns := make(map[string]bool)
	var finalPatterns []string
	for _, p := range patterns {
		if !uniquePatterns[p] {
			uniquePatterns[p] = true
			finalPatterns = append(finalPatterns, p)
		}
	}

	return notation.FilterMap(data, finalPatterns)
}

// Filter applies data filters from policies
// Filter is used for query filtering (e.g., ["status:published"])
// This is separate from Field which controls field visibility
func (g *Grant) Filter(data any) (map[string]any, error) {
	if len(g.policies) == 0 {
		return nil, nil
	}

	var patterns []string
	for _, p := range g.policies {
		if len(p.Filters) > 0 {
			patterns = append(patterns, p.Filters...)
		}
	}

	if len(patterns) == 0 {
		// No filters means allow all
		if m, ok := data.(map[string]any); ok {
			return m, nil
		}
		return notation.FilterMap(data, []string{"*"})
	}

	return notation.FilterMap(data, patterns)
}

// CacheKey represents a query key for filtering policies
type CacheKey struct {
	Subject string
	Action  string
	Object  string
	Strict  bool
}

// FieldByCKey filters data based on field permissions matching a specific cache key
// This queries the grant's policies for matches and applies their field filters
// Use this when you need to apply field filtering for a specific subject/action/object combination
func (g *Grant) FieldByCKey(data any, key CacheKey) (map[string]any, error) {
	// Find matching policies based on the cache key
	matchingPolicies := g.findMatchingPolicies(key)

	if len(matchingPolicies) == 0 {
		// No matching policies - deny all fields
		return map[string]any{}, nil
	}

	// Collect field patterns from all matching policies
	fieldPatterns := []string{}

	for _, p := range matchingPolicies {
		if len(p.Fields) == 0 {
			// No field restrictions means allow all
			fieldPatterns = append(fieldPatterns, "*")
		} else {
			fieldPatterns = append(fieldPatterns, p.Fields...)
		}
	}

	// If no field patterns specified, allow all
	if len(fieldPatterns) == 0 {
		fieldPatterns = []string{"*"}
	}

	// Remove duplicates
	uniquePatterns := make(map[string]bool)
	var finalPatterns []string
	for _, p := range fieldPatterns {
		if !uniquePatterns[p] {
			uniquePatterns[p] = true
			finalPatterns = append(finalPatterns, p)
		}
	}

	return notation.FilterMap(data, finalPatterns)
}

// FilterByCKey applies data filters matching a specific cache key
// This is separate from FieldByCKey - it applies data filtering, not field visibility
func (g *Grant) FilterByCKey(data any, key CacheKey) (map[string]any, error) {
	// Find matching policies based on the cache key
	matchingPolicies := g.findMatchingPolicies(key)

	if len(matchingPolicies) == 0 {
		// No matching policies
		return map[string]any{}, nil
	}

	// Collect filter patterns from all matching policies
	filterPatterns := []string{}

	for _, p := range matchingPolicies {
		if len(p.Filters) > 0 {
			filterPatterns = append(filterPatterns, p.Filters...)
		}
	}

	// If no filter patterns, allow all
	if len(filterPatterns) == 0 {
		if m, ok := data.(map[string]any); ok {
			return m, nil
		}
		return notation.FilterMap(data, []string{"*"})
	}

	// Remove duplicates
	uniquePatterns := make(map[string]bool)
	var finalPatterns []string
	for _, p := range filterPatterns {
		if !uniquePatterns[p] {
			uniquePatterns[p] = true
			finalPatterns = append(finalPatterns, p)
		}
	}

	return notation.FilterMap(data, finalPatterns)
}

// findMatchingPolicies finds policies in the grant that match the given key
func (g *Grant) findMatchingPolicies(key CacheKey) []policy.Policy {
	queryPolicy := policy.Policy{
		Subject: key.Subject,
		Action:  key.Action,
		Object:  key.Object,
	}

	var matches []policy.Policy
	pattern := queryPolicy.MatchPattern(key.Strict)

	for _, p := range g.policies {
		if pattern.MatchString(p.Key()) {
			matches = append(matches, p)
		}
	}

	return matches
}
