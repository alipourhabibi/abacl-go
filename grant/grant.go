package grant

import (
	"regexp"
	"strings"

	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/gonotation/v2/notation"
)

// Grant represents a collection of policies that were matched for an access check
type Grant struct {
	strict   bool
	policies []policy.Policy
	present  map[string]policy.Policy
}

// New creates a new Grant from the given policies
func New(policies []policy.Policy, strict bool) (*Grant, error) {
	grant := &Grant{
		policies: policies,
		strict:   strict,
		present:  make(map[string]policy.Policy),
	}

	// Build present map for quick lookups
	for _, p := range policies {
		grant.present[p.Key()] = p
	}

	return grant, nil
}

// GetPresent returns the present map
func (g *Grant) GetPresent() map[string]policy.Policy {
	return g.present
}

// Policies returns all policies in this grant
func (g *Grant) Policies() []policy.Policy {
	return g.policies
}

// Update adds or updates a policy in the grant
func (g *Grant) Update(p policy.Policy) {
	g.present[p.Key()] = p
}

// Exists checks if a policy exists in the grant
func (g *Grant) Exists(p policy.Policy) bool {
	_, ok := g.present[p.Key()]
	return ok
}

// Delete removes a policy from the grant
func (g *Grant) Delete(p policy.Policy) {
	delete(g.present, p.Key())
}

// Get finds policies matching the given policy pattern (using regex)
func (g *Grant) Get(pol policy.Policy) ([]policy.Policy, bool) {
	key := pol.Key()
	pols := []policy.Policy{}

	for k := range g.present {
		ok, _ := regexp.MatchString(key, k)
		if ok {
			pols = append(pols, g.present[k])
		}
	}
	return pols, len(pols) != 0
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

// parse extracts main and scope from a component string
func (g *Grant) parse(prop string) []string {
	// 0: main
	// 1: scope
	return strings.Split(prop, ":")
}

// Scopes extracts unique scopes from a specific component (subject, action, or object)
func (g *Grant) Scopes(prop string) []string {
	scopeSet := []string{}

	for _, p := range g.present {
		switch prop {
		case "subject":
			s := g.parse(p.Subject)
			if len(s) > 1 && s[1] != "" {
				scopeSet = append(scopeSet, s[1])
			}
		case "object":
			s := g.parse(p.Object)
			if len(s) > 1 && s[1] != "" {
				scopeSet = append(scopeSet, s[1])
			}
		case "action":
			s := g.parse(p.Action)
			if len(s) > 1 && s[1] != "" {
				scopeSet = append(scopeSet, s[1])
			}
		}
	}

	return scopeSet
}

// Field applies field filters from all policies to the given data
func (g *Grant) Field(data any) (map[string]any, error) {
	fields := []string{}
	for _, p := range g.policies {
		fields = append(fields, p.Fields...)
	}

	if len(fields) == 0 {
		return notation.FilterMap(data, []string{"*"})
	}

	return notation.FilterMap(data, fields)
}

// Filter applies data filters from policies
func (g *Grant) Filter(data any) (map[string]any, error) {
	filters := []string{}
	for _, p := range g.policies {
		filters = append(filters, p.Filters...)
	}

	if len(filters) == 0 {
		if m, ok := data.(map[string]any); ok {
			return m, nil
		}
		return notation.FilterMap(data, []string{"*"})
	}

	return notation.FilterMap(data, filters)
}

// CacheKey represents a query key for filtering policies
type CacheKey struct {
	Subject string
	Action  string
	Object  string
	Strict  bool
}

// FieldByCKey filters data based on field permissions matching a specific cache key
// This is your original implementation
func (g *Grant) FieldByCKey(data any, cKey CacheKey) (map[string]any, error) {
	if g.present == nil {
		g.present = make(map[string]policy.Policy)
	}

	// Ensure present map is populated
	for _, p := range g.policies {
		g.Update(p)
	}

	// Find matching policies
	var newPols []policy.Policy
	cKeyPol := policy.Policy{
		Subject: cKey.Subject,
		Object:  cKey.Object,
		Action:  cKey.Action,
	}

	if !cKey.Strict {
		p := cKeyPol.Strictify()
		newPols, _ = g.Get(p)
	} else {
		newPols, _ = g.Get(cKeyPol)
	}

	// Collect field patterns from matching policies
	mapDatas := map[string]any{}
	for _, p := range newPols {
		globs := []string{}
		if len(p.Fields) == 0 {
			globs = append(globs, "*")
		} else {
			globs = append(globs, p.Fields...)
		}

		data, err := notation.FilterMap(data, globs)
		if err != nil {
			return nil, err
		}

		for k, vv := range data {
			mapDatas[k] = vv
		}
	}

	return mapDatas, nil
}

// FilterByCKey applies data filters matching a specific cache key
func (g *Grant) FilterByCKey(data any, cKey CacheKey) (map[string]any, error) {
	if g.present == nil {
		g.present = make(map[string]policy.Policy)
	}

	for _, p := range g.policies {
		g.Update(p)
	}

	// Find matching policies
	var newPols []policy.Policy
	cKeyPol := policy.Policy{
		Subject: cKey.Subject,
		Object:  cKey.Object,
		Action:  cKey.Action,
	}

	if !cKey.Strict {
		p := cKeyPol.Strictify()
		newPols, _ = g.Get(p)
	} else {
		newPols, _ = g.Get(cKeyPol)
	}

	// Collect filter patterns
	mapDatas := map[string]any{}
	for _, p := range newPols {
		globs := []string{}
		if len(p.Filters) == 0 {
			// No filters means allow all
			if m, ok := data.(map[string]any); ok {
				return m, nil
			}
			globs = append(globs, "*")
		} else {
			globs = append(globs, p.Filters...)
		}

		filtered, err := notation.FilterMap(data, globs)
		if err != nil {
			return nil, err
		}

		for k, vv := range filtered {
			mapDatas[k] = vv
		}
	}

	return mapDatas, nil
}
