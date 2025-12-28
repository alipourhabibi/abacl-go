// policy/policy.go
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Policy defines an access control rule
type Policy struct {
	Subject string // e.g., "user", "admin:readonly"
	Action  string // e.g., "read", "create:own"
	Object  string // e.g., "article", "article:published"

	// Optional constraints
	TimeWindows []TimeWindow
	Fields      []string // Field filters: ["*", "!password"]
	Filters     []string // Data filters
	Locations   []string // IP/CIDR restrictions
}

type TimeWindow struct {
	CronExpr string
	Duration int // Duration in seconds
}

// Validate checks if the policy is well-formed
func (p *Policy) Validate() error {
	if p.Subject == "" {
		return fmt.Errorf("policy subject cannot be empty")
	}
	if p.Action == "" {
		return fmt.Errorf("policy action cannot be empty")
	}
	if p.Object == "" {
		return fmt.Errorf("policy object cannot be empty")
	}

	// Validate no embedded colons break our assumptions
	if strings.Count(p.Subject, ":") > 1 {
		return fmt.Errorf("policy subject can contain at most one colon")
	}
	if strings.Count(p.Action, ":") > 1 {
		return fmt.Errorf("policy action can contain at most one colon")
	}
	if strings.Count(p.Object, ":") > 1 {
		return fmt.Errorf("policy object can contain at most one colon")
	}

	return nil
}

// Key generates a unique identifier for this policy
// Format: "subject:scope|action:scope|object:scope"
func (p *Policy) Key() string {
	subMain, subScope := ParseComponent(p.Subject)
	actMain, actScope := ParseComponent(p.Action)
	objMain, objScope := ParseComponent(p.Object)

	return fmt.Sprintf("%s:%s|%s:%s|%s:%s",
		subMain, subScope, actMain, actScope, objMain, objScope)
}

// ParseComponent extracts the main part and scope from a policy component
// e.g., "user:admin" -> ("user", "admin"), "read" -> ("read", "")
func ParseComponent(component string) (main, scope string) {
	parts := strings.SplitN(component, ":", 2)
	main = parts[0]
	if len(parts) > 1 {
		scope = parts[1]
	}
	return
}

// MatchPattern creates a regex pattern for matching policies
// When strict=false, wildcards match any scope; when true, exact match required
func (p *Policy) MatchPattern(strict bool) *regexp.Regexp {
	subMain, subScope := ParseComponent(p.Subject)
	actMain, actScope := ParseComponent(p.Action)
	objMain, objScope := ParseComponent(p.Object)

	// Escape special regex characters in the main parts
	subMain = regexp.QuoteMeta(subMain)
	actMain = regexp.QuoteMeta(actMain)
	objMain = regexp.QuoteMeta(objMain)

	var pattern string
	if strict {
		// Strict mode: exact match including scopes
		subScope = regexp.QuoteMeta(subScope)
		actScope = regexp.QuoteMeta(actScope)
		objScope = regexp.QuoteMeta(objScope)
		pattern = fmt.Sprintf("^%s:%s\\|%s:%s\\|%s:%s$",
			subMain, subScope, actMain, actScope, objMain, objScope)
	} else {
		// Non-strict: match any scope if not specified
		subPattern := subMain + ":"
		actPattern := actMain + ":"
		objPattern := objMain + ":"

		if subScope != "" {
			subPattern += regexp.QuoteMeta(subScope)
		} else {
			subPattern += ".*"
		}

		if actScope != "" {
			actPattern += regexp.QuoteMeta(actScope)
		} else {
			actPattern += ".*"
		}

		if objScope != "" {
			objPattern += regexp.QuoteMeta(objScope)
		} else {
			objPattern += ".*"
		}

		pattern = fmt.Sprintf("^%s\\|%s\\|%s$",
			subPattern, actPattern, objPattern)
	}

	// Compile once - panic if invalid since this is a programming error
	re, err := regexp.Compile(pattern)
	if err != nil {
		panic(fmt.Sprintf("invalid regex pattern %q: %v", pattern, err))
	}

	return re
}

// Matches checks if this policy matches another policy based on the strict mode
func (p *Policy) Matches(other *Policy, strict bool) bool {
	pattern := p.MatchPattern(strict)
	return pattern.MatchString(other.Key())
}
