package policy

import (
	"fmt"
	"strings"
	"time"
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
	Duration time.Duration
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

	// Validate no more than one colon
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

// Key generates a unique identifier for this policy using your original format
func (p *Policy) Key() string {
	subs := strings.Split(p.Subject, ":")
	if len(subs) == 1 {
		subs = append(subs, "NULL")
	}
	objs := strings.Split(p.Object, ":")
	if len(objs) == 1 {
		objs = append(objs, "ANY")
	}
	acts := strings.Split(p.Action, ":")
	if len(acts) == 1 {
		acts = append(acts, "ALL")
	}
	key := fmt.Sprintf("%s:%s:%s:%s:%s:%s", subs[0], subs[1], acts[0], acts[1], objs[0], objs[1])
	return key
}

// Strictify converts a policy to use regex wildcards for non-strict matching
func (p *Policy) Strictify() Policy {
	subs := strings.Split(p.Subject, ":")
	if len(subs) == 1 {
		subs = append(subs, "NULL")
	}
	objs := strings.Split(p.Object, ":")
	if len(objs) == 1 {
		objs = append(objs, "ANY")
	}
	acts := strings.Split(p.Action, ":")
	if len(acts) == 1 {
		acts = append(acts, "ALL")
	}

	return Policy{
		Subject: fmt.Sprintf("%s:%s", subs[0], "\\w+"),
		Object:  fmt.Sprintf("%s:%s", objs[0], "\\w+"),
		Action:  fmt.Sprintf("%s:%s", acts[0], "\\w+"),
	}
}
