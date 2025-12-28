// permission/permission.go
package permission

import "github.com/alipourhabibi/abacl-go/grant"

// Permission represents the result of an access control check
type Permission struct {
	granted bool
	grant   *grant.Grant
}

// New creates a new Permission
func New(granted bool, g *grant.Grant) *Permission {
	return &Permission{
		granted: granted,
		grant:   g,
	}
}

// Granted returns true if access was granted
func (p *Permission) Granted() bool {
	return p.granted
}

// Denied returns true if access was denied
func (p *Permission) Denied() bool {
	return !p.granted
}

// Grant returns the underlying grant with matched policies
func (p *Permission) Grant() *grant.Grant {
	return p.grant
}

// Field is a convenience method to filter fields using the grant
// Use this to apply field visibility rules (what fields can be accessed)
func (p *Permission) Field(data any) (map[string]any, error) {
	if !p.granted || p.grant == nil {
		return nil, nil
	}
	return p.grant.Field(data)
}

// Filter is a convenience method to apply data filters using the grant
// Use this to apply query filtering rules (what data can be accessed)
func (p *Permission) Filter(data any) (map[string]any, error) {
	if !p.granted || p.grant == nil {
		return nil, nil
	}
	return p.grant.Filter(data)
}
