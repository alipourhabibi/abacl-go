package permission

import "github.com/alipourhabibi/abacl-go/grant"

type Permission struct {
	granted bool
	grant   grant.Grant
}

func NewPermission(granted bool, grant grant.Grant) (*Permission, error) {
	return &Permission{
		granted: granted,
		grant:   grant,
	}, nil
}

func (p *Permission) Granted() bool {
	return p.granted
}

func (p *Permission) Grant() grant.Grant {
	return p.grant
}
