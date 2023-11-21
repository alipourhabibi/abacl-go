package grant

import (
	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/abacl-go/utils"
	"golang.org/x/exp/maps"
)

type Grant struct {
	strict   bool
	policies []policy.Policy
	present  map[string]policy.Policy
}

func NewGrant(pols []policy.Policy, strict bool) (*Grant, error) {
	return &Grant{
		policies: pols,
		strict:   strict,
	}, nil
}

func (g *Grant) GetAll() []policy.Policy {
	return maps.Values(g.present)
}

func (g *Grant) Update(policy policy.Policy) {
	key := utils.Key(policy)
	g.present[key] = policy
}

func (g *Grant) Exists(policy policy.Policy) bool {
	_, ok := g.present[utils.Key(policy)]
	return ok
}

func (g *Grant) Delete(policy policy.Policy) {
	delete(g.present, utils.Key(policy))
}
