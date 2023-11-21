package driver

import (
	"github.com/alipourhabibi/abacl-go/policy"
)

type Driver interface {
	Clear()
	Set(policy.Policy)
	Exists(policy.Policy) bool
	Del(policy.Policy)
	Update(policy.Policy)
	Get(policy.Policy) ([]policy.Policy, bool)
}
