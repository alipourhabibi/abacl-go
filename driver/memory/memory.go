package memory

import (
	"regexp"

	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/abacl-go/utils"
)

type Memory map[string]policy.Policy

func (m Memory) Clear() {
	m = make(Memory, 0)
}

func (m Memory) Set(policy policy.Policy) {
	m[utils.Key(policy)] = policy
}

func (m Memory) Exists(policy policy.Policy) bool {
	_, ok := m[utils.Key(policy)]
	return ok
}

func (m Memory) Del(policy policy.Policy) {
	delete(m, utils.Key(policy))
}

func (m Memory) Update(policy policy.Policy) {
	m[utils.Key(policy)] = policy
}

func (m Memory) Get(pol policy.Policy) ([]policy.Policy, bool) {
	key := utils.Key(pol)
	pols := []policy.Policy{}
	for k := range m {
		ok, _ := regexp.MatchString(key, k)
		if ok {
			pols = append(pols, m[k])
		}
	}
	return pols, len(pols) != 0
}

func (m Memory) GetALL() Memory {
	return m
}
