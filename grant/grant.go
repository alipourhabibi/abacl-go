package grant

import (
	"regexp"
	"strings"

	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/abacl-go/utils"
	"github.com/alipourhabibi/gonotation/v2/notation"
	"golang.org/x/exp/maps"
)

type Grant struct {
	strict   bool
	policies []policy.Policy
	present  map[string]policy.Policy
}

func (g *Grant) GetPresent() map[string]policy.Policy {
	return g.present
}

func NewGrant(pols []policy.Policy, strict bool) (*Grant, error) {
	grant := &Grant{
		policies: pols,
		strict:   strict,
	}
	grant.present = map[string]policy.Policy{}
	for _, v := range pols {
		grant.Update(v)
	}
	return grant, nil
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

func (g *Grant) Filter(data any) (map[string]any, error) {
	filters := []string{}
	for _, v := range g.policies {
		filters = append(filters, v.Field...)
	}
	return notation.FilterMap(data, filters)
}

func (g *Grant) filterOne(data any, globs []string) (any, error) {
	return notation.FilterMap(data, globs)
}

func (g *Grant) FieldByCKey(data any, cKey utils.CacheKey) (map[string]any, error) {
	if g.present == nil {
		g.present = map[string]policy.Policy{}
	}
	for _, v := range g.policies {
		g.Update(v)
	}
	newPols := []policy.Policy{}
	cKeyPol := policy.Policy{
		Subject: cKey.Subject,
		Object:  cKey.Object,
		Action:  cKey.Action,
	}
	if !g.strict {
		p := utils.PolicyStrictify(cKeyPol)
		newPols, _ = g.Get(p)
	} else {
		newPols, _ = g.Get(cKeyPol)
	}
	mapDatas := map[string]interface{}{}
	for _, v := range newPols {
		globs := []string{}
		if v.Field == nil {
			globs = append(globs, "*")
		}
		for _, vv := range v.Field {
			globs = append(globs, vv)
		}
		data, err := g.fieldOne(data, globs)
		if err != nil {
			return nil, err
		}
		for k, vv := range data.(map[string]any) {
			mapDatas[k] = vv
		}
	}
	return mapDatas, nil
}

func (g *Grant) Field(data any) (map[string]any, error) {
	fields := []string{}
	for _, v := range g.policies {
		fields = append(fields, v.Field...)
	}
	return notation.FilterMap(data, fields)
}

func (g *Grant) fieldOne(data any, globs []string) (any, error) {
	return notation.FilterMap(data, globs)
}

func (g *Grant) Scopes(cKey *utils.CacheKey, prop string) []string {
	scopeSet := []string{}
	if cKey == nil {
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
	} else {
		newPols := []policy.Policy{}
		cKeyPol := policy.Policy{
			Subject: cKey.Subject,
			Object:  cKey.Object,
			Action:  cKey.Action,
		}
		if !g.strict {
			p := utils.PolicyStrictify(cKeyPol)
			newPols, _ = g.Get(p)
		} else {
			newPols, _ = g.Get(cKeyPol)
		}

		// newPols = append(newPols, cKeyPol)
		for _, p := range newPols {
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
	}
	return scopeSet
}

func (g *Grant) Subjects(cKey *utils.CacheKey) []string {
	subjects := []string{}
	if cKey == nil {
		for _, v := range g.present {
			subjects = append(subjects, v.Subject)
		}
	} else {
		newPols := []policy.Policy{}
		cKeyPol := policy.Policy{
			Subject: cKey.Subject,
			Object:  cKey.Object,
			Action:  cKey.Action,
		}
		if !cKey.Strict {
			p := utils.PolicyStrictify(cKeyPol)
			newPols, _ = g.Get(p)
		} else {
			newPols, _ = g.Get(cKeyPol)
		}
		for _, v := range newPols {
			subjects = append(subjects, v.Subject)
		}
	}

	return subjects
}

func (g *Grant) parse(prop string) []string {
	// 0: main
	// 1: scope
	return strings.Split(prop, ":")
}

func (g *Grant) Get(pol policy.Policy) ([]policy.Policy, bool) {
	key := utils.Key(pol)
	pols := []policy.Policy{}
	m := g.present
	for k := range m {
		ok, _ := regexp.MatchString(key, k)
		if ok {
			pols = append(pols, m[k])
		}
	}
	return pols, len(pols) != 0
}
