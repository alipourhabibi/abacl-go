package grant

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/abacl-go/utils"
	"github.com/alipourhabibi/gonotation/glob"
	"github.com/alipourhabibi/gonotation/notation"
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

func (g *Grant) Filter(data any) (map[string]any, error) {
	mapDatas := map[string]interface{}{}
	for _, v := range g.policies {
		globs := []glob.Glob{}
		for _, vv := range v.Filter {
			globs = append(globs, glob.NewGlob(vv))
		}
		data, err := g.filterOne(data, globs)
		if err != nil {
			return nil, err
		}
		if data != nil {
			t := map[string]interface{}{}
			err = json.Unmarshal([]byte(data.(string)), &t)
			if err != nil {
				return nil, err
			}
			for k, vv := range t {
				mapDatas[k] = vv
			}
		}
	}
	return mapDatas, nil
}

func (g *Grant) filterOne(data any, globs []glob.Glob) (any, error) {
	if len(globs) == 0 {
		return nil, nil
	}
	d, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	nn := notation.New(string(d))
	ss, err := nn.Filter(globs, false)
	if err != nil {
		return nil, err
	}
	return ss, nil
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
		globs := []glob.Glob{}
		if v.Field == nil {
			globs = append(globs, glob.NewGlob("*"))
		}
		for _, vv := range v.Field {
			globs = append(globs, glob.NewGlob(vv))
		}
		data, err := g.fieldOne(data, globs)
		if err != nil {
			return nil, err
		}
		if data != nil {
			t := map[string]interface{}{}
			err = json.Unmarshal([]byte(data.(string)), &t)
			if err != nil {
				return nil, err
			}
			for k, vv := range t {
				mapDatas[k] = vv
			}
		}
	}
	return mapDatas, nil
}

func (g *Grant) Field(data any) (map[string]any, error) {
	mapDatas := map[string]interface{}{}
	for _, v := range g.policies {
		globs := []glob.Glob{}
		for _, vv := range v.Field {
			globs = append(globs, glob.NewGlob(vv))
		}
		data, err := g.fieldOne(data, globs)
		if err != nil {
			return nil, err
		}
		if data != nil {
			t := map[string]interface{}{}
			err = json.Unmarshal([]byte(data.(string)), &t)
			if err != nil {
				return nil, err
			}
			for k, vv := range t {
				mapDatas[k] = vv
			}
		}
	}
	return mapDatas, nil
}

func (g *Grant) fieldOne(data any, globs []glob.Glob) (any, error) {
	if len(globs) == 0 {
		return nil, nil
	}
	d, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	nn := notation.New(string(d))
	ss, err := nn.Filter(globs, false)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (g *Grant) Scopes(cKey *utils.CacheKey, prop string) []string {
	scopeSet := []string{}
	if cKey == nil {
		for _, p := range g.present {
			switch prop {
			case "subject":
				s := g.parse(p.Subject)
				if s[1] != "" {
					scopeSet = append(scopeSet, s[1])
				}
			case "object":
				s := g.parse(p.Object)
				if s[1] != "" {
					scopeSet = append(scopeSet, s[1])
				}
			case "action":
				s := g.parse(p.Action)
				if s[1] != "" {
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
		for _, p := range newPols {
			switch prop {
			case "subject":
				s := g.parse(p.Subject)
				if s[1] != "" {
					scopeSet = append(scopeSet, s[1])
				}
			case "object":
				s := g.parse(p.Object)
				if s[1] != "" {
					scopeSet = append(scopeSet, s[1])
				}
			case "action":
				s := g.parse(p.Action)
				if s[1] != "" {
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
		if !g.strict {
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
