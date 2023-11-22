package grant

import (
	"encoding/json"

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
