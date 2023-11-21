package acl

import (
	"fmt"

	"github.com/alipourhabibi/abacl-go/driver"
	"github.com/alipourhabibi/abacl-go/grant"
	"github.com/alipourhabibi/abacl-go/permission"
	"github.com/alipourhabibi/abacl-go/policy"
	"github.com/alipourhabibi/abacl-go/utils"
)

type AccessControlOptions struct {
	Strict bool
}

type AccessControl struct {
	options AccessControlOptions
	driver  driver.Driver
}

func NewAccessControl(policy []policy.Policy, options AccessControlOptions, driver driver.Driver) (*AccessControl, error) {
	for _, v := range policy {
		driver.Update(v)
	}
	return &AccessControl{
		options: options,
		driver:  driver,
	}, nil
}

func (a *AccessControl) Clear() {
	a.driver.Clear()
}

func (a *AccessControl) Delete(p policy.Policy) {
	a.driver.Del(p)
}

func (a *AccessControl) Exists(p policy.Policy) bool {
	return a.driver.Exists(p)
}

func (a *AccessControl) Update(p policy.Policy) {
	a.driver.Update(p)

}

func (a *AccessControl) Get(strict bool, policy policy.Policy) ([]policy.Policy, bool) {
	// TODO
	if !strict {
		p := utils.PolicyStrictify(policy)
		fmt.Println(">>", p)
		return a.driver.Get(p)
	}
	return a.driver.Get(policy)
}

func (a *AccessControl) Can(sub []string, obj, act string) (*permission.Permission, error) {
	strict := a.options.Strict
	if len(sub) == 0 {
		return nil, fmt.Errorf("No subjects given")
	}

	// Generate an array of keys represengin different combination of subjects
	keys := []policy.Policy{}
	for _, v := range sub {
		pol := policy.Policy{}
		pol.Subject = v
		pol.Object = obj
		pol.Action = act
		keys = append(keys, pol)
	}
	/*
		for _, v := range sub {
			pol := policy.Policy{}
			pol.Subject = v
			pol.Object = obj
			pol.Action = act + ":" + utils.ACT
			keys = append(keys, pol)
		}
		for _, v := range sub {
			pol := policy.Policy{}
			pol.Subject = v
			pol.Object = obj + ":" + utils.OBJ
			pol.Action = act
			keys = append(keys, pol)
		}
		for _, v := range sub {
			pol := policy.Policy{}
			pol.Subject = v
			pol.Object = obj + ":" + utils.OBJ
			pol.Action = act + ":" + utils.ACT
			keys = append(keys, pol)
		}
	*/

	pols := []policy.Policy{}
	fmt.Println("KEYS", keys)
	for _, v := range keys {
		pol, ok := a.Get(strict, v)
		if ok {
			pols = append(pols, pol...)
		}
	}

	granted := len(pols) != 0
	grant, err := grant.NewGrant(pols, strict)
	if err != nil {
		return nil, err
	}

	return permission.NewPermission(granted, *grant)
}
