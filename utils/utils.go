package utils

import (
	"fmt"
	"strings"

	"github.com/alipourhabibi/abacl-go/policy"
)

const (
	SUB = "NULL"
	OBJ = "ANY"
	ACT = "ALL"
)

func Key(policy policy.Policy) string {
	subs := strings.Split(policy.Subject, ":")
	if len(subs) == 1 {
		subs = append(subs, SUB)
	}
	objs := strings.Split(policy.Object, ":")
	if len(objs) == 1 {
		objs = append(objs, OBJ)
	}
	acts := strings.Split(policy.Action, ":")
	if len(acts) == 1 {
		acts = append(acts, ACT)
	}
	key := fmt.Sprintf("%s:%s:%s:%s:%s:%s", subs[0], subs[1], objs[0], objs[1], acts[0], acts[1])
	return key
}

func PolicyStrictify(pol policy.Policy) policy.Policy {
	subs := strings.Split(pol.Subject, ":")
	if len(subs) == 1 {
		subs = append(subs, SUB)
	}
	objs := strings.Split(pol.Object, ":")
	if len(objs) == 1 {
		objs = append(objs, OBJ)
	}
	acts := strings.Split(pol.Action, ":")
	if len(acts) == 1 {
		acts = append(acts, ACT)
	}
	return policy.Policy{
		Subject: fmt.Sprintf("%s:%s", subs[0], ".*"),
		Object:  fmt.Sprintf("%s:%s", objs[0], ".*"),
		Action:  fmt.Sprintf("%s:%s", acts[0], ".*"),
	}
}
