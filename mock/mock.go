package mock

import "github.com/alipourhabibi/abacl-go/policy"

const (
	Admin   = "admin"
	User    = "user"
	Guest   = "guest"
	Manager = "manager"
)

var Policies = []policy.Policy{
	{
		Subject: Admin,
		Action:  "any",
		Object:  "all",
	},
	{
		Subject: Guest,
		Action:  "read",
		Object:  "article:published",
	},
	{
		Subject: Guest,
		Action:  "create:own",
		Object:  "article:published",
	},
	{
		Subject: Manager,
		Action:  "any",
		Object:  "article",
	},
	{
		Subject: Manager,
		Action:  "read",
		Object:  "article:published",
		Filter:  []string{"*"},
	},
	{
		Subject: Manager,
		Action:  "update:shared",
		Object:  "article",
		Field:   []string{"*", "!id", "!owner"},
	},
	{
		Subject:  User,
		Action:   "create:own",
		Object:   "article",
		Field:    []string{"*", "!owner"},
		Location: []string{"192.168.2.10", "192.168.1.0/24"},
		Time: []policy.Time{
			{
				CronExp:  "* * 7 * * *", // from 7 AM
				Duration: 9 * 60 * 60,   // for 9 hours
			},
		},
	},
	{
		Subject: User,
		Action:  "read:own",
		Object:  "article",
	},
	{
		Subject: User,
		Action:  "read:shared",
		Object:  "article",
		Filter:  []string{"*", "!owner"},
	},
	{
		Subject: User,
		Action:  "delete:own",
		Object:  "article",
	},
	{
		Subject: User,
		Action:  "update:own",
		Object:  "article",
		Field:   []string{"*", "!id", "!owner"},
	},
}
