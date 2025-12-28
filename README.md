# abacl-go

A lightweight, policy-based access control library for Go. Define permissions using subjects, actions, objects, scopes, field restrictions, and data filters. Policies use pluggable drivers (e.g., in-memory).

## Features

- Policy rules: Subjects (e.g., "user:admin"), actions (e.g., "read:own"), objects (e.g., "article:published").
- Scope matching: Strict (exact) or non-strict (wildcard).
- Field & data filters: Control visibility (e.g., ["*", "!password"]) and queries (e.g., "status:published").

## Installation

```bash
go get github.com/alipourhabibi/abacl-go
```

## Quick Start

```go
package main

import (
	"fmt"
	"github.com/alipourhabibi/abacl-go/acl"
	"github.com/alipourhabibi/abacl-go/driver/memory"
	"github.com/alipourhabibi/abacl-go/policy"
)

func main() {
	drv := memory.NewMemoryDriver()
	policies := []policy.Policy{
		{Subject: "user", Action: "read:own", Object: "article", Fields: []string{"*", "!password"}},
		{Subject: "admin", Action: "write:own", Object: "article", Fields: []string{"*"}},
	}
	opts := acl.Options{Strict: true}
	ac, err := acl.New(policies, opts, drv)
	if err != nil { panic(err) }

	perm, err := ac.Check([]string{"user"}, "read:own", "article")
	if err != nil { panic(err) }
	if perm.Granted() {
		fmt.Println("Granted!")
		data := map[string]any{"title": "Article", "password": "secret"}
		filtered, _ := perm.Field(data)
		fmt.Printf("Filtered: %+v\n", filtered)
	}
}
```

## Usage Examples

- Add/Remove: `ac.Add(p)`, `ac.Remove(p)`, `ac.Exists(p)`, `ac.Clear()`.
- Query: `ac.Query(subject, action, object, strict)`.
- Check: `ac.Check(subjects, action, object)`, or with options.
- List: `ac.ListAll()`.
- Filtering: Use `perm.Field(data)` for fields, `perm.Filter(data)` for data.

## Extending

Implement `driver.Driver` for custom storage (e.g., Redis).

## Contributing

Submit issues/PRs on GitHub.
