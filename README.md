# ABACL-Go

[![Go Report Card](https://goreportcard.com/badge/github.com/alipourhabibi/abacl-go)](https://goreportcard.com/report/github.com/alipourhabibi/abacl-go)
[![GoDoc](https://godoc.org/github.com/alipourhabibi/abacl-go?status.svg)](https://godoc.org/github.com/alipourhabibi/abacl-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**ABACL-Go** is a flexible, high-performance Attribute-Based Access Control (ABAC) library for Go. It provides fine-grained authorization with support for field-level permissions, data filtering, and scope-based access control.

## Features

- **Attribute-Based Access Control** - Fine-grained permissions based on subjects, actions, and objects
- **Field-Level Filtering** - Control which fields users can modify in write operations
- **Response Data Filtering** - Control which fields users can see in read operations
- **Scope Support** - Flexible scopes like `read:own`, `update:shared`, `article:published`
- **High Performance** - Thread-safe with efficient regex-based pattern matching
- **Pluggable Storage** - In-memory driver included, easy to add custom drivers

## Installation

```bash
go get github.com/alipourhabibi/abacl-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/alipourhabibi/abacl-go/acl"
    "github.com/alipourhabibi/abacl-go/driver/memory"
    "github.com/alipourhabibi/abacl-go/policy"
)

func main() {
    // Define policies
    policies := []policy.Policy{
        {
            Subject: "user",
            Action:  "read",
            Object:  "article",
            Filters: []string{"*", "!password", "!internalNotes"}, // Hide these fields in response
        },
        {
            Subject: "user",
            Action:  "update",
            Object:  "article",
            Fields:  []string{"title", "content"}, // Can only modify these fields
        },
    }

    // Create ACL
    drv := memory.NewMemoryDriver()
    ac, err := acl.New(policies, acl.Options{Strict: false}, drv)
    if err != nil {
        log.Fatal(err)
    }

    // Check read permission and filter response
    readPerm, _ := ac.Check([]string{"user"}, "read", "article")
    if readPerm.Granted() {
        responseData := map[string]interface{}{
            "id":            1,
            "title":         "My Article",
            "password":      "secret123",
            "internalNotes": "confidential",
        }
        
        // Filter removes sensitive fields from response
        filtered, _ := readPerm.Filter(responseData)
        fmt.Printf("User sees: %+v\n", filtered)
        // Output: map[id:1 title:My Article]
    }

    // Check update permission and filter modifiable fields
    updatePerm, _ := ac.Check([]string{"user"}, "update", "article")
    if updatePerm.Granted() {
        updateRequest := map[string]interface{}{
            "title":   "Updated Title",
            "content": "Updated Content",
            "id":      999, // Attempting to change ID
        }
        
        // Field removes fields user cannot modify
        sanitized, _ := updatePerm.Field(updateRequest)
        fmt.Printf("User can modify: %+v\n", sanitized)
        // Output: map[title:Updated Title content:Updated Content]
    }
}
```

## Core Concepts

### Policies

A policy defines access rules with these components:

```go
type Policy struct {
    Subject  string   // Who (e.g., "user", "admin:readonly")
    Action   string   // What action (e.g., "read", "update:own")
    Object   string   // On what (e.g., "article", "document:published")
    
    Fields   []string // Modifiable fields in write operations (e.g., ["title", "content"])
    Filters  []string // Visible fields in read operations (e.g., ["*", "!password"])
    
    // Optional constraints
    TimeWindows []TimeWindow
    Locations   []string
}
```

### Scopes

Scopes provide fine-grained control using the `:` separator:

- **Subject scopes**: `user:premium`, `admin:readonly`
- **Action scopes**: `read:own`, `update:shared`, `delete:any`
- **Object scopes**: `article:published`, `document:draft`

### Fields vs Filters

**Fields** control which properties can be **modified** in write operations (create, update):
```go
Fields: []string{"title", "content", "tags"}     // Can only modify these
Fields: []string{"*", "!id", "!createdAt"}       // Can modify all except these
```

**Filters** control which properties are **visible** in read operations:
```go
Filters: []string{"*", "!password", "!ssn"}      // Hide sensitive fields
Filters: []string{"name", "email", "avatar"}     // Show only public fields
```

**Key Difference:**
- **Fields**: Used for write operations - "What can I modify in the request?"
- **Filters**: Used for read operations - "What can I see in the response?"

## Usage Examples

### 1. Basic Permission Check

```go
// Create ACL
policies := []policy.Policy{
    {
        Subject: "user",
        Action:  "read",
        Object:  "article",
    },
}

drv := memory.NewMemoryDriver()
ac, _ := acl.New(policies, acl.Options{}, drv)

// Check permission
perm, err := ac.Check([]string{"user"}, "read", "article")
if perm.Granted() {
    fmt.Println("Access granted")
}
```

### 2. Read Operation - Filter Response Data

```go
policies := []policy.Policy{
    {
        Subject: "user",
        Action:  "read",
        Object:  "profile",
        Filters: []string{"name", "email", "avatar"}, // Only show these fields
    },
}

ac, _ := acl.New(policies, acl.Options{}, memory.NewMemoryDriver())
perm, _ := ac.Check([]string{"user"}, "read", "profile")

// Data from database
userData := map[string]interface{}{
    "name":       "John Doe",
    "email":      "john@example.com",
    "avatar":     "https://example.com/avatar.jpg",
    "ssn":        "123-45-6789",
    "creditCard": "4111111111111111",
}

// Filter removes fields user cannot see
filtered, _ := perm.Filter(userData)
// Result: {name: "John Doe", email: "john@example.com", avatar: "..."}
// ssn and creditCard are hidden
```

### 3. Write Operation - Sanitize Request Data

```go
policies := []policy.Policy{
    {
        Subject: "user",
        Action:  "update",
        Object:  "article",
        Fields:  []string{"*", "!id", "!author", "!createdAt"}, // Cannot modify these
    },
}

ac, _ := acl.New(policies, acl.Options{}, memory.NewMemoryDriver())
perm, _ := ac.Check([]string{"user"}, "update", "article")

// User's update request
updateData := map[string]interface{}{
    "title":     "New Title",
    "content":   "New Content",
    "id":        999,              // Trying to change ID
    "author":    "hacker@evil.com", // Trying to change author
    "createdAt": "2025-01-01",      // Trying to change timestamp
}

// Field removes fields user cannot modify
sanitized, _ := perm.Field(updateData)
// Result: {title: "New Title", content: "New Content"}
// id, author, and createdAt are removed
```

### 4. Scope-Based Access

```go
policies := []policy.Policy{
    {
        Subject: "user",
        Action:  "read:own",      // Reading own articles
        Object:  "article",
        Filters: []string{"*"},   // Can see all fields
    },
    {
        Subject: "user",
        Action:  "read:shared",   // Reading shared articles
        Object:  "article",
        Filters: []string{"title", "content"}, // Limited fields
    },
    {
        Subject: "user",
        Action:  "update:own",    // Updating own articles
        Object:  "article",
        Fields:  []string{"*", "!id"}, // Can modify all except id
    },
}

// User reading their own article - all fields visible
ownPerm, _ := ac.Check([]string{"user"}, "read:own", "article")
ownData, _ := ownPerm.Filter(articleData)

// User reading shared article - limited fields
sharedPerm, _ := ac.Check([]string{"user"}, "read:shared", "article")
sharedData, _ := sharedPerm.Filter(articleData)

// User updating their own article
updatePerm, _ := ac.Check([]string{"user"}, "update:own", "article")
sanitized, _ := updatePerm.Field(updateRequest)
```

### 5. Multiple Subjects (Roles)

```go
// User has both "editor" and "reviewer" roles
perm, _ := ac.Check([]string{"editor", "reviewer"}, "update", "article")

// Grants access if ANY role has permission
if perm.Granted() {
    // Get combined permissions from all roles
    sanitized, _ := perm.Field(updateData)
}
```

### 6. Strict vs Non-Strict Matching

```go
// Non-strict mode (default): wildcards match
ac, _ := acl.New(policies, acl.Options{Strict: false}, drv)

// Query "read" matches "read:own", "read:shared", etc.
perm, _ := ac.Check([]string{"user"}, "read", "article")

// Strict mode: exact match required
ac, _ := acl.New(policies, acl.Options{Strict: true}, drv)

// Query "read" only matches exact "read", not "read:own"
perm, _ := ac.Check([]string{"user"}, "read", "article")
```

### 7. Advanced Field Filtering with Cache Key

```go
g := perm.Grant()

// Filter fields for specific scope
modifiable, _ := g.FieldByCKey(updateData, grant.CacheKey{
    Subject: "user",
    Action:  "update:own",
    Object:  "article",
    Strict:  false,
})

// Filter response for specific scope
visible, _ := g.FilterByCKey(responseData, grant.CacheKey{
    Subject: "user",
    Action:  "read:own",
    Object:  "article",
    Strict:  false,
})
```

## Advanced Usage

### Custom Driver Implementation

```go
type CustomDriver struct {
    // Your storage implementation
}

func (d *CustomDriver) Set(p policy.Policy) error {
    // Store policy
}

func (d *CustomDriver) Get(key string) (policy.Policy, bool) {
    // Retrieve policy
}

func (d *CustomDriver) Find(patternPolicy policy.Policy) ([]policy.Policy, error) {
    // Search policies with regex matching
}

// Implement other Driver interface methods...

// Use custom driver
ac, _ := acl.New(policies, acl.Options{}, &CustomDriver{})
```

### Real-World Example: Blog API

```go
func main() {
    policies := []policy.Policy{
        {
            Subject: "author",
            Action:  "create",
            Object:  "article",
            Fields:  []string{"*", "!id", "!createdAt"}, // Cannot set ID or timestamp
        },
        {
            Subject: "author",
            Action:  "update:own",
            Object:  "article",
            Fields:  []string{"title", "content", "tags"}, // Can only modify these
        },
        {
            Subject: "author",
            Action:  "read:own",
            Object:  "article",
            Filters: []string{"*"}, // Can see all fields of own articles
        },
        {
            Subject: "editor",
            Action:  "update",
            Object:  "article",
            Fields:  []string{"status", "featured", "publishedAt"}, // Editorial fields
        },
        {
            Subject: "public",
            Action:  "read",
            Object:  "article",
            Filters: []string{"title", "content", "author", "publishedAt"}, // Public fields only
        },
    }

    drv := memory.NewMemoryDriver()
    ac, _ := acl.New(policies, acl.Options{Strict: false}, drv)

    // Author creates article
    createPerm, _ := ac.Check([]string{"author"}, "create", "article")
    if createPerm.Granted() {
        newArticle := map[string]interface{}{
            "title":     "My Article",
            "content":   "Content here",
            "id":        123,           // Will be filtered out
            "createdAt": "2025-01-01",  // Will be filtered out
        }
        sanitized, _ := createPerm.Field(newArticle)
        // Save sanitized data (without 'id' and 'createdAt')
    }

    // Author reads their own article
    readOwnPerm, _ := ac.Check([]string{"author"}, "read:own", "article")
    if readOwnPerm.Granted() {
        article := loadArticle(123)
        fullData, _ := readOwnPerm.Filter(article)
        // Author sees all fields including internal notes
    }

    // Public reads article
    readPublicPerm, _ := ac.Check([]string{"public"}, "read", "article")
    if readPublicPerm.Granted() {
        article := loadArticle(123)
        publicView, _ := readPublicPerm.Filter(article)
        respondJSON(publicView) // Only public fields visible
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## Roadmap

- [ ] Redis driver implementation
- [ ] Time-based access control (TimeWindows)
- [ ] Location-based access control
- [ ] Policy inheritance
- [ ] Performance optimizations
