// Package secret resolves opaque references to secret material, keeping
// plaintext out of configs and stores. Providers live in subpackages: datastore
// encrypts into an app's own table, env reads the process environment, and
// the aws and gcp packages wrap the cloud secret managers.
package secret

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrNotFound reports a ref with no secret behind it.
var ErrNotFound = errors.New("secret: not found")

// Secrets resolves opaque references to secret material.
type Secrets interface {
	Read(ctx context.Context, ref string) (Secret, error)
	Write(ctx context.Context, ref string, s Secret) error
	Delete(ctx context.Context, ref string) error
	Name() string
}

// Secret is plaintext, in-memory only; never logged, never on the bus.
type Secret struct {
	Tenant string
	Value  []byte
	Meta   map[string]string
}

// Rotator replaces the value of an existing secret without creating a secret
// or changing its reference. Rotation must not recreate a deleted secret.
// Implementations preserve tenant isolation and encrypt values at rest.
type Rotator interface {
	RotateSecret(ctx context.Context, ref string, s Secret) error
}

// Scope is the namespace an app mints tenant-owned refs under:
// <Prefix><tenant>/<parts...>, such as "filament/<tenant>/<conn>/<field>/v1".
// Refs outside the prefix, such as env-style refs, carry no tenant.
type Scope struct {
	// Prefix is the app's root segment with its trailing slash, such as
	// "filament/".
	Prefix string
}

// Validate requires a single root segment ending in a slash.
func (s Scope) Validate() error {
	root, ok := strings.CutSuffix(s.Prefix, "/")
	if !ok || root == "" || strings.Contains(root, "/") {
		return fmt.Errorf("secret: scope prefix %q must be one segment followed by a slash", s.Prefix)
	}
	return nil
}

// Root is the prefix without its trailing slash, such as "filament".
func (s Scope) Root() string { return strings.TrimSuffix(s.Prefix, "/") }

// Ref builds the canonical ref for a secret tenant owns.
func (s Scope) Ref(tenant string, parts ...string) string {
	return s.Prefix + strings.Join(append([]string{tenant}, parts...), "/")
}

// Owner returns the tenant a scoped ref belongs to. It reports false for a ref
// outside the scope, and fails for a scoped ref with no tenant segment.
func (s Scope) Owner(ref string) (string, bool, error) {
	rest, scoped := strings.CutPrefix(ref, s.Prefix)
	if !scoped {
		return "", false, nil
	}
	owner, _, ok := strings.Cut(rest, "/")
	if !ok || owner == "" {
		return "", true, fmt.Errorf("secret: malformed scoped ref %q", ref)
	}
	return owner, true, nil
}

// Check enforces the cross-tenant isolation rule for a ref-keyed store: a ref
// in the scope may only be read or written by its owning tenant. Refs outside
// the scope carry no tenant and pass through.
func (s Scope) Check(ref, tenant string) error {
	owner, scoped, err := s.Owner(ref)
	if err != nil || !scoped {
		return err
	}
	if owner != tenant {
		return fmt.Errorf("secret: ref %q is not owned by tenant %q", ref, tenant)
	}
	return nil
}
