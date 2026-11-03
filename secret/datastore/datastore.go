// Package datastore implements secret.Secrets over the app's own datastore. It
// encrypts values with AES-GCM and enforces the scope's tenant rule; the app
// owns the schema and supplies the rows through Store.
package datastore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/galaxy-io/modules/secret"
)

// Row is one encrypted secret as the app stores it.
type Row struct {
	Tenant     string
	Ref        string
	Ciphertext []byte
	Nonce      []byte
	KeyID      string
	// Meta is the JSON-encoded secret metadata.
	Meta []byte
}

// Store persists rows in the app's secrets table, unique on (tenant, ref) and
// on ref. tenant on Get and Delete is the owner of a scoped ref and empty for
// a ref outside the scope; a store matches on it when it is set.
type Store interface {
	// Put inserts the row or replaces the one at (tenant, ref).
	Put(ctx context.Context, r Row) error
	// Replace updates the row at (tenant, ref), reporting false when none
	// exists. It never inserts.
	Replace(ctx context.Context, r Row) (bool, error)
	// Get returns the row at ref, wrapping secret.ErrNotFound when missing.
	Get(ctx context.Context, tenant, ref string) (Row, error)
	// Delete removes the row at ref; a missing row is not an error.
	Delete(ctx context.Context, tenant, ref string) error
}

// Provider encrypts secret values with AES-GCM before handing them to Store.
type Provider struct {
	store Store
	scope secret.Scope
	keyID string
	gcm   cipher.AEAD
	name  string
}

var (
	_ secret.Secrets = (*Provider)(nil)
	_ secret.Rotator = (*Provider)(nil)
)

// Option configures a Provider.
type Option func(*Provider)

// WithName replaces the default "datastore" provider name, such as with the
// backing datastore's.
func WithName(name string) Option { return func(p *Provider) { p.name = name } }

// NewFromEnv constructs a provider from ENCRYPTION_KEY (base64-encoded AES
// key) and ENCRYPTION_KEY_ID (defaults to "default").
func NewFromEnv(store Store, scope secret.Scope, opts ...Option) (*Provider, error) {
	encoded := os.Getenv("ENCRYPTION_KEY")
	if encoded == "" {
		return nil, errors.New("secret/datastore: ENCRYPTION_KEY is required")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("secret/datastore: ENCRYPTION_KEY must be base64: %w", err)
	}
	keyID := os.Getenv("ENCRYPTION_KEY_ID")
	if keyID == "" {
		keyID = "default"
	}
	return New(store, scope, keyID, key, opts...)
}

// New constructs a provider. key must be 16, 24, or 32 bytes.
func New(store Store, scope secret.Scope, keyID string, key []byte, opts ...Option) (*Provider, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret/datastore: key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret/datastore: gcm: %w", err)
	}
	p := &Provider{store: store, scope: scope, keyID: keyID, gcm: gcm, name: "datastore"}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return p.name }

// Write stores s at ref, creating or replacing it.
func (p *Provider) Write(ctx context.Context, ref string, s secret.Secret) error {
	return p.write(ctx, ref, s, false)
}

// RotateSecret updates an existing tenant-owned secret without inserting a row.
func (p *Provider) RotateSecret(ctx context.Context, ref string, s secret.Secret) error {
	return p.write(ctx, ref, s, true)
}

func (p *Provider) write(ctx context.Context, ref string, s secret.Secret, rotate bool) error {
	if s.Tenant == "" {
		return errors.New("secret/datastore: tenant is required")
	}
	if err := p.scope.Check(ref, s.Tenant); err != nil {
		return err
	}
	nonce := make([]byte, p.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("secret/datastore: nonce: %w", err)
	}
	meta, err := json.Marshal(s.Meta)
	if err != nil {
		return fmt.Errorf("secret/datastore: marshal metadata: %w", err)
	}
	row := Row{Tenant: s.Tenant, Ref: ref, Ciphertext: p.gcm.Seal(nil, nonce, s.Value, nil), Nonce: nonce, KeyID: p.keyID, Meta: meta}
	if rotate {
		var found bool
		found, err = p.store.Replace(ctx, row)
		if err == nil && !found {
			return secret.ErrNotFound
		}
	} else {
		err = p.store.Put(ctx, row)
	}
	if err != nil {
		return fmt.Errorf("secret/datastore: write: %w", err)
	}
	return nil
}

// Read returns the decrypted secret at ref.
func (p *Provider) Read(ctx context.Context, ref string) (secret.Secret, error) {
	owner, _, err := p.scope.Owner(ref)
	if err != nil {
		return secret.Secret{}, err
	}
	row, err := p.store.Get(ctx, owner, ref)
	if err != nil {
		if errors.Is(err, secret.ErrNotFound) {
			return secret.Secret{}, fmt.Errorf("read secret %q: %w", ref, secret.ErrNotFound)
		}
		return secret.Secret{}, fmt.Errorf("secret/datastore: read: %w", err)
	}
	value, err := p.gcm.Open(nil, row.Nonce, row.Ciphertext, nil)
	if err != nil {
		return secret.Secret{}, fmt.Errorf("secret/datastore: decrypt %q: %w", ref, err)
	}
	var meta map[string]string
	if len(row.Meta) > 0 {
		if err := json.Unmarshal(row.Meta, &meta); err != nil {
			return secret.Secret{}, fmt.Errorf("secret/datastore: unmarshal metadata: %w", err)
		}
	}
	return secret.Secret{Tenant: row.Tenant, Value: value, Meta: meta}, nil
}

// Delete removes the secret at ref; deleting a missing ref is a no-op.
func (p *Provider) Delete(ctx context.Context, ref string) error {
	owner, _, err := p.scope.Owner(ref)
	if err != nil {
		return err
	}
	if err := p.store.Delete(ctx, owner, ref); err != nil {
		return fmt.Errorf("secret/datastore: delete: %w", err)
	}
	return nil
}
