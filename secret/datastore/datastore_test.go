package datastore_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/galaxy-io/modules/secret"
	"github.com/galaxy-io/modules/secret/datastore"
)

// memStore mirrors the table contract: rows keyed by ref, unique per tenant.
type memStore struct{ rows map[string]datastore.Row }

func (m *memStore) Put(_ context.Context, r datastore.Row) error {
	if old, ok := m.rows[r.Ref]; ok && old.Tenant != r.Tenant {
		return errors.New("unique ref violated")
	}
	m.rows[r.Ref] = r
	return nil
}

func (m *memStore) Replace(_ context.Context, r datastore.Row) (bool, error) {
	if old, ok := m.rows[r.Ref]; !ok || old.Tenant != r.Tenant {
		return false, nil
	}
	m.rows[r.Ref] = r
	return true, nil
}

func (m *memStore) Get(_ context.Context, tenant, ref string) (datastore.Row, error) {
	r, ok := m.rows[ref]
	if !ok || tenant != "" && r.Tenant != tenant {
		return datastore.Row{}, secret.ErrNotFound
	}
	return r, nil
}

func (m *memStore) Delete(_ context.Context, tenant, ref string) error {
	if r, ok := m.rows[ref]; ok && (tenant == "" || r.Tenant == tenant) {
		delete(m.rows, ref)
	}
	return nil
}

var scope = secret.Scope{Prefix: "filament/"}

func newProvider(t *testing.T) (*datastore.Provider, *memStore) {
	t.Helper()
	store := &memStore{rows: map[string]datastore.Row{}}
	p, err := datastore.New(store, scope, "test-key-v1", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return p, store
}

func TestRoundTripAndRotation(t *testing.T) {
	p, store := newProvider(t)
	ref := scope.Ref("tenant-a", "conn", "dsn", "v1")
	original := secret.Secret{Tenant: "tenant-a", Value: []byte("postgres://user:pw@host/db"), Meta: map[string]string{"rotated": "2026-01-01"}}
	if err := p.Write(t.Context(), ref, original); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(store.rows[ref].Ciphertext, original.Value) || store.rows[ref].KeyID != "test-key-v1" {
		t.Fatal("stored plaintext or lost key id")
	}
	got, err := p.Read(t.Context(), ref)
	if err != nil || string(got.Value) != string(original.Value) || got.Meta["rotated"] != "2026-01-01" || got.Tenant != "tenant-a" {
		t.Fatalf("round trip = %+v %v", got, err)
	}
	original.Value = []byte("rotated")
	if err := p.RotateSecret(t.Context(), ref, original); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Read(t.Context(), ref); err != nil || string(got.Value) != "rotated" {
		t.Fatal("rotation not persisted")
	}
	wrong := original
	wrong.Tenant = "tenant-b"
	if err := p.RotateSecret(t.Context(), ref, wrong); err == nil {
		t.Fatal("rotation crossed tenant boundary")
	}
	if err := p.Write(t.Context(), ref, wrong); err == nil {
		t.Fatal("write crossed tenant boundary")
	}
	if err := p.Delete(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(t.Context(), ref); !errors.Is(err, secret.ErrNotFound) {
		t.Fatalf("read after delete: %v", err)
	}
	if err := p.RotateSecret(t.Context(), ref, original); !errors.Is(err, secret.ErrNotFound) {
		t.Fatal("rotation recreated a deleted secret")
	}
}

func TestUnscopedRefs(t *testing.T) {
	p, _ := newProvider(t)
	ref := "shared-reference"
	value := secret.Secret{Tenant: "default", Value: []byte("initial")}
	if err := p.Write(t.Context(), ref, value); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Read(t.Context(), ref); err != nil || string(got.Value) != "initial" {
		t.Fatalf("read unscoped: %v", err)
	}
	other := value
	other.Tenant = "other"
	if err := p.RotateSecret(t.Context(), ref, other); !errors.Is(err, secret.ErrNotFound) {
		t.Fatal("rotation crossed tenant boundary")
	}
}

func TestStoreReceivesOwner(t *testing.T) {
	p, store := newProvider(t)
	ref := scope.Ref("tenant-a", "conn", "token", "v1")
	if err := p.Write(t.Context(), ref, secret.Secret{Tenant: "tenant-a", Value: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	// A row whose tenant disagrees with its ref's owner is invisible.
	r := store.rows[ref]
	r.Tenant = "tenant-b"
	store.rows[ref] = r
	if _, err := p.Read(t.Context(), ref); !errors.Is(err, secret.ErrNotFound) {
		t.Fatal("read ignored the ref's owner")
	}
}

func TestNewValidates(t *testing.T) {
	store := &memStore{rows: map[string]datastore.Row{}}
	if _, err := datastore.New(store, secret.Scope{}, "k", make([]byte, 32)); err == nil {
		t.Fatal("accepted empty scope")
	}
	if _, err := datastore.New(store, scope, "k", make([]byte, 7)); err == nil {
		t.Fatal("accepted bad key length")
	}
	p, err := datastore.New(store, scope, "k", make([]byte, 32), datastore.WithName("postgres"))
	if err != nil || p.Name() != "postgres" {
		t.Fatal("name option ignored")
	}
}
