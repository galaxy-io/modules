package secret_test

import (
	"testing"

	"github.com/galaxy-io/modules/secret"
)

func TestScope(t *testing.T) {
	scope := secret.Scope{Prefix: "filament/"}
	ref := scope.Ref("tenant-a", "conn", "token", "v1")
	if ref != "filament/tenant-a/conn/token/v1" {
		t.Fatalf("ref = %q", ref)
	}
	if owner, scoped, err := scope.Owner(ref); err != nil || !scoped || owner != "tenant-a" {
		t.Fatalf("owner = %q %v %v", owner, scoped, err)
	}
	if err := scope.Check(ref, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err := scope.Check(ref, "tenant-b"); err == nil {
		t.Fatal("crossed tenant boundary")
	}
	if err := scope.Check("postgres-creds/dsn", "tenant-b"); err != nil {
		t.Fatal("unscoped ref refused")
	}
	for _, malformed := range []string{"filament/", "filament/tenant-a", "filament//conn"} {
		if err := scope.Check(malformed, "tenant-a"); err == nil {
			t.Fatalf("accepted malformed ref %q", malformed)
		}
	}
}

func TestScopeValidate(t *testing.T) {
	for prefix, ok := range map[string]bool{"filament/": true, "alchemy/": true, "": false, "filament": false, "/": false, "a/b/": false} {
		if err := (secret.Scope{Prefix: prefix}).Validate(); (err == nil) != ok {
			t.Errorf("Validate(%q) = %v", prefix, err)
		}
	}
}
