// Package gcp implements secret.Secrets backed by Google Cloud Secret Manager.
package gcp

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/galaxy-io/modules/secret"
)

const (
	managedLabel = "managed-by"
	maxSecretID  = 255
)

var (
	_             secret.Secrets = (*Provider)(nil)
	prefixPattern                = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	// rootPattern keeps the scope root valid as a GCP label value.
	rootPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

// API is the subset of the Secret Manager client used by Provider.
type API interface {
	AccessSecretVersion(context.Context, *secretmanagerpb.AccessSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	GetSecret(context.Context, *secretmanagerpb.GetSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error)
	CreateSecret(context.Context, *secretmanagerpb.CreateSecretRequest, ...gax.CallOption) (*secretmanagerpb.Secret, error)
	AddSecretVersion(context.Context, *secretmanagerpb.AddSecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	DeleteSecret(context.Context, *secretmanagerpb.DeleteSecretRequest, ...gax.CallOption) error
	DestroySecretVersion(context.Context, *secretmanagerpb.DestroySecretVersionRequest, ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
}

// Provider stores secrets in Google Cloud Secret Manager.
type Provider struct {
	client    API
	scope     secret.Scope
	projectID string
	region    string
	prefix    string
	close     func() error
}

// Option configures a Provider.
type Option func(*Provider)

// WithPrefix replaces the scope's root as the prefix on each GCP secret ID. A
// hyphen always separates the prefix from the hash, so a trailing one is trimmed.
func WithPrefix(prefix string) Option { return func(p *Provider) { p.prefix = prefix } }

// New constructs a provider from an explicit Secret Manager API. scope names
// the refs the app mints for tenants; its root labels the secrets the
// provider creates, so it can prove it owns them later.
func New(client API, scope secret.Scope, projectID, region string, opts ...Option) (*Provider, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if !rootPattern.MatchString(scope.Root()) {
		return nil, fmt.Errorf("secret/gcp: scope root %q must be a valid label value", scope.Root())
	}
	p := &Provider{client: client, scope: scope, projectID: projectID, region: region}
	for _, opt := range opts {
		opt(p)
	}
	p.prefix = strings.TrimRight(p.prefix, "-_")
	if strings.TrimSpace(projectID) == "" {
		return nil, errors.New("secret/gcp: project ID is required (set GCP_PROJECT_ID)")
	}
	if strings.TrimSpace(region) == "" {
		return nil, errors.New("secret/gcp: region is required (set GCP_REGION)")
	}
	if strings.Contains(region, "/") {
		return nil, errors.New("secret/gcp: GCP_REGION must be a location ID")
	}
	if !prefixPattern.MatchString(p.prefix) {
		return nil, errors.New("secret/gcp: SECRETS_PREFIX may contain only letters, digits, hyphens, and underscores")
	}
	if len(p.prefix)+1+sha256.Size*2 > maxSecretID {
		return nil, fmt.Errorf("secret/gcp: SECRETS_PREFIX is too long (maximum %d characters)", maxSecretID-1-sha256.Size*2)
	}
	return p, nil
}

// NewFromConfig uses Application Default Credentials to construct a provider.
func NewFromConfig(ctx context.Context, scope secret.Scope, projectID, region string, opts ...Option) (*Provider, error) {
	p, err := New(nil, scope, projectID, region, opts...)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("secretmanager.%s.rep.googleapis.com:443", region)
	client, err := secretmanager.NewClient(ctx, option.WithEndpoint(endpoint))
	if err != nil {
		return nil, fmt.Errorf("secret/gcp: create client: %w", err)
	}
	p.client = client
	p.close = client.Close
	return p, nil
}

// Name returns the provider identifier.
func (p *Provider) Name() string { return "gcp-secret-manager" }

// Close releases the underlying Google Cloud client when Provider created it.
func (p *Provider) Close() error {
	if p.close == nil {
		return nil
	}
	return p.close()
}

type envelope struct {
	Ref    string            `json:"ref"`
	Tenant string            `json:"tenant,omitempty"`
	Value  []byte            `json:"value"`
	Meta   map[string]string `json:"meta,omitempty"`
}

func (p *Provider) secretID(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return cmp.Or(p.prefix, p.scope.Root()) + "-" + hex.EncodeToString(sum[:])
}

func (p *Provider) secretName(ref string) string {
	return fmt.Sprintf("%s/secrets/%s", p.parentName(), p.secretID(ref))
}

func (p *Provider) parentName() string {
	return fmt.Sprintf("projects/%s/locations/%s", p.projectID, p.region)
}

// Read fetches and decodes the latest version of the secret at ref.
func (p *Provider) Read(ctx context.Context, ref string) (secret.Secret, error) {
	value, _, err := p.readVersion(ctx, ref, "")
	return value, err
}

// readVersion reads an immutable version, or latest when version is empty.
func (p *Provider) readVersion(ctx context.Context, ref, version string) (secret.Secret, string, error) {
	if version != "" {
		if _, err := strconv.ParseUint(version, 10, 64); err != nil {
			return secret.Secret{}, "", errors.New("secret/gcp: invalid version number")
		}
	}
	version = cmp.Or(version, "latest")
	out, err := p.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: p.secretName(ref) + "/versions/" + version})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return secret.Secret{}, "", fmt.Errorf("secret/gcp: read %q: %w", ref, secret.ErrNotFound)
		}
		return secret.Secret{}, "", fmt.Errorf("secret/gcp: read %q: %w", ref, err)
	}
	if out.Payload == nil {
		return secret.Secret{}, "", fmt.Errorf("secret/gcp: read %q: empty secret", ref)
	}
	var env envelope
	if err := json.Unmarshal(out.Payload.Data, &env); err != nil {
		return secret.Secret{}, "", fmt.Errorf("secret/gcp: read %q: decode: %w", ref, err)
	}
	if env.Ref != ref || env.Value == nil {
		return secret.Secret{}, "", fmt.Errorf("secret/gcp: read %q: not a matching managed envelope", ref)
	}
	number, err := p.versionNumber(ref, out.Name)
	if err != nil {
		return secret.Secret{}, "", err
	}
	return secret.Secret{Tenant: env.Tenant, Value: env.Value, Meta: env.Meta}, number, nil
}

// Write creates the secret if absent, otherwise stores a new version.
func (p *Provider) Write(ctx context.Context, ref string, s secret.Secret) error {
	_, err := p.writeVersion(ctx, ref, s)
	return err
}

// writeVersion appends a version to the same secret and returns its number.
func (p *Provider) writeVersion(ctx context.Context, ref string, s secret.Secret) (string, error) {
	raw, err := json.Marshal(envelope{Ref: ref, Tenant: s.Tenant, Value: s.Value, Meta: s.Meta})
	if err != nil {
		return "", fmt.Errorf("secret/gcp: write %q: encode: %w", ref, err)
	}
	name := p.secretName(ref)
	sm, err := p.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: name})
	if status.Code(err) == codes.NotFound {
		sm, err = p.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   p.parentName(),
			SecretId: p.secretID(ref),
			Secret: &secretmanagerpb.Secret{
				Labels:      map[string]string{managedLabel: p.scope.Root()},
				Annotations: map[string]string{p.refAnnotation(): ref},
			},
		})
		if status.Code(err) == codes.AlreadyExists {
			sm, err = p.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: name})
		}
	}
	if err != nil {
		return "", fmt.Errorf("secret/gcp: prepare %q: %w", ref, err)
	}
	if err := p.managed(sm, ref); err != nil {
		return "", fmt.Errorf("secret/gcp: write %q: %w", ref, err)
	}
	version, err := p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: name, Payload: &secretmanagerpb.SecretPayload{Data: raw},
	})
	if err != nil {
		return "", fmt.Errorf("secret/gcp: write %q: %w", ref, err)
	}
	return p.versionNumber(ref, version.Name)
}

// RotateSecret adds a version to the same secret, then destroys the old version.
// A failed append leaves the old version intact. Cleanup errors are returned even
// though the new version has already become latest.
func (p *Provider) RotateSecret(ctx context.Context, ref string, s secret.Secret) error {
	if s.Tenant == "" {
		return errors.New("secret/gcp: tenant is required")
	}
	if err := p.scope.Check(ref, s.Tenant); err != nil {
		return err
	}
	name := p.secretName(ref)
	sm, err := p.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: name})
	if status.Code(err) == codes.NotFound {
		return secret.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("secret/gcp: inspect rotation: %w", err)
	}
	if err := p.managed(sm, ref); err != nil {
		return err
	}
	current, old, err := p.readVersion(ctx, ref, "")
	if err != nil {
		return err
	}
	if current.Tenant != "" && current.Tenant != s.Tenant {
		return errors.New("secret/gcp: secret belongs to another tenant")
	}
	raw, err := json.Marshal(envelope{Ref: ref, Tenant: s.Tenant, Value: s.Value, Meta: s.Meta})
	if err != nil {
		return fmt.Errorf("secret/gcp: encode rotation: %w", err)
	}
	version, err := p.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{Parent: name, Payload: &secretmanagerpb.SecretPayload{Data: raw}})
	if err != nil {
		return fmt.Errorf("secret/gcp: rotate %q: %w", ref, err)
	}
	next, err := p.versionNumber(ref, version.Name)
	if err != nil {
		return err
	}
	if next == old {
		return errors.New("secret/gcp: rotation returned the old version")
	}
	if _, err := p.client.DestroySecretVersion(ctx, &secretmanagerpb.DestroySecretVersionRequest{Name: name + "/versions/" + old}); err != nil {
		return fmt.Errorf("secret/gcp: destroy previous version after rotation: %w", err)
	}
	return nil
}

// ErrUnmanaged is returned when Provider cannot prove it owns a secret.
var ErrUnmanaged = errors.New("secret/gcp: refusing to modify an unmanaged secret")

// refAnnotation is the annotation key holding a secret's ref, such as
// "filament-ref".
func (p *Provider) refAnnotation() string { return p.scope.Root() + "-ref" }

func (p *Provider) managed(sm *secretmanagerpb.Secret, ref string) error {
	if sm == nil || sm.Labels[managedLabel] != p.scope.Root() || sm.Annotations[p.refAnnotation()] != ref {
		return ErrUnmanaged
	}
	return nil
}

// Delete permanently deletes the secret at ref. Deleting a missing ref is a
// no-op. GCP metadata is checked before its irreversible deletion.
func (p *Provider) Delete(ctx context.Context, ref string) error {
	if p.prefix == "" && !strings.HasPrefix(ref, p.scope.Prefix) {
		return fmt.Errorf("delete %q: %w", ref, ErrUnmanaged)
	}
	name := p.secretName(ref)
	sm, err := p.client.GetSecret(ctx, &secretmanagerpb.GetSecretRequest{Name: name})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("secret/gcp: delete %q: inspect: %w", ref, err)
	}
	if err := p.managed(sm, ref); err != nil {
		return fmt.Errorf("secret/gcp: delete %q: %w", ref, err)
	}
	if err := p.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{Name: name}); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return fmt.Errorf("secret/gcp: delete %q: %w", ref, err)
	}
	return nil
}

// Project IDs and their numeric project identifiers can name the same resource.
// Read/write requests use the configured project; responses must identify the
// requested regional secret, and only their immutable version number is saved.
func (p *Provider) versionNumber(ref, name string) (string, error) {
	parent, version, ok := strings.Cut(name, "/secrets/"+p.secretID(ref)+"/versions/")
	if !ok || !strings.HasPrefix(parent, "projects/") || !strings.HasSuffix(parent, "/locations/"+p.region) {
		return "", errors.New("secret/gcp: unexpected version name")
	}
	if n, err := strconv.ParseUint(version, 10, 64); err != nil || n == 0 {
		return "", errors.New("secret/gcp: invalid version number")
	}
	return version, nil
}
