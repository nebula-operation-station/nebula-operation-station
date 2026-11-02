// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// Private registry read authority (ADR 0006, P1-32). The credential of a
// private registry lives only in the executor vault. The server asks for a
// typed, bounded metadata read (a manifest digest or a tag list of one
// approved repository); the executor checks its own record and a read
// grant, opens the credential at exactly the bound version, performs the
// read with registrymeta.PrivateClient and returns sanitized values only.
// Lock, restart (the vault starts locked), credential rotation and
// credential expiry pause reads; a read in flight across a lock or rotation
// is discarded.
//
// The registry record and the credential are both vault secrets:
//
//	registry.<id>.config  JSON privateRegistryRecord (origins, realm, scope)
//	registry.<id>.cred    JSON privateRegistryCred (user, secret, expiry)
//
// so neither is readable while the vault is locked and every change gets a
// new vault version.

// Private registry limits.
const (
	// maxPrivateRegistries bounds the configured private registries.
	maxPrivateRegistries = 64
	// maxRegistryCAPEMBytes bounds an administrator-supplied CA bundle.
	maxRegistryCAPEMBytes = 32 << 10
	// minRegistryCredentialLifetime rejects credentials that expire almost
	// immediately.
	minRegistryCredentialLifetime = time.Hour
	// maxRegistryCredentialLifetime forces rotation at least every 90 days.
	maxRegistryCredentialLifetime = 90 * 24 * time.Hour
	// maxRegistryClients bounds the cached per-configuration clients.
	maxRegistryClients = 2 * maxPrivateRegistries
	// privateRegistryFormat versions the stored record.
	privateRegistryFormat = "nebula-private-registry-v1"
)

// Registry read methods a read grant names.
const (
	// RegistryMethodTagDigest is a manifest HEAD of one tag or digest.
	RegistryMethodTagDigest = "tag_digest"
	// RegistryMethodListTags is a bounded tag list of one repository.
	RegistryMethodListTags = "list_tags"
)

var registryIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ErrRegistryReadGrantUnavailable is returned by the default authorizer: no
// read-grant profile for private registry reads is wired, so every read is
// refused (fail closed) until one is.
var ErrRegistryReadGrantUnavailable = errors.New("executor: no read-grant profile covers private registry reads")

// RegistryRead is one typed private registry read the executor is about to
// make, with the registry's current identity from the executor's own
// record. Nothing in it comes from the caller except the registry ID,
// method and repository, which select work inside existing authority.
type RegistryRead struct {
	RegistryID string
	Method     string
	Repository string
	// ConfigDigest is the SHA-256 of the stored registry record: it pins
	// the registry origin, auth realm, service, repository scope and the
	// record's random nonce, so a removed and re-added registry differs.
	ConfigDigest string
	// ConfigVersion and CredentialVersion are the vault versions used.
	ConfigVersion     int64
	CredentialVersion int64
	// CredentialID is the random identity of the stored credential, new on
	// every add or rotation, so a version number reused after a removal
	// never matches an old grant.
	CredentialID string
}

// RegistryReadClaim is one reserved read. Check re-verifies it (lock,
// revocation, expiry, unchanged scope) without spending again.
type RegistryReadClaim interface {
	Check() error
	ID() string
}

// RegistryReadAuthorizer finds a read grant that covers a read and
// reserves its budget.
type RegistryReadAuthorizer interface {
	AuthorizeRegistryRead(RegistryRead) (RegistryReadClaim, error)
}

type noRegistryReadGrants struct{}

func (noRegistryReadGrants) AuthorizeRegistryRead(RegistryRead) (RegistryReadClaim, error) {
	return nil, ErrRegistryReadGrantUnavailable
}

// privateRegistryState is the Service's private registry state.
type privateRegistryState struct {
	// adminMu serializes administration.
	adminMu sync.Mutex
	// auth authorizes reads; nil means noRegistryReadGrants.
	auth RegistryReadAuthorizer
	// allowLoopback lets tests dial httptest registries. Production never
	// sets it.
	allowLoopback bool

	mu      sync.Mutex
	clients map[string]*registrymeta.PrivateClient
}

// SetRegistryReadAuthorizer wires the read-grant check for private registry
// reads. Without one, every read is refused.
func (s *Service) SetRegistryReadAuthorizer(a RegistryReadAuthorizer) {
	s.registry.mu.Lock()
	s.registry.auth = a
	s.registry.mu.Unlock()
}

func (s *Service) registryAuthorizer() RegistryReadAuthorizer {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	if s.registry.auth == nil {
		return noRegistryReadGrants{}
	}
	return s.registry.auth
}

// privateRegistryRecord is the stored, administrator-approved description.
type privateRegistryRecord struct {
	Format              string   `json:"format"`
	ID                  string   `json:"id"`
	Registry            string   `json:"registry"`
	Mode                string   `json:"mode"`
	Realm               string   `json:"realm"`
	Service             string   `json:"service"`
	Repositories        []string `json:"repositories"`
	AllowPrivateNetwork bool     `json:"allow_private_network"`
	CAPEM               string   `json:"ca_pem"`
	CreatedBy           string   `json:"created_by"`
	CreatedUnix         int64    `json:"created_unix"`
	Nonce               string   `json:"nonce"`
}

// privateRegistryCred is the stored credential.
type privateRegistryCred struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Secret      []byte `json:"secret"`
	ExpiresUnix int64  `json:"expires_unix"`
}

var registryNonceRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// newRegistryNonce returns 128 random bits as hex.
func newRegistryNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func registryConfigID(id string) string { return "registry." + id + ".config" }
func registryCredID(id string) string   { return "registry." + id + ".cred" }

func (r privateRegistryRecord) meta() registrymeta.PrivateRegistry {
	return registrymeta.PrivateRegistry{Registry: r.Registry, Mode: registrymeta.AuthMode(r.Mode), Realm: r.Realm,
		Service: r.Service, Repositories: r.Repositories, AllowPrivateNetwork: r.AllowPrivateNetwork}
}

// validate checks the record and returns its CA pool (nil: system roots).
func (r privateRegistryRecord) validate() (*x509.CertPool, error) {
	if r.Format != privateRegistryFormat || !registryIDRe.MatchString(r.ID) || !registryNonceRe.MatchString(r.Nonce) {
		return nil, errors.New("invalid registry record")
	}
	if _, err := r.meta().Validate(); err != nil {
		return nil, err
	}
	if r.CAPEM == "" {
		return nil, nil
	}
	if len(r.CAPEM) > maxRegistryCAPEMBytes {
		return nil, errors.New("CA bundle too large")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(r.CAPEM)) {
		return nil, errors.New("CA bundle has no certificate")
	}
	return pool, nil
}

func (c privateRegistryCred) validate() error {
	if c.ExpiresUnix <= 0 || !registryNonceRe.MatchString(c.ID) {
		return errors.New("credential has no expiry or identity")
	}
	return registrymeta.Credential{Username: c.Username, Secret: c.Secret}.Validate()
}

// loadedRegistry is a record and credential opened at exact versions.
type loadedRegistry struct {
	rec           privateRegistryRecord
	roots         *x509.CertPool
	configDigest  string
	configVersion int64
	cred          privateRegistryCred
	credVersion   int64
}

// wipe clears the opened secret.
func (l *loadedRegistry) wipe() { clear(l.cred.Secret) }

var (
	errRegistryNotFound = errors.New("private registry not found")
	errRegistryCorrupt  = errors.New("private registry record does not validate")
)

// loadRegistry opens the record and credential of id. The caller must wipe
// the result.
func (s *Service) loadRegistry(id string) (*loadedRegistry, error) {
	raw, cfgVer, err := s.vault.OpenVersion(registryConfigID(id))
	if errors.Is(err, vault.ErrNotFound) {
		return nil, errRegistryNotFound
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	var rec privateRegistryRecord
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil || rec.ID != id {
		return nil, errRegistryCorrupt
	}
	roots, err := rec.validate()
	if err != nil {
		return nil, errRegistryCorrupt
	}
	l := &loadedRegistry{rec: rec, roots: roots, configDigest: hex.EncodeToString(sum[:]), configVersion: cfgVer}
	craw, credVer, err := s.vault.OpenVersion(registryCredID(id))
	if errors.Is(err, vault.ErrNotFound) {
		return nil, errRegistryNotFound
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(craw, &l.cred)
	clear(craw)
	if err != nil || l.cred.validate() != nil {
		l.wipe()
		return nil, errRegistryCorrupt
	}
	l.credVersion = credVer
	return l, nil
}

func (s *Service) registryInfo(l *loadedRegistry) *pb.PrivateRegistryInfo {
	return &pb.PrivateRegistryInfo{RegistryId: l.rec.ID, RegistryOrigin: l.rec.Registry, AuthMode: registryModeProto(l.rec.Mode),
		Realm: l.rec.Realm, Service: l.rec.Service, Repositories: slices.Clone(l.rec.Repositories),
		AllowPrivateNetwork: l.rec.AllowPrivateNetwork, CustomCa: l.rec.CAPEM != "", ConfigVersion: l.configVersion,
		CredentialVersion: l.credVersion, CredentialExpiresUnix: l.cred.ExpiresUnix}
}

func registryModeProto(m string) pb.PrivateRegistryAuthMode {
	switch registrymeta.AuthMode(m) {
	case registrymeta.AuthBasic:
		return pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC
	case registrymeta.AuthToken:
		return pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_TOKEN
	}
	return pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_UNSPECIFIED
}

// registryAdminError maps administration errors; messages never contain a
// credential.
func (s *Service) registryAdminError(op string, err error) error {
	switch {
	case errors.Is(err, errRegistryNotFound):
		return status.Error(codes.NotFound, "private registry not found")
	case errors.Is(err, errRegistryCorrupt):
		s.log.Error("audit", "kind", "registry_record_invalid", "op", op)
		return status.Error(codes.DataLoss, "private registry record does not validate")
	}
	return s.vaultError(op, err)
}

// checkCredentialExpiry enforces the credential lifetime window.
func (s *Service) checkCredentialExpiry(expires int64) error {
	now := s.clock()
	exp := time.Unix(expires, 0)
	if exp.Before(now.Add(minRegistryCredentialLifetime)) || exp.After(now.Add(maxRegistryCredentialLifetime)) {
		return status.Errorf(codes.InvalidArgument, "credential expiry must be %s to %s from now", minRegistryCredentialLifetime, maxRegistryCredentialLifetime)
	}
	return nil
}

func (s *Service) putRegistryCred(id string, c privateRegistryCred, who string) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	defer clear(raw)
	_, err = s.vault.Put(registryCredID(id), raw, who)
	return err
}

// registryIDs returns the configured registry IDs.
func (s *Service) registryIDs() ([]string, error) {
	list, err := s.vault.List()
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, i := range list {
		if rest, ok := strings.CutPrefix(i.ID, "registry."); ok {
			if id, ok := strings.CutSuffix(rest, ".config"); ok && registryIDRe.MatchString(id) {
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// AddPrivateRegistry stores an approved private registry and its credential
// in the executor vault (admin role). It never replaces an existing one:
// changing origins, realm or scope means remove and add, which voids every
// read grant bound to the old record digest.
func (s *Service) AddPrivateRegistry(ctx context.Context, in *pb.AddPrivateRegistryRequest) (*pb.AddPrivateRegistryResponse, error) {
	defer clear(in.GetSecret())
	s.registry.adminMu.Lock()
	defer s.registry.adminMu.Unlock()
	who := callerName(ctx)
	mode := ""
	switch in.GetAuthMode() {
	case pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC:
		mode = string(registrymeta.AuthBasic)
	case pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_TOKEN:
		mode = string(registrymeta.AuthToken)
	default:
		return nil, status.Error(codes.InvalidArgument, "unsupported private registry auth mode")
	}
	nonce, err := newRegistryNonce()
	if err != nil {
		return nil, status.Error(codes.Internal, "random source unavailable")
	}
	credID, err := newRegistryNonce()
	if err != nil {
		return nil, status.Error(codes.Internal, "random source unavailable")
	}
	rec := privateRegistryRecord{Format: privateRegistryFormat, ID: in.GetRegistryId(), Registry: in.GetRegistryOrigin(), Mode: mode,
		Realm: in.GetRealm(), Service: in.GetService(), Repositories: slices.Clone(in.GetRepositories()),
		AllowPrivateNetwork: in.GetAllowPrivateNetwork(), CAPEM: in.GetCaPem(), CreatedBy: who, CreatedUnix: s.clock().Unix(), Nonce: nonce}
	if _, err := rec.validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid private registry: "+err.Error())
	}
	cred := privateRegistryCred{ID: credID, Username: in.GetUsername(), Secret: in.GetSecret(), ExpiresUnix: in.GetCredentialExpiresUnix()}
	if err := cred.validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid private registry credential")
	}
	if err := s.checkCredentialExpiry(cred.ExpiresUnix); err != nil {
		return nil, err
	}
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "the executor vault is locked")
	}
	ids, err := s.registryIDs()
	if err != nil {
		return nil, s.registryAdminError("add_private_registry", err)
	}
	if slices.Contains(ids, rec.ID) {
		return nil, status.Error(codes.AlreadyExists, "private registry exists; remove it first")
	}
	if len(ids) >= maxPrivateRegistries {
		return nil, status.Errorf(codes.ResourceExhausted, "at most %d private registries", maxPrivateRegistries)
	}
	// The credential is written first: a record without a credential would
	// be readable metadata for a registry that cannot be used.
	if err := s.putRegistryCred(rec.ID, cred, who); err != nil {
		return nil, s.registryAdminError("add_private_registry", err)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode private registry")
	}
	if _, err := s.vault.Put(registryConfigID(rec.ID), raw, who); err != nil {
		_ = s.vault.Delete(registryCredID(rec.ID))
		return nil, s.registryAdminError("add_private_registry", err)
	}
	l, err := s.loadRegistry(rec.ID)
	if err != nil {
		return nil, s.registryAdminError("add_private_registry", err)
	}
	defer l.wipe()
	s.log.Info("audit", "kind", "private_registry_added", "by", who, "registry", rec.ID, "origin", rec.Registry,
		"mode", rec.Mode, "repositories", len(rec.Repositories), "credential_version", l.credVersion)
	return &pb.AddPrivateRegistryResponse{Registry: s.registryInfo(l)}, nil
}

// RotatePrivateRegistryCredential replaces the credential (admin role). The
// new vault version leaves every read grant bound to the old version
// without effect, and cached results of the old version are not reused.
func (s *Service) RotatePrivateRegistryCredential(ctx context.Context, in *pb.RotatePrivateRegistryCredentialRequest) (*pb.RotatePrivateRegistryCredentialResponse, error) {
	defer clear(in.GetSecret())
	s.registry.adminMu.Lock()
	defer s.registry.adminMu.Unlock()
	who := callerName(ctx)
	id := in.GetRegistryId()
	if !registryIDRe.MatchString(id) {
		return nil, status.Error(codes.InvalidArgument, "invalid registry id")
	}
	credID, err := newRegistryNonce()
	if err != nil {
		return nil, status.Error(codes.Internal, "random source unavailable")
	}
	cred := privateRegistryCred{ID: credID, Username: in.GetUsername(), Secret: in.GetSecret(), ExpiresUnix: in.GetCredentialExpiresUnix()}
	if err := cred.validate(); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid private registry credential")
	}
	if err := s.checkCredentialExpiry(cred.ExpiresUnix); err != nil {
		return nil, err
	}
	old, err := s.loadRegistry(id)
	if err != nil {
		return nil, s.registryAdminError("rotate_private_registry", err)
	}
	old.wipe()
	if err := s.putRegistryCred(id, cred, who); err != nil {
		return nil, s.registryAdminError("rotate_private_registry", err)
	}
	l, err := s.loadRegistry(id)
	if err != nil {
		return nil, s.registryAdminError("rotate_private_registry", err)
	}
	defer l.wipe()
	s.log.Info("audit", "kind", "private_registry_rotated", "by", who, "registry", id,
		"credential_version", l.credVersion, "previous_version", old.credVersion)
	return &pb.RotatePrivateRegistryCredentialResponse{Registry: s.registryInfo(l)}, nil
}

// RemovePrivateRegistry deletes the credential, then the record (admin role).
func (s *Service) RemovePrivateRegistry(ctx context.Context, in *pb.RemovePrivateRegistryRequest) (*pb.RemovePrivateRegistryResponse, error) {
	s.registry.adminMu.Lock()
	defer s.registry.adminMu.Unlock()
	id := in.GetRegistryId()
	if !registryIDRe.MatchString(id) {
		return nil, status.Error(codes.InvalidArgument, "invalid registry id")
	}
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "the executor vault is locked")
	}
	credErr := s.vault.Delete(registryCredID(id))
	if credErr != nil && !errors.Is(credErr, vault.ErrNotFound) {
		return nil, s.registryAdminError("remove_private_registry", credErr)
	}
	cfgErr := s.vault.Delete(registryConfigID(id))
	if cfgErr != nil && !errors.Is(cfgErr, vault.ErrNotFound) {
		return nil, s.registryAdminError("remove_private_registry", cfgErr)
	}
	s.dropRegistryClients(id)
	if credErr != nil && cfgErr != nil {
		return nil, status.Error(codes.NotFound, "private registry not found")
	}
	s.log.Info("audit", "kind", "private_registry_removed", "by", callerName(ctx), "registry", id)
	return &pb.RemovePrivateRegistryResponse{}, nil
}

// ListPrivateRegistries lists metadata only, never a credential.
func (s *Service) ListPrivateRegistries(_ context.Context, _ *pb.ListPrivateRegistriesRequest) (*pb.ListPrivateRegistriesResponse, error) {
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "the executor vault is locked")
	}
	ids, err := s.registryIDs()
	if err != nil {
		return nil, s.registryAdminError("list_private_registries", err)
	}
	slices.Sort(ids)
	out := &pb.ListPrivateRegistriesResponse{}
	for _, id := range ids {
		l, err := s.loadRegistry(id)
		if errors.Is(err, errRegistryNotFound) {
			continue
		}
		if err != nil {
			return nil, s.registryAdminError("list_private_registries", err)
		}
		out.Registries = append(out.Registries, s.registryInfo(l))
		l.wipe()
	}
	return out, nil
}

// registryClient returns the client of one exact configuration, so budgets
// and caches survive across reads but never across a configuration change.
func (s *Service) registryClient(l *loadedRegistry) (*registrymeta.PrivateClient, error) {
	key := l.rec.ID + "/" + l.configDigest
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	if c, ok := s.registry.clients[key]; ok {
		return c, nil
	}
	// The client keeps its own real clock: its rate limiter sleeps, so its
	// clock and sleep must agree. Expiry is checked here with s.clock.
	c, err := registrymeta.NewPrivateClient(registrymeta.PrivateOptions{Registry: l.rec.meta(), RootCAs: l.roots,
		AllowLoopback: s.registry.allowLoopback})
	if err != nil {
		return nil, err
	}
	if s.registry.clients == nil || len(s.registry.clients) >= maxRegistryClients {
		s.registry.clients = map[string]*registrymeta.PrivateClient{}
	}
	s.registry.clients[key] = c
	return c, nil
}

func (s *Service) dropRegistryClients(id string) {
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	for k := range s.registry.clients {
		if strings.HasPrefix(k, id+"/") {
			delete(s.registry.clients, k)
		}
	}
}

// validateReadPrivateRegistry checks the request shape before anything else.
func validateReadPrivateRegistry(in *pb.ReadPrivateRegistryRequest) (string, error) {
	if !registryIDRe.MatchString(in.GetRegistryId()) {
		return "", status.Error(codes.InvalidArgument, "read private registry: invalid registry id")
	}
	if len(in.GetRepository()) == 0 || len(in.GetRepository()) > registrymeta.MaxRepoLen {
		return "", status.Error(codes.InvalidArgument, "read private registry: invalid repository")
	}
	switch in.GetMethod() {
	case pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST:
		tag, digest := in.GetTag(), in.GetDigest()
		if (tag == "") == (digest == "") || (tag != "" && !registrymeta.ValidTag(tag)) || (digest != "" && !registrymeta.ValidDigest(digest)) {
			return "", status.Error(codes.InvalidArgument, "read private registry: exactly one valid tag or digest is required")
		}
		return RegistryMethodTagDigest, nil
	case pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS:
		if in.GetTag() != "" || in.GetDigest() != "" {
			return "", status.Error(codes.InvalidArgument, "read private registry: a tag list takes no tag or digest")
		}
		return RegistryMethodListTags, nil
	}
	return "", status.Error(codes.InvalidArgument, "read private registry: unknown method")
}

// ReadPrivateRegistry performs one typed private registry metadata read:
//
//  1. the request shape is validated;
//  2. the vault must be unlocked; the record and credential are opened at
//     their current versions, the credential must not be expired and the
//     repository must be in the record's exact scope;
//  3. a read grant must cover the registry, method, repository, record
//     digest and both versions, and reserve its budget;
//  4. the read runs with the credential only inside this process: only a
//     manifest HEAD or a tag list GET, against the approved origin and
//     realm, no redirects;
//  5. lock, rotation, removal, expiry and grant revocation are re-checked
//     before the result is returned, so a read across one is discarded;
//  6. values are re-validated; errors carry no credential or registry text.
func (s *Service) ReadPrivateRegistry(ctx context.Context, in *pb.ReadPrivateRegistryRequest) (*pb.ReadPrivateRegistryResponse, error) {
	method, err := validateReadPrivateRegistry(in)
	if err != nil {
		return nil, err
	}
	if err := s.checkNotRecovering(); err != nil {
		return nil, err
	}
	epoch := s.vault.LockGeneration()
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked {
		return nil, status.Error(codes.FailedPrecondition, "read private registry: the executor vault is locked")
	}
	l, err := s.loadRegistry(in.GetRegistryId())
	switch {
	case errors.Is(err, errRegistryNotFound):
		return nil, status.Error(codes.NotFound, "read private registry: registry not found")
	case errors.Is(err, vault.ErrLocked):
		return nil, status.Error(codes.FailedPrecondition, "read private registry: the executor vault is locked")
	case err != nil:
		return nil, status.Error(codes.FailedPrecondition, "read private registry: registry record or credential is unavailable")
	}
	defer l.wipe()
	if !s.clock().Before(time.Unix(l.cred.ExpiresUnix, 0)) {
		return nil, status.Error(codes.FailedPrecondition, "read private registry: the credential expired; rotate it")
	}
	if !slices.Contains(l.rec.Repositories, in.GetRepository()) {
		return nil, status.Error(codes.PermissionDenied, "read private registry: repository is outside the approved scope")
	}
	read := RegistryRead{RegistryID: l.rec.ID, Method: method, Repository: in.GetRepository(), ConfigDigest: l.configDigest,
		ConfigVersion: l.configVersion, CredentialVersion: l.credVersion, CredentialID: l.cred.ID}
	claim, err := s.registryAuthorizer().AuthorizeRegistryRead(read)
	if err != nil {
		return nil, registryGrantStatus(err)
	}
	client, err := s.registryClient(l)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "read private registry: registry configuration is invalid")
	}
	if err := claim.Check(); err != nil {
		return nil, registryGrantStatus(err)
	}
	cred := registrymeta.Credential{Username: l.cred.Username, Secret: l.cred.Secret}
	// Cache entries are keyed by the exact record and credential identity
	// (ADR 0006: private entries also key on credential scope/version).
	scope := l.rec.ID + "/" + l.configDigest + "/" + l.cred.ID + "/v" + strconv.FormatInt(l.credVersion, 10)
	ref := registrymeta.Ref{Registry: l.rec.Registry, Repository: in.GetRepository(), Tag: in.GetTag(), Digest: in.GetDigest()}
	out := &pb.ReadPrivateRegistryResponse{RegistryId: l.rec.ID, Repository: in.GetRepository(), ObservedAtUnix: s.clock().Unix(),
		ConfigVersion: l.configVersion, CredentialVersion: l.credVersion}
	switch method {
	case RegistryMethodTagDigest:
		res, err := client.TagDigest(ctx, ref, cred, scope)
		if err != nil {
			return nil, s.registryReadError(ctx, l.rec.ID, err)
		}
		if !registrymeta.ValidDigest(res.Digest) {
			return nil, status.Error(codes.Unavailable, "read private registry: response failed validation")
		}
		out.Digest, out.FromCache = res.Digest, res.FromCache
	case RegistryMethodListTags:
		res, err := client.ListTags(ctx, ref, cred, scope)
		if err != nil {
			return nil, s.registryReadError(ctx, l.rec.ID, err)
		}
		out.Incomplete, out.FromCache = res.Incomplete, res.FromCache
		for _, t := range res.Tags {
			if !registrymeta.ValidTag(t) {
				// A list with dropped tags is never complete.
				out.Incomplete = true
				continue
			}
			out.Tags = append(out.Tags, t)
		}
	}
	if err := s.recheckRegistryRead(ctx, epoch, l, claim); err != nil {
		return nil, err
	}
	s.log.Info("audit", "kind", "private_registry_read", "registry", l.rec.ID, "repository", in.GetRepository(),
		"method", method, "credential_version", l.credVersion, "grant", claim.ID())
	return out, nil
}

// recheckRegistryRead discards a read that crossed a lock, rotation,
// removal, expiry or grant revocation.
func (s *Service) recheckRegistryRead(ctx context.Context, epoch uint64, l *loadedRegistry, claim RegistryReadClaim) error {
	if err := ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	if st, err := s.vault.State(); err != nil || st != vault.StateUnlocked || s.vault.LockGeneration() != epoch {
		return status.Error(codes.FailedPrecondition, "read private registry: the executor was locked during the read")
	}
	list, err := s.vault.List()
	if err != nil {
		return status.Error(codes.Unavailable, "read private registry: vault unavailable")
	}
	var cfgOK, credOK bool
	for _, i := range list {
		switch i.ID {
		case registryConfigID(l.rec.ID):
			cfgOK = i.Version == l.configVersion
		case registryCredID(l.rec.ID):
			credOK = i.Version == l.credVersion
		}
	}
	if !cfgOK || !credOK {
		return status.Error(codes.Aborted, "read private registry: the registry or its credential changed during the read")
	}
	if !s.clock().Before(time.Unix(l.cred.ExpiresUnix, 0)) {
		return status.Error(codes.FailedPrecondition, "read private registry: the credential expired; rotate it")
	}
	if err := claim.Check(); err != nil {
		return registryGrantStatus(err)
	}
	return nil
}

// registryGrantStatus maps authorization failures.
func registryGrantStatus(err error) error {
	if errors.Is(err, ErrRegistryReadGrantUnavailable) {
		return status.Error(codes.FailedPrecondition, "read private registry: no read-grant profile covers private registry reads")
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	if permit.CodeOf(err) == "" {
		return status.Error(codes.PermissionDenied, "read private registry: no read grant covers this read")
	}
	return readGrantStatus(err)
}

// registryReadError maps registry errors to fixed messages: no registry
// text, URL, credential or token reaches the caller.
func (s *Service) registryReadError(ctx context.Context, id string, err error) error {
	if ctx.Err() != nil {
		return status.FromContextError(ctx.Err()).Err()
	}
	var code codes.Code
	var msg string
	switch {
	case errors.Is(err, registrymeta.ErrOutOfScope):
		code, msg = codes.PermissionDenied, "repository is outside the approved scope"
	case errors.Is(err, registrymeta.ErrRealmNotApproved):
		code, msg = codes.FailedPrecondition, "the registry asked for an unapproved auth realm"
	case errors.Is(err, registrymeta.ErrCredentialRejected):
		code, msg = codes.FailedPrecondition, "the registry refused the credential; rotate it"
	case errors.Is(err, registrymeta.ErrRedirectNotAllowed), errors.Is(err, registrymeta.ErrRequestNotAllowed),
		errors.Is(err, registrymeta.ErrOriginNotAllowed), errors.Is(err, registrymeta.ErrPrivateAddress):
		code, msg = codes.FailedPrecondition, "the registry tried to leave its approved origin"
	case errors.Is(err, registrymeta.ErrRateLimited):
		code, msg = codes.ResourceExhausted, "registry rate limited; paused"
	case errors.Is(err, registrymeta.ErrNotFound):
		code, msg = codes.NotFound, "tag or digest not found"
	case errors.Is(err, registrymeta.ErrBadRef):
		code, msg = codes.InvalidArgument, "invalid reference"
	case errors.Is(err, registrymeta.ErrResponseTooLarge), errors.Is(err, registrymeta.ErrBadResponse):
		code, msg = codes.Unavailable, "registry response failed validation"
	default:
		code, msg = codes.Unavailable, "registry unreachable"
	}
	s.log.Warn("private registry read failed", "registry", id, "reason", msg)
	return status.Error(code, fmt.Sprintf("read private registry: %s", msg))
}
