// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

const (
	regUser   = "ci-robot"
	regSecret = "glpat-private-registry-secret"
	regDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

// fakeRegistry is a TLS private registry. onRequest runs inside the handler
// before it answers, to simulate a lock or rotation during a read.
type fakeRegistry struct {
	srv       *httptest.Server
	mu        sync.Mutex
	reqs      []string
	authz     []string
	secret    string
	token     bool   // token auth on /auth instead of basic
	realm     string // challenge realm override
	tags      []string
	onRequest func()
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	f := &fakeRegistry{secret: regSecret, tags: []string{"1.0.0", "1.1.0"}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(regUser+":"+f.secret))
}

func (f *fakeRegistry) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
	f.authz = append(f.authz, r.Header.Get("Authorization"))
	hook, token, realm := f.onRequest, f.token, f.realm
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	authz := r.Header.Get("Authorization")
	if token {
		if r.URL.Path == "/auth" {
			if authz != f.basic() {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "bearer-xyz"})
			return
		}
		if authz != "Bearer bearer-xyz" {
			if realm == "" {
				realm = f.srv.URL + "/auth"
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`",service="reg"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	} else if authz != f.basic() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/v2/team/app/manifests/"):
		w.Header().Set("Docker-Content-Digest", regDigest)
	case r.Method == http.MethodGet && r.URL.Path == "/v2/team/app/tags/list":
		_ = json.NewEncoder(w).Encode(map[string]any{"name": "team/app", "tags": f.tags})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeRegistry) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *fakeRegistry) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
}

// fakeRegistryGrants is a read-grant stand-in bound to exact versions.
type fakeRegistryGrants struct {
	mu      sync.Mutex
	reads   []RegistryRead
	version int64 // credential version the grant names; 0 = any
	revoked bool
}

type fakeRegistryClaim struct{ g *fakeRegistryGrants }

func (c fakeRegistryClaim) ID() string { return "grant-1" }
func (c fakeRegistryClaim) Check() error {
	c.g.mu.Lock()
	defer c.g.mu.Unlock()
	if c.g.revoked {
		return errors.New("revoked")
	}
	return nil
}

func (g *fakeRegistryGrants) AuthorizeRegistryRead(r RegistryRead) (RegistryReadClaim, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.reads = append(g.reads, r)
	if g.revoked || (g.version != 0 && g.version != r.CredentialVersion) {
		return nil, errors.New("not covered")
	}
	return fakeRegistryClaim{g}, nil
}

type registryEnv struct {
	*reconcileEnv
	reg    *fakeRegistry
	grants *fakeRegistryGrants
}

func newRegistryEnv(t *testing.T) *registryEnv {
	t.Helper()
	e := newReconcileEnv(t)
	e.svc.SetVaultParams(vault.MinParams)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Init(pass, vault.MinParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	e.svc.registry.allowLoopback = true
	g := &fakeRegistryGrants{}
	e.svc.SetRegistryReadAuthorizer(g)
	return &registryEnv{reconcileEnv: e, reg: newFakeRegistry(t), grants: g}
}

func (e *registryEnv) addRequest() *pb.AddPrivateRegistryRequest {
	return &pb.AddPrivateRegistryRequest{
		RegistryId: "corp", RegistryOrigin: e.reg.srv.URL, AuthMode: pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_BASIC,
		Repositories: []string{"team/app"}, CaPem: e.reg.caPEM(), Username: regUser, Secret: []byte(regSecret),
		CredentialExpiresUnix: e.clock.Now().Add(30 * 24 * time.Hour).Unix(),
	}
}

func (e *registryEnv) add(t *testing.T) *pb.PrivateRegistryInfo {
	t.Helper()
	resp, err := e.svc.AddPrivateRegistry(context.Background(), e.addRequest())
	if err != nil {
		t.Fatalf("AddPrivateRegistry: %v", err)
	}
	return resp.GetRegistry()
}

// allLogText renders every captured log record for leak checks.
func allLogText(b *logBuffer) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var sb strings.Builder
	for _, r := range b.records {
		sb.WriteString(r.msg)
		for k, v := range r.attrs {
			sb.WriteString(" " + k + "=" + fmt.Sprint(v))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func digestRead() *pb.ReadPrivateRegistryRequest {
	return &pb.ReadPrivateRegistryRequest{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST,
		Repository: "team/app", Tag: "1.0.0"}
}

func TestPrivateRegistryCredentialAdminIsAdminOnly(t *testing.T) {
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		10001: {peercred.RoleAdmin}, 10002: {peercred.RoleServer}, 10003: {peercred.RolePVECollector},
	}, MethodRoles())
	for _, m := range []string{
		pb.ExecutorService_AddPrivateRegistry_FullMethodName,
		pb.ExecutorService_RotatePrivateRegistryCredential_FullMethodName,
		pb.ExecutorService_RemovePrivateRegistry_FullMethodName,
	} {
		if _, ok := policy.Allowed(10001, m); !ok {
			t.Fatalf("admin denied %s", m)
		}
		for _, uid := range []uint32{10002, 10003, 10004} {
			if _, ok := policy.Allowed(uid, m); ok {
				t.Fatalf("uid %d allowed credential method %s", uid, m)
			}
		}
	}
	for _, m := range []string{pb.ExecutorService_ListPrivateRegistries_FullMethodName, pb.ExecutorService_ReadPrivateRegistry_FullMethodName} {
		if _, ok := policy.Allowed(10002, m); !ok {
			t.Fatalf("server denied %s", m)
		}
		if _, ok := policy.Allowed(10003, m); ok {
			t.Fatalf("pve-collector allowed %s", m)
		}
	}
	// No message the server can receive has a credential-shaped field.
	for _, m := range []protoreflect.ProtoMessage{&pb.PrivateRegistryInfo{}, &pb.ReadPrivateRegistryResponse{}, &pb.ListPrivateRegistriesResponse{}, &pb.ReadPrivateRegistryRequest{}} {
		fields := m.ProtoReflect().Descriptor().Fields()
		for i := 0; i < fields.Len(); i++ {
			name := string(fields.Get(i).Name())
			for _, bad := range []string{"secret", "user", "password", "token", "credential_ref"} {
				if strings.Contains(name, bad) {
					t.Fatalf("%T has credential-shaped field %q", m, name)
				}
			}
		}
	}
}

func TestPrivateRegistryReadUsesVaultCredentialOnlyInExecutor(t *testing.T) {
	e := newRegistryEnv(t)
	req := e.addRequest()
	resp, err := e.svc.AddPrivateRegistry(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Trim(string(req.GetSecret()), "\x00") != "" {
		t.Fatal("request secret buffer was not cleared")
	}
	info := resp.GetRegistry()
	if info.GetCredentialVersion() != 1 || !info.GetCustomCa() || info.GetRegistryOrigin() != e.reg.srv.URL {
		t.Fatalf("info = %+v", info)
	}
	out, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	if err != nil {
		t.Fatalf("ReadPrivateRegistry: %v", err)
	}
	if out.GetDigest() != regDigest || out.GetCredentialVersion() != 1 || out.GetRegistryId() != "corp" {
		t.Fatalf("read = %+v", out)
	}
	if got := e.reg.requests(); len(got) != 1 || got[0] != "HEAD /v2/team/app/manifests/1.0.0" {
		t.Fatalf("registry requests = %q (only a manifest HEAD is allowed)", got)
	}
	if len(e.grants.reads) != 1 {
		t.Fatalf("grant checks = %d", len(e.grants.reads))
	}
	r := e.grants.reads[0]
	if r.RegistryID != "corp" || r.Method != RegistryMethodTagDigest || r.Repository != "team/app" || r.CredentialVersion != 1 ||
		r.ConfigVersion != 1 || len(r.ConfigDigest) != 64 {
		t.Fatalf("grant read = %+v", r)
	}
	tags, err := e.svc.ReadPrivateRegistry(context.Background(), &pb.ReadPrivateRegistryRequest{RegistryId: "corp",
		Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app"})
	if err != nil || len(tags.GetTags()) != 2 || tags.GetIncomplete() {
		t.Fatalf("tags = %+v, %v", tags, err)
	}
	list, err := e.svc.ListPrivateRegistries(context.Background(), &pb.ListPrivateRegistriesRequest{})
	if err != nil || len(list.GetRegistries()) != 1 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, text := range []string{list.String(), out.String(), tags.String(), allLogText(e.logs)} {
		if strings.Contains(text, regSecret) || strings.Contains(text, regUser) {
			t.Fatalf("credential leaked: %s", text)
		}
	}
}

func TestPrivateRegistryReadWithoutGrantIsRefused(t *testing.T) {
	e := newRegistryEnv(t)
	e.add(t)
	e.svc.SetRegistryReadAuthorizer(nil) // production default: fail closed
	_, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "read-grant") {
		t.Fatalf("err = %v", err)
	}
	e.svc.SetRegistryReadAuthorizer(&fakeRegistryGrants{revoked: true})
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked grant: %v", err)
	}
	if n := len(e.reg.requests()); n != 0 {
		t.Fatalf("unauthorized reads sent %d requests", n)
	}
}

func TestPrivateRegistryReadStaysInRepositoryScope(t *testing.T) {
	e := newRegistryEnv(t)
	e.add(t)
	for _, repo := range []string{"team/other", "team", "team/app/x", "TEAM/APP"} {
		in := digestRead()
		in.Repository = repo
		if _, err := e.svc.ReadPrivateRegistry(context.Background(), in); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: %v", repo, err)
		}
	}
	if len(e.grants.reads) != 0 || len(e.reg.requests()) != 0 {
		t.Fatalf("out-of-scope reads reached the grant (%d) or registry (%d)", len(e.grants.reads), len(e.reg.requests()))
	}
	for _, in := range []*pb.ReadPrivateRegistryRequest{
		{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST, Repository: "team/app"},
		{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST, Repository: "team/app", Tag: "a", Digest: regDigest},
		{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app", Tag: "a"},
		{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_UNSPECIFIED, Repository: "team/app"},
		{RegistryId: "../x", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app"},
		{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST, Repository: "team/app", Tag: "../../blobs"},
	} {
		if _, err := e.svc.ReadPrivateRegistry(context.Background(), in); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%+v: %v", in, err)
		}
	}
}

func TestPrivateRegistryLockPausesAndDiscardsReads(t *testing.T) {
	e := newRegistryEnv(t)
	e.add(t)
	e.svc.vault.Lock()
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("locked: %v", err)
	}
	if n := len(e.reg.requests()); n != 0 {
		t.Fatalf("locked executor sent %d requests", n)
	}
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	// Lock and unlock while the registry answers: the result is discarded.
	var once sync.Once
	e.reg.onRequest = func() {
		once.Do(func() {
			e.svc.vault.Lock()
			_ = e.svc.vault.Unlock(pass)
		})
	}
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lock during read: %v", err)
	}
}

func TestPrivateRegistryRotationRebindsGrantsAndDiscardsInFlight(t *testing.T) {
	e := newRegistryEnv(t)
	e.add(t)
	e.grants.version = 1
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); err != nil {
		t.Fatal(err)
	}
	newSecret := "rotated-secret-value"
	rot, err := e.svc.RotatePrivateRegistryCredential(context.Background(), &pb.RotatePrivateRegistryCredentialRequest{
		RegistryId: "corp", Username: regUser, Secret: []byte(newSecret), CredentialExpiresUnix: e.clock.Now().Add(24 * time.Hour).Unix()})
	if err != nil || rot.GetRegistry().GetCredentialVersion() != 2 {
		t.Fatalf("rotate: %+v, %v", rot, err)
	}
	// A grant bound to version 1 no longer covers reads.
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("stale grant: %v", err)
	}
	e.grants.version = 2
	e.reg.mu.Lock()
	e.reg.secret = newSecret
	e.reg.mu.Unlock()
	out, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	if err != nil || out.GetCredentialVersion() != 2 || out.GetFromCache() {
		t.Fatalf("read after rotation: %+v, %v", out, err)
	}
	// Rotation while a read is in flight discards that read.
	e.grants.version = 0
	var once sync.Once
	e.reg.onRequest = func() {
		once.Do(func() {
			_, _ = e.svc.RotatePrivateRegistryCredential(context.Background(), &pb.RotatePrivateRegistryCredentialRequest{
				RegistryId: "corp", Username: regUser, Secret: []byte(newSecret), CredentialExpiresUnix: e.clock.Now().Add(24 * time.Hour).Unix()})
		})
	}
	in := &pb.ReadPrivateRegistryRequest{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app"}
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), in); status.Code(err) != codes.Aborted {
		t.Fatalf("rotation during read: %v", err)
	}
	// Revocation during a read discards it too.
	e.reg.onRequest = func() {
		e.grants.mu.Lock()
		e.grants.revoked = true
		e.grants.mu.Unlock()
	}
	in.Repository, in.Method, in.Tag = "team/app", pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_TAG_DIGEST, "9.9.9"
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), in); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revocation during read: %v", err)
	}
}

func TestPrivateRegistryExpiredCredentialPausesReads(t *testing.T) {
	e := newRegistryEnv(t)
	req := e.addRequest()
	req.CredentialExpiresUnix = e.clock.Now().Add(2 * time.Hour).Unix()
	if _, err := e.svc.AddPrivateRegistry(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Hour)
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	if n := len(e.reg.requests()); n != 0 || len(e.grants.reads) != 0 {
		t.Fatalf("expired credential was used: %d requests, %d grant checks", n, len(e.grants.reads))
	}
	for _, d := range []time.Duration{time.Minute, 91 * 24 * time.Hour, -time.Hour} {
		_, err := e.svc.RotatePrivateRegistryCredential(context.Background(), &pb.RotatePrivateRegistryCredentialRequest{
			RegistryId: "corp", Username: regUser, Secret: []byte("x"), CredentialExpiresUnix: e.clock.Now().Add(d).Unix()})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("expiry %s accepted: %v", d, err)
		}
	}
}

func TestPrivateRegistryRealmIsPinned(t *testing.T) {
	e := newRegistryEnv(t)
	other := newFakeRegistry(t)
	e.reg.token = true
	e.reg.realm = other.srv.URL + "/auth"
	req := e.addRequest()
	req.AuthMode = pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_TOKEN
	req.Realm, req.Service = e.reg.srv.URL+"/auth", "reg"
	if _, err := e.svc.AddPrivateRegistry(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "unapproved auth realm") {
		t.Fatalf("err = %v", err)
	}
	if n := len(other.requests()); n != 0 {
		t.Fatalf("unapproved realm received %d requests", n)
	}
	for _, a := range e.reg.authz {
		if a != "" {
			t.Fatal("a credential was sent despite the unapproved realm")
		}
	}
	// With the approved realm in the challenge the token flow works and
	// the Basic credential goes only to the realm.
	e.reg.mu.Lock()
	e.reg.realm = ""
	e.reg.mu.Unlock()
	in := digestRead()
	in.Tag = "1.1.0"
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), in); err != nil {
		t.Fatalf("approved realm: %v", err)
	}
	e.reg.mu.Lock()
	defer e.reg.mu.Unlock()
	for i, a := range e.reg.authz {
		if strings.HasPrefix(a, "Basic ") && e.reg.reqs[i] != "GET /auth" {
			t.Fatalf("basic credential sent to %s", e.reg.reqs[i])
		}
	}
}

func TestPrivateRegistryAdminValidation(t *testing.T) {
	e := newRegistryEnv(t)
	for name, mutate := range map[string]func(r *pb.AddPrivateRegistryRequest){
		"http origin":   func(r *pb.AddPrivateRegistryRequest) { r.RegistryOrigin = "http://reg.example" },
		"wildcard repo": func(r *pb.AddPrivateRegistryRequest) { r.Repositories = []string{"team/*"} },
		"no repos":      func(r *pb.AddPrivateRegistryRequest) { r.Repositories = nil },
		"bad id":        func(r *pb.AddPrivateRegistryRequest) { r.RegistryId = "Corp/1" },
		"no mode":       func(r *pb.AddPrivateRegistryRequest) { r.AuthMode = 0 },
		"token no realm": func(r *pb.AddPrivateRegistryRequest) {
			r.AuthMode = pb.PrivateRegistryAuthMode_PRIVATE_REGISTRY_AUTH_MODE_TOKEN
		},
		"bad ca":     func(r *pb.AddPrivateRegistryRequest) { r.CaPem = "not a pem" },
		"no secret":  func(r *pb.AddPrivateRegistryRequest) { r.Secret = nil },
		"colon user": func(r *pb.AddPrivateRegistryRequest) { r.Username = "a:b" },
		"no expiry":  func(r *pb.AddPrivateRegistryRequest) { r.CredentialExpiresUnix = 0 },
		"long expiry": func(r *pb.AddPrivateRegistryRequest) {
			r.CredentialExpiresUnix = e.clock.Now().Add(365 * 24 * time.Hour).Unix()
		},
	} {
		req := e.addRequest()
		mutate(req)
		_, err := e.svc.AddPrivateRegistry(context.Background(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(err.Error(), regSecret) {
			t.Fatalf("%s: error leaks the secret", name)
		}
	}
	e.add(t)
	if _, err := e.svc.AddPrivateRegistry(context.Background(), e.addRequest()); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate add: %v", err)
	}
	if _, err := e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); status.Code(err) != codes.NotFound {
		t.Fatalf("read after removal: %v", err)
	}
	if _, err := e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); status.Code(err) != codes.NotFound {
		t.Fatalf("second removal: %v", err)
	}
}

// A removed and re-added registry restarts its vault versions at 1, but its
// record digest and credential identity are new, so a grant bound to the
// old registry cannot cover it.
func TestPrivateRegistryReAddNeverMatchesOldGrantBinding(t *testing.T) {
	e := newRegistryEnv(t)
	e.add(t)
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); err != nil {
		t.Fatal(err)
	}
	e.add(t)
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); err != nil {
		t.Fatal(err)
	}
	first, second := e.grants.reads[0], e.grants.reads[1]
	if first.CredentialVersion != second.CredentialVersion || first.ConfigVersion != second.ConfigVersion {
		t.Fatalf("versions differ unexpectedly: %+v vs %+v", first, second)
	}
	if first.ConfigDigest == second.ConfigDigest || first.CredentialID == second.CredentialID || len(second.CredentialID) != 32 {
		t.Fatalf("re-added registry reuses the old identity: %+v vs %+v", first, second)
	}
}

// TestPrivateRegistryReAddDuringReadIsDiscarded removes and re-adds the
// registry while a read is in flight. Vault versions restart at 1, so the
// re-added registry has the same version numbers; the read must still be
// discarded because the record and credential identity changed.
func TestPrivateRegistryReAddDuringReadIsDiscarded(t *testing.T) {
	e := newRegistryEnv(t)
	e.add(t)
	var once sync.Once
	var reAddErr error
	e.reg.onRequest = func() {
		once.Do(func() {
			if _, err := e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); err != nil {
				reAddErr = err
				return
			}
			_, reAddErr = e.svc.AddPrivateRegistry(context.Background(), e.addRequest())
		})
	}
	_, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	if reAddErr != nil {
		t.Fatalf("remove and re-add during the read: %v", reAddErr)
	}
	if status.Code(err) != codes.Aborted {
		t.Fatalf("read across remove and re-add = %v, want Aborted", err)
	}
	// The re-added registry serves reads again.
	e.reg.onRequest = nil
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); err != nil {
		t.Fatalf("read after re-add: %v", err)
	}
}

func TestPrivateRegistryTagListDropsInvalidTags(t *testing.T) {
	e := newRegistryEnv(t)
	e.reg.tags = []string{"1.0.0", "bad\u0007tag", "-lead"}
	e.add(t)
	out, err := e.svc.ReadPrivateRegistry(context.Background(), &pb.ReadPrivateRegistryRequest{RegistryId: "corp",
		Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app"})
	if err != nil || len(out.GetTags()) != 1 || !out.GetIncomplete() {
		t.Fatalf("out = %+v, %v", out, err)
	}
}
