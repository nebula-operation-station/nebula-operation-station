// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// registryLeaseEnv is a registryEnv whose reads are authorized by the
// production authorizer (Service.RegistryReadGrants) over the real permit
// authority and executor.db, with read dispatch resumed.
type registryLeaseEnv struct {
	*registryEnv
	grantSeq int
}

func newRegistryLeaseEnv(t *testing.T) *registryLeaseEnv {
	t.Helper()
	e := newRegistryEnv(t)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{Verifier: v, Store: e.db, RiskPolicy: risk, Leases: e.db, Now: e.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.ResumeReadDispatch(); err != nil {
		t.Fatal(err)
	}
	e.svc.SetRegistryReadAuthorizer(e.svc.RegistryReadGrants())
	return &registryLeaseEnv{registryEnv: e}
}

// addRepos adds the "corp" registry with the given repository scope.
func (e *registryLeaseEnv) addRepos(t *testing.T, repos ...string) {
	t.Helper()
	req := e.addRequest()
	req.Repositories = repos
	if _, err := e.svc.AddPrivateRegistry(context.Background(), req); err != nil {
		t.Fatalf("AddPrivateRegistry: %v", err)
	}
}

// target freezes the executor's current record and credential identity.
func (e *registryLeaseEnv) target(t *testing.T, methods []string, repos ...string) permit.RegistryTarget {
	t.Helper()
	l, err := e.svc.loadRegistry("corp")
	if err != nil {
		t.Fatal(err)
	}
	defer l.wipe()
	return permit.RegistryTarget{RegistryID: "corp", ConfigDigest: l.configDigest, ConfigVersion: l.configVersion,
		CredentialID: l.cred.ID, CredentialVersion: l.credVersion, Repositories: repos, Methods: methods}
}

// lease proposes and approves a registry read lease and returns its id and
// stored document.
func (e *registryLeaseEnv) lease(t *testing.T, budget int64, lifetime time.Duration, targets ...permit.RegistryTarget) (string, []byte) {
	t.Helper()
	e.grantSeq++
	id := fmt.Sprintf("00000000-0000-4000-8000-%012x", 0xc06a00+e.grantSeq)
	now := e.clock.Now()
	d := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: id, Issuer: "root", CreatedUnix: now.Unix(),
		ExpiryUnix: now.Add(lifetime).Unix(), Trigger: permit.TriggerOnDemand,
		Actions: []permit.ReadGrantAction{}, MinIntervalS: 900, RunBudget: budget,
		RateProfile: schedgrant.RegistryReadProfile, RegistryTargets: targets,
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.svc.auth.ProposeReadGrant(raw)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	g, err := e.svc.auth.ApproveReadGrantCLI(p.Digest, "test")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	return id, g.Doc
}

func (e *registryLeaseEnv) defaultLease(t *testing.T) string {
	t.Helper()
	id, _ := e.lease(t, schedgrant.RegistryDefaultRunBudget, 7*24*time.Hour,
		e.target(t, []string{schedgrant.RegistryReadTagDigest}, "team/app"))
	return id
}

func wantRegistryCode(t *testing.T, err error, code codes.Code, contains string) {
	t.Helper()
	if status.Code(err) != code || !strings.Contains(status.Convert(err).Message(), contains) {
		t.Fatalf("got %v, want %v containing %q", err, code, contains)
	}
}

// TestRegistryLeaseReadKeepsCredentialInExecutor: with a covering lease the
// read succeeds; the credential appears in no response, lease document,
// claim id, error or log line; only the registry saw it.
func TestRegistryLeaseReadKeepsCredentialInExecutor(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	id, doc := e.lease(t, schedgrant.RegistryDefaultRunBudget, 7*24*time.Hour,
		e.target(t, schedgrant.RegistryReadMethods(), "team/app"))
	resp, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.GetDigest() != regDigest {
		t.Fatalf("digest %q", resp.GetDigest())
	}
	list := &pb.ReadPrivateRegistryRequest{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app"}
	tags, err := e.svc.ReadPrivateRegistry(context.Background(), list)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	logs := allLogText(e.logs)
	if !strings.Contains(logs, id) {
		t.Fatalf("audit lacks the paying lease %s:\n%s", id, logs)
	}
	basic := e.reg.basic()
	for name, text := range map[string]string{
		"digest response": prototext.Format(resp), "tags response": prototext.Format(tags),
		"lease document": string(doc), "logs": logs,
	} {
		for _, secret := range []string{regSecret, basic, strings.TrimPrefix(basic, "Basic ")} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s carries the credential", name)
			}
		}
	}
	if strings.Contains(string(doc), regUser) {
		t.Fatal("lease document carries the registry user name")
	}
	if got := e.reg.requests(); len(got) != 2 {
		t.Fatalf("registry requests %v", got)
	}
}

// TestRegistryLeaseProductionDefaultRefusesWithoutLease: the production
// authorizer without any lease refuses before any registry I/O.
func TestRegistryLeaseProductionDefaultRefusesWithoutLease(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	_, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead())
	wantRegistryCode(t, err, codes.PermissionDenied, "no approved registry read lease")
	if got := e.reg.requests(); len(got) != 0 {
		t.Fatalf("registry contacted without a lease: %v", got)
	}
}

// TestRegistryLeaseOutOfScopeRepositoryRefused: a repository outside the
// record scope and one inside the record but outside the lease, and a
// method the lease does not list, are refused before any registry I/O.
func TestRegistryLeaseOutOfScopeRepositoryRefused(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app", "team/worker")
	e.defaultLease(t)
	ctx := context.Background()
	outside := digestRead()
	outside.Repository = "team/other"
	_, err := e.svc.ReadPrivateRegistry(ctx, outside)
	wantRegistryCode(t, err, codes.PermissionDenied, "outside the approved scope")
	notLeased := digestRead()
	notLeased.Repository = "team/worker"
	_, err = e.svc.ReadPrivateRegistry(ctx, notLeased)
	wantRegistryCode(t, err, codes.PermissionDenied, "does not cover this repository or method")
	list := &pb.ReadPrivateRegistryRequest{RegistryId: "corp", Method: pb.PrivateRegistryReadMethod_PRIVATE_REGISTRY_READ_METHOD_LIST_TAGS, Repository: "team/app"}
	_, err = e.svc.ReadPrivateRegistry(ctx, list)
	wantRegistryCode(t, err, codes.PermissionDenied, "does not cover this repository or method")
	if got := e.reg.requests(); len(got) != 0 {
		t.Fatalf("registry contacted for an uncovered read: %v", got)
	}
	// A prefix of a leased repository is not the repository.
	if _, err := e.svc.checkRegistryLease(ctx, RegistryRead{RegistryID: "corp", Method: schedgrant.RegistryReadTagDigest,
		Repository: "team"}, e.clock.Now()); !errors.Is(err, ErrRegistryReadNotLeased) && !errors.Is(err, ErrRegistryLeaseStale) {
		t.Fatalf("prefix repository: %v", err)
	}
}

// TestRegistryLeaseRotationLeavesLeaseStale: a rotated credential never
// matches an older lease; a new lease over the new identity works.
func TestRegistryLeaseRotationLeavesLeaseStale(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	e.defaultLease(t)
	ctx := context.Background()
	if _, err := e.svc.RotatePrivateRegistryCredential(ctx, &pb.RotatePrivateRegistryCredentialRequest{RegistryId: "corp",
		Username: regUser, Secret: []byte(regSecret), CredentialExpiresUnix: e.clock.Now().Add(30 * 24 * time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
	wantRegistryCode(t, err, codes.PermissionDenied, "needs replacement")
	e.defaultLease(t)
	if _, err := e.svc.ReadPrivateRegistry(ctx, digestRead()); err != nil {
		t.Fatalf("after new lease: %v", err)
	}
}

// TestRegistryLeaseReAddLeavesLeaseStale: removing and re-adding the
// registry (vault versions restart) never matches the old lease.
func TestRegistryLeaseReAddLeavesLeaseStale(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	e.defaultLease(t)
	ctx := context.Background()
	if _, err := e.svc.RemovePrivateRegistry(ctx, &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); err != nil {
		t.Fatal(err)
	}
	e.addRepos(t, "team/app")
	_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
	wantRegistryCode(t, err, codes.PermissionDenied, "needs replacement")
}

// TestRegistryLeaseExpiryAndRevocation: an expired or revoked lease does
// not authorize; an expired credential pauses reads even under a lease.
func TestRegistryLeaseExpiryAndRevocation(t *testing.T) {
	ctx := context.Background()
	t.Run("lease expiry", func(t *testing.T) {
		e := newRegistryLeaseEnv(t)
		e.addRepos(t, "team/app")
		e.lease(t, schedgrant.RegistryDefaultRunBudget, time.Hour, e.target(t, []string{schedgrant.RegistryReadTagDigest}, "team/app"))
		e.clock.Add(time.Hour)
		_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
		wantRegistryCode(t, err, codes.PermissionDenied, "expired")
	})
	t.Run("revocation", func(t *testing.T) {
		e := newRegistryLeaseEnv(t)
		e.addRepos(t, "team/app")
		id := e.defaultLease(t)
		if err := e.svc.auth.RevokeReadGrant(id, "test"); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
		wantRegistryCode(t, err, codes.PermissionDenied, "no approved registry read lease")
	})
	t.Run("revocation after claim", func(t *testing.T) {
		e := newRegistryLeaseEnv(t)
		e.addRepos(t, "team/app")
		id := e.defaultLease(t)
		e.reg.onRequest = func() {
			if err := e.svc.auth.RevokeReadGrant(id, "test"); err != nil {
				t.Error(err)
			}
		}
		_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
		wantRegistryCode(t, err, codes.PermissionDenied, "no approved registry read lease")
	})
	t.Run("credential expiry", func(t *testing.T) {
		e := newRegistryLeaseEnv(t)
		req := e.addRequest()
		req.CredentialExpiresUnix = e.clock.Now().Add(2 * time.Hour).Unix()
		if _, err := e.svc.AddPrivateRegistry(ctx, req); err != nil {
			t.Fatal(err)
		}
		e.defaultLease(t)
		e.clock.Add(2 * time.Hour)
		_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
		wantRegistryCode(t, err, codes.FailedPrecondition, "credential expired")
		if got := e.reg.requests(); len(got) != 0 {
			t.Fatalf("registry contacted with an expired credential: %v", got)
		}
	})
}

// TestRegistryLeasePausedByLock: Lock pauses registry reads like every
// read; a vault unlock alone does not resume them, the local credential
// unlock does. A lock during the read discards it.
func TestRegistryLeasePausedByLock(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.usePrivateKeyring()
	e.addRepos(t, "team/app")
	e.defaultLease(t)
	ctx := context.Background()
	if _, err := e.svc.Lock(ctx, &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.ReadPrivateRegistry(ctx, digestRead())
	wantRegistryCode(t, err, codes.FailedPrecondition, "locked")
	if err := e.svc.vault.Unlock([]byte(strings.Repeat("correct-horse-battery-staple-", 4))); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.ReadPrivateRegistry(ctx, digestRead())
	wantRegistryCode(t, err, codes.FailedPrecondition, "paused until local credential unlock")
	resp, err := e.svc.Unlock(ctx, &pb.UnlockRequest{Passphrase: []byte(testPassphrase), Scope: pb.UnlockScope_UNLOCK_SCOPE_KEYS})
	if err != nil || !resp.GetKeysUnlocked() {
		t.Fatalf("local unlock: %v %v", resp, err)
	}
	if _, err := e.svc.ReadPrivateRegistry(ctx, digestRead()); err != nil {
		t.Fatalf("after local unlock: %v", err)
	}
	e.clock.Add(15 * time.Minute)
	e.reg.onRequest = func() {
		if _, err := e.svc.Lock(ctx, &pb.LockRequest{}); err != nil {
			t.Error(err)
		}
	}
	uncached := digestRead()
	uncached.Tag = "1.1.0" // not cached: the read reaches the registry
	_, err = e.svc.ReadPrivateRegistry(ctx, uncached)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lock during read: %v", err)
	}
}

// TestRegistryLeaseIntervalAndBudget: the 15-minute floor holds per
// repository and method, the budget per registry.
func TestRegistryLeaseIntervalAndBudget(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app", "team/worker")
	e.lease(t, 2, 7*24*time.Hour, e.target(t, schedgrant.RegistryReadMethods(), "team/app", "team/worker"))
	ctx := context.Background()
	// The same tag as digestRead, so the RPC below is the same read.
	r := RegistryRead{RegistryID: "corp", Method: schedgrant.RegistryReadTagDigest, Repository: "team/app", Reference: "1.0.0"}
	l, err := e.svc.loadRegistry("corp")
	if err != nil {
		t.Fatal(err)
	}
	r.ConfigDigest, r.ConfigVersion, r.CredentialID, r.CredentialVersion = l.configDigest, l.configVersion, l.cred.ID, l.credVersion
	l.wipe()
	if _, err := e.svc.checkRegistryLease(ctx, r, e.clock.Now()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := e.svc.checkRegistryLease(ctx, r, e.clock.Now().Add(14*time.Minute)); !errors.Is(err, ErrRegistryTooSoon) {
		t.Fatalf("within the floor: %v", err)
	}
	if _, err := e.svc.ReadPrivateRegistry(ctx, digestRead()); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("RPC within the floor: %v", err)
	}
	other := r
	other.Repository = "team/worker"
	if _, err := e.svc.checkRegistryLease(ctx, other, e.clock.Now()); err != nil {
		t.Fatalf("other repository: %v", err)
	}
	third := r
	third.Method = schedgrant.RegistryReadListTags
	if _, err := e.svc.checkRegistryLease(ctx, third, e.clock.Now()); !errors.Is(err, ErrRegistryBudget) {
		t.Fatalf("over budget: %v", err)
	}
}

// TestRegistryLeaseDoesNotAuthorizeOtherReads: a registry lease is not an
// SSH, provider or device read lease.
func TestRegistryLeaseDoesNotAuthorizeOtherReads(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	id := e.defaultLease(t)
	g, ok, err := e.db.ReadGrant(id)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if _, isLease, err := netDevLeaseDoc(g); err != nil || isLease {
		t.Fatalf("registry lease read as a device lease: %v %v", isLease, err)
	}
	doc, isLease, err := registryLeaseDoc(g)
	if err != nil || !isLease || len(doc.Actions) != 0 || len(doc.Targets) != 0 {
		t.Fatalf("registry lease doc: %+v %v %v", doc, isLease, err)
	}
}

// TestRegistryLeaseIntervalIsPerTag: the interval key is registry, method,
// repository and tag, so two tags of one repository read at the same time
// are both authorized, while the same tag again within the floor is not.
func TestRegistryLeaseIntervalIsPerTag(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	e.defaultLease(t)
	ctx := context.Background()
	r := RegistryRead{RegistryID: "corp", Method: schedgrant.RegistryReadTagDigest, Repository: "team/app", Reference: "1.0.0"}
	l, err := e.svc.loadRegistry("corp")
	if err != nil {
		t.Fatal(err)
	}
	r.ConfigDigest, r.ConfigVersion, r.CredentialID, r.CredentialVersion = l.configDigest, l.configVersion, l.cred.ID, l.credVersion
	l.wipe()
	if _, err := e.svc.checkRegistryLease(ctx, r, e.clock.Now()); err != nil {
		t.Fatalf("first tag: %v", err)
	}
	second := r
	second.Reference = "2.0.0"
	if _, err := e.svc.checkRegistryLease(ctx, second, e.clock.Now()); err != nil {
		t.Fatalf("second tag of the same repository: %v", err)
	}
	if _, err := e.svc.checkRegistryLease(ctx, r, e.clock.Now()); !errors.Is(err, ErrRegistryTooSoon) {
		t.Fatalf("same tag again: %v", err)
	}
	if registryActionKey(r.Method, r.Repository, "1.0.0") == registryActionKey(r.Method, r.Repository, "2.0.0") ||
		registryActionKey(r.Method, "team/app", "") == registryActionKey(schedgrant.RegistryReadListTags, "team/app", "") {
		t.Fatal("interval keys collide")
	}
}

// TestRegistryLeaseUnverifiableStoredLeaseIsSkipped: one stored registry
// lease that fails re-verification is skipped (and logged), so a valid
// lease still authorizes the read instead of an internal error for all.
func TestRegistryLeaseUnverifiableStoredLeaseIsSkipped(t *testing.T) {
	e := newRegistryLeaseEnv(t)
	e.addRepos(t, "team/app")
	id := e.defaultLease(t)
	g, ok, err := e.db.ReadGrant(id)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	bad := g
	bad.ID = "00000000-0000-4000-8000-000000000001" // sorts first
	bad.Digest = strings.Repeat("0", 64)
	if err := e.db.SaveReadGrant(bad); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ReadPrivateRegistry(context.Background(), digestRead()); err != nil {
		t.Fatalf("read with one valid and one unverifiable lease: %v", err)
	}
	if !strings.Contains(allLogText(e.logs), "registry read lease skipped") {
		t.Fatalf("skipped lease not logged: %s", allLogText(e.logs))
	}
}
