// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/containerdef"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The execution part of standalone definitions (cu05b): docker.update and
// docker.rollback members get the bound definition as the run secret
// "definition", their runs record its vault secret ID for redaction, and
// their results are judged per container.

// testStandaloneUpdate is a same-tag standalone update binding of
// container "web" on the definition defID at version.
func testStandaloneUpdate(defID string, version uint64) canonical.BatchContainerUpdate {
	return canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormAlone,
		Images: []canonical.ContainerUpdateImage{{Service: "", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{digestOf("a")}, NewIndexDigest: digestOf("b"),
			NewPlatformDigest: digestOf("c"), OldImageID: digestOf("d")}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "", ContainerID: hexOf("1"), ContainerName: "web",
			ImageID: digestOf("d"), RunningReference: "nginx:1.27", ConfigurationDigest: hexOf("2")}},
		Dependencies: []canonical.ContainerUpdateDependency{},
		DefinitionID: defID, DefinitionVersion: version,
	}
}

// passingStandaloneResultFor is a standalone-update-v1 result of a clean
// update of u by execution.
func passingStandaloneResultFor(u canonical.BatchContainerUpdate, execution string) composeUpdateResult {
	zero := 0
	t, img := u.Targets[0], u.Images[0]
	b := snapshotEntry{ID: t.ContainerID, Name: t.ContainerName, Service: "", Replica: "1", State: "running",
		StartedAt: "2026-11-08T01:00:00Z", Health: "healthy", Ports: []string{"80/tcp->0.0.0.0:8080"},
		Mounts:   []snapshotMount{{Type: "volume", Source: "/var/lib/docker/volumes/state/_data", Destination: "/state", Mode: "z", RW: true}},
		Networks: []string{"bridge"}, ImageID: t.ImageID, RunningReference: t.RunningReference, ConfigurationDigest: t.ConfigurationDigest}
	a := b
	a.ID, a.StartedAt = newIncarnation(t.ContainerID), "2026-11-08T02:00:00Z"
	a.ImageID, a.RunningReference, a.ConfigurationDigest = pulledImageID, expectedReference(img), hexOf("9")
	return composeUpdateResult{Format: standaloneUpdateFormat, Phase: phaseAfterSnapshot, RecreateExit: &zero,
		Baseline: []snapshotEntry{b}, After: []snapshotEntry{a},
		Pulled: []resultImage{{Service: "", ImageID: pulledImageID}}, Retained: []resultRetained{{Service: "", Tag: retainedTag(execution, 0)}}}
}

// unlockVault initializes and unlocks the executor vault of e.
func (e *containerEnv) unlockVault(t *testing.T) {
	t.Helper()
	e.svc.SetVaultParams(testVaultParams)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Init(pass, testVaultParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
}

// putDefinition stores a new version of the definition of container web on
// web-1 with env, through the admin RPC, and returns its ID and version and
// the stored encoding.
func (e *containerEnv) putDefinition(t *testing.T, env ...*pb.ContainerDefinitionEnv) (string, uint64, []byte) {
	t.Helper()
	req := putDefinitionRequest("web")
	if len(env) > 0 {
		req.Env = env
	}
	out, err := e.svc.PutContainerDefinition(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	d := out.GetDefinition()
	raw, err := e.svc.vault.Open(executordb.ContainerDefinitionSecretID(d.GetDefinitionId(), d.GetVersion()))
	if err != nil {
		t.Fatal(err)
	}
	return d.GetDefinitionId(), d.GetVersion(), raw
}

// storeRawDefinition stores raw as the next version of web's definition
// without the storage shape check (a corrupted or older store), and
// returns its ID and version.
func (e *containerEnv) storeRawDefinition(t *testing.T, raw []byte) (string, uint64) {
	t.Helper()
	id, err := newExecutionID()
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.db.NextContainerDefinition("web-1", "web", id)
	if err != nil {
		t.Fatal(err)
	}
	next.CreatedBy = "test"
	if _, err := e.svc.vault.PutWithCommit(next.VaultSecretID, raw, "test", func(sec executordb.VaultSecret) error {
		_, err := e.db.AddContainerDefinition(next, sec)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return next.DefinitionID, next.Version
}

// standaloneScript is a stand-in docker.update job, trusted and pinned for
// action: it copies its parameters and its definition secret to
// <dir>/params-<tag>.json and <dir>/def-<tag>.json, writes the definition
// to its log when logDef, waits while <dir>/block exists, prints
// <dir>/result.json and exits with code.
func (e *containerEnv) standaloneScript(t *testing.T, action, tag string, code int, logDef bool) []byte {
	t.Helper()
	logLine := ""
	if logDef {
		logLine = "cat \"$NEBULA_SECRETS_DIR/definition\" >&2\n"
	}
	s := fmt.Appendf(nil, "#!/bin/sh\ncp \"$NEBULA_PARAMS\" %q\ncp \"$NEBULA_SECRETS_DIR/definition\" %q\n%s"+
		"while [ -e %q ]; do sleep 0.05; done\nif [ -f %q ]; then cat %q; else printf '{\"format\":\"test\"}\\n'; fi\nexit %d\n",
		filepath.Join(e.dir, "params-"+tag+".json"), filepath.Join(e.dir, "def-"+tag+".json"), logLine,
		filepath.Join(e.dir, "block"), filepath.Join(e.dir, "result.json"), filepath.Join(e.dir, "result.json"), code)
	e.trustFor(t, s, action, "1.0.0")
	e.svc.batchRun.composePins = append(e.svc.batchRun.composePins, containerArtifact{ActionID: action, ModuleVersion: "1.0.0", SHA256: sha256Hex(s)})
	return s
}

// standaloneRun is one standalone member driven below the batch authority:
// the claim-time step (standaloneMemberSecrets), the dispatcher's intent
// record and the transport, exactly as RunBatchMember drives them after
// the authority admitted and claimed the member. The batch authority
// (internal/permit/batch, outside this change) does not admit standalone
// bindings yet, so a plan with one cannot be proposed in these tests.
type standaloneRun struct {
	execID  string
	member  canonical.BatchMember
	params  []byte
	outcome dispatch.Outcome
	call    *batchMemberCall
	err     error
}

// standaloneMember is a standalone member of u for action, naming art.
func (e *containerEnv) standaloneMember(t *testing.T, action string, u canonical.BatchContainerUpdate, art []byte) (canonical.BatchMember, []byte) {
	t.Helper()
	params, hash, err := canonical.ContainerUpdateParameters(u)
	if err != nil {
		t.Fatal(err)
	}
	hk, ok, err := e.db.HostKey("web-1")
	if err != nil || !ok {
		t.Fatal("web-1 not pinned")
	}
	e.next++
	m := canonical.BatchMember{MemberID: "member-0", ContainerUpdate: &u, Request: canonical.Request{
		RequestVersion: canonical.RequestVersion, ExecutionID: fmt.Sprintf("00000000-0000-4000-9%03d-%012d", e.next, 100), ActionID: action,
		ModuleVersion: "1.0.0", ArtifactSHA256: sha256Hex(art), ParametersHash: hash, CredentialRefs: []string{"cred"},
		RiskClass: canonical.RiskMedium, ResolvedTargets: []canonical.Target{{HostID: "web-1", HostKeyFingerprint: hk.Fingerprint}}},
		CredentialVersions: []canonical.CredentialVersion{{Reference: "cred", Version: CredentialVersionOf(e.userPub)}}, PreconditionHashes: []string{}}
	return m, params
}

// nextStandaloneExecution is the execution ID the next standaloneMember
// call gives its member.
func (e *containerEnv) nextStandaloneExecution() string {
	return fmt.Sprintf("00000000-0000-4000-9%03d-%012d", e.next+1, 100)
}

// runStandalone runs a standalone member of u for action with art; mod,
// when set, changes the call state after the claim-time step (what the
// claim read). ctx bounds the wait for the durable job.
func (e *containerEnv) runStandalone(ctx context.Context, t *testing.T, action string, u canonical.BatchContainerUpdate, art []byte,
	mod func(c *batchMemberCall)) standaloneRun {
	t.Helper()
	m, params := e.standaloneMember(t, action, u, art)
	r := standaloneRun{execID: m.Request.ExecutionID, member: m, params: params}
	x := e.svc.batchRun
	if err := checkContainerMember(m, params, x.composePins...); err != nil {
		t.Fatalf("member check: %v", err)
	}
	secrets, refs, err := e.svc.standaloneMemberSecrets(m, "web-1")
	if err != nil {
		r.err = err
		return r
	}
	eps, err := parseEndpoints([]string{e.ssh["web-1"].addr})
	if err != nil {
		t.Fatal(err)
	}
	hk, _, _ := e.db.HostKey("web-1")
	call := &batchMemberCall{hostID: "web-1", fingerprint: hk.Fingerprint, endpoints: []string{e.ssh["web-1"].addr}, eps: eps,
		artifact: art, secrets: secrets, secretRefs: refs, timeout: containerMutationTimeout,
		resp: &pb.RunBatchMemberResponse{ExecutionId: r.execID, ExitCode: -1}, durable: true}
	if mod != nil {
		mod(call)
	}
	r.call = call
	x.setCall(r.execID, call)
	defer x.setCall(r.execID, nil)
	run := dispatch.Run{ParentDigest: hexOf("d"), MemberID: m.MemberID, ExecutionID: r.execID, ActionID: action, Member: m, Parameters: params}
	rec := batchRunRecorder{s: e.svc, x: x}
	if err := rec.RecordIntent(ctx, run); err != nil {
		t.Fatal(err)
	}
	key := r.execID + "/web-1"
	e.svc.setDispatching(key, true)
	r.outcome, r.err = e.svc.batchTransport(ctx, x, run)
	e.svc.setDispatching(key, false)
	if err := rec.RecordOutcome(ctx, run, r.outcome); err != nil {
		t.Fatal(err)
	}
	return r
}

// The standalone pins are the digests of the docker.update and
// docker.rollback 1.0.0 scripts the server ships, each for its own action
// and version only; a change of a script without a reviewed pin update
// fails here.
func TestShippedStandalonePinsMatchEmbeddedScripts(t *testing.T) {
	for _, pin := range []containerArtifact{shippedStandaloneUpdatePin(), shippedStandaloneRollbackPin()} {
		a, ok := actions.Lookup(pin.ActionID)
		if !ok {
			t.Fatalf("%s is not in the catalog", pin.ActionID)
		}
		if a.Version != pin.ModuleVersion || !a.Durable || a.Timeout != containerMutationTimeout || len(a.Secrets) != 0 {
			t.Fatalf("catalog has %s %s (durable %v, %v, secrets %v), the executor pins %s", a.ID, a.Version, a.Durable, a.Timeout, a.Secrets, pin.ModuleVersion)
		}
		if got := sha256Hex(a.Script); got != pin.SHA256 {
			t.Fatalf("the embedded %s %s script has digest %s, the executor pins %q: update the pin after review", a.ID, a.Version, got, pin.SHA256)
		}
		if !strings.Contains(string(a.Script), pin.ActionID+" 1.0.0") || !strings.Contains(string(a.Script), "NEBULA_SECRETS_DIR") {
			t.Fatalf("the pinned %s script is not the definition-consuming 1.0.0", pin.ActionID)
		}
	}
	// Each pin admits its artifact only for its own action and version.
	u := testStandaloneUpdate("11111111-2222-4333-8444-555555555555", 1)
	m, params := testContainerMember(t, u)
	m.Request.ActionID, m.Request.ModuleVersion, m.Request.ArtifactSHA256 = standaloneUpdateAction, "1.0.0", standaloneUpdateArtifactSHA256
	if err := checkContainerMember(m, params, shippedContainerPins()...); err != nil {
		t.Fatalf("shipped standalone update refused: %v", err)
	}
	m.Request.ArtifactSHA256 = standaloneRollbackArtifactSHA256
	if err := checkContainerMember(m, params, shippedContainerPins()...); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("update member naming the rollback artifact: %v", err)
	}
	m.Request.ArtifactSHA256, m.Request.ModuleVersion = standaloneUpdateArtifactSHA256, "1.0.1"
	if err := checkContainerMember(m, params, shippedContainerPins()...); !errors.Is(err, errContainerArtifact) {
		t.Fatalf("shipped artifact under 1.0.1: %v", err)
	}
	// A standalone binding never runs as a compose action, and the other way round.
	m.Request.ActionID, m.Request.ModuleVersion, m.Request.ArtifactSHA256 = composeUpdateAction, composeUpdateVersion, composeUpdateArtifactSHA256
	if err := checkContainerMember(m, params, shippedContainerPins()...); !errors.Is(err, errContainerUnsupported) {
		t.Fatalf("standalone binding as docker.compose_update: %v", err)
	}
	cm, cparams := testContainerMember(t, testComposeUpdate())
	cm.Request.ActionID, cm.Request.ModuleVersion, cm.Request.ArtifactSHA256 = standaloneUpdateAction, "1.0.0", standaloneUpdateArtifactSHA256
	if err := checkContainerMember(cm, cparams, shippedContainerPins()...); !errors.Is(err, errContainerUnsupported) {
		t.Fatalf("compose binding as docker.update: %v", err)
	}
}

// A standalone container without a stored definition (or with another
// definition ID or version, or with the vault locked) is unavailable: the
// member is refused before the claim, nothing runs, no run or hold is left
// and the member is not spent. The refusal carries no definition content.
func TestStandaloneWithoutDefinitionUnavailable(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	art := e.standaloneScript(t, standaloneUpdateAction, "none", 0, false)
	other := "99999999-2222-4333-8444-555555555555"
	cases := []struct {
		name string
		u    func(id string, v uint64) canonical.BatchContainerUpdate
		pre  func(t *testing.T)
		want string
	}{
		{"no definition stored", func(string, uint64) canonical.BatchContainerUpdate { return testStandaloneUpdate(other, 1) },
			nil, errDefinitionUnavailable.Error()},
		{"another definition ID", func(_ string, v uint64) canonical.BatchContainerUpdate { return testStandaloneUpdate(other, v) },
			func(t *testing.T) { e.putDefinition(t) }, errDefinitionUnavailable.Error()},
		{"a version not stored", func(id string, v uint64) canonical.BatchContainerUpdate { return testStandaloneUpdate(id, v+5) },
			nil, errDefinitionUnavailable.Error()},
		{"vault locked", func(id string, v uint64) canonical.BatchContainerUpdate { return testStandaloneUpdate(id, v) },
			func(t *testing.T) { e.svc.vault.Lock() }, "vault_locked"},
	}
	var id string
	var v uint64
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.pre != nil {
				c.pre(t)
			}
			if id == "" {
				if rows, err := e.db.ContainerDefinitionVersions("web-1", "web"); err == nil {
					id, v = rows[0].DefinitionID, rows[0].Version
				}
			}
			// The claim-time step refuses: RunBatchMember answers
			// FailedPrecondition container_member_refused before the claim.
			r := e.runStandalone(context.Background(), t, standaloneUpdateAction, c.u(id, v), art, nil)
			if r.err == nil || r.call != nil || !strings.Contains(r.err.Error(), c.want) {
				t.Fatalf("err = %v, want refused with %q", r.err, c.want)
			}
			if strings.Contains(r.err.Error(), defPlanted) {
				t.Fatal("the refusal carries definition content")
			}
			if _, err := e.db.GetRun(r.execID, "web-1"); err == nil {
				t.Fatal("a refused member left a run")
			}
		})
	}
	// The recheck right before dispatch refuses the same way.
	if err := e.svc.vault.Unlock([]byte(strings.Repeat("correct-horse-battery-staple-", 4))); err != nil {
		t.Fatal(err)
	}
	m, _ := e.standaloneMember(t, standaloneUpdateAction, testStandaloneUpdate(other, 1), art)
	if err := e.svc.recheckStandaloneDefinition(m.ContainerUpdate, "web-1", nil); !errors.Is(err, errDefinitionUnavailable) {
		t.Fatalf("dispatch recheck without a definition: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-none.json")); err == nil {
		t.Fatal("a member without its definition ran")
	}
}

// A standalone member runs with the bound definition as its run secret
// (exactly the stored encoding, at $NEBULA_SECRETS_DIR/definition) and
// with parameters that are the binding's rendering and name no secret. Its
// run records the slot's vault secret ID, derived from the binding, so its
// durable output is redacted; the passing result is judged recreated.
func TestBatchMemberRecordsDefinitionSecretRefs(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	id, v, stored := e.putDefinition(t)
	art := e.standaloneScript(t, standaloneUpdateAction, "ok", 0, true)
	u := testStandaloneUpdate(id, v)
	e.writeResult(t, passingStandaloneResultFor(u, e.nextStandaloneExecution()))
	r := e.runStandalone(context.Background(), t, standaloneUpdateAction, u, art, nil)
	if r.err != nil || r.outcome != dispatch.OutcomeSuccess {
		t.Fatalf("%v %v %+v", r.outcome, r.err, r.call)
	}
	resp := r.call.resp
	if resp.GetClass() != hostrun.ClassSuccess {
		t.Fatalf("response %+v", resp)
	}
	if r.call.secrets != nil {
		t.Fatal("the executor kept the definition after the dispatch")
	}
	got, err := os.ReadFile(filepath.Join(e.dir, "def-ok.json"))
	if err != nil || !bytes.Equal(got, stored) {
		t.Fatalf("the job got definition %q (%v), want the stored encoding", got, err)
	}
	params, err := os.ReadFile(filepath.Join(e.dir, "params-ok.json"))
	want, _, _ := canonical.ContainerUpdateParameters(u)
	if err != nil || !bytes.Equal(params, want) || bytes.Contains(params, []byte("nebula_secrets")) || bytes.Contains(params, []byte(defPlanted)) {
		t.Fatalf("parameters %q", params)
	}
	run, err := e.db.GetRun(r.execID, "web-1")
	wantRef := executordb.ContainerDefinitionSecretID(id, v)
	if err != nil || len(run.SecretRefs) != 1 || run.SecretRefs[definitionSlot] != wantRef || run.ActionID != standaloneUpdateAction ||
		run.Timeout != containerMutationTimeout {
		t.Fatalf("run %+v %v", run, err)
	}
	// The whole definition the stand-in wrote to its log is redacted.
	for _, out := range [][]byte{run.Log, run.Result, resp.GetLog(), resp.GetResult()} {
		if bytes.Contains(out, []byte(defPlanted)) || bytes.Contains(out, stored) {
			t.Fatalf("definition content in the output: %q", out)
		}
	}
	if !bytes.Contains(run.Log, []byte("[secret "+definitionSlot+" redacted]")) {
		t.Fatalf("log %q", run.Log)
	}
	row, err := e.db.GetContainerRecreation(r.execID)
	if err != nil || row.State != executordb.RecreationRecreated || !row.Verdict.Passed || row.Form != canonical.ContainerUpdateFormAlone ||
		row.Unit != "web" || len(row.Containers) != 1 {
		t.Fatalf("row %+v %v", row, err)
	}
	var def recreationDefinition
	if err := json.Unmarshal(row.Definition, &def); err != nil || def.DefinitionID != id || def.DefinitionVersion != v {
		t.Fatalf("recreation definition %s %v", row.Definition, err)
	}
	noLeakIn(t, e.logs, defPlanted)
}

// noLeakIn fails when any log record of logs holds one of the needles.
func noLeakIn(t *testing.T, logs *logBuffer, needles ...string) {
	t.Helper()
	logs.mu.Lock()
	defer logs.mu.Unlock()
	for _, r := range logs.records {
		line := fmt.Sprint(r.msg, r.attrs)
		for _, n := range needles {
			if strings.Contains(line, n) {
				t.Fatalf("log line holds %q: %s", n, line)
			}
		}
	}
}

// A standalone member whose job finishes while the vault is locked keeps
// its output on the host (the run stays open) until the vault is unlocked;
// then the output is stored with the whole definition redacted.
func TestBatchMemberOutputRedactedWithLockedVaultWaits(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	id, v, stored := e.putDefinition(t)
	art := e.standaloneScript(t, standaloneUpdateAction, "slow", 0, true)
	u := testStandaloneUpdate(id, v)
	e.writeResult(t, passingStandaloneResultFor(u, e.nextStandaloneExecution()))
	block := filepath.Join(e.dir, "block")
	if err := os.WriteFile(block, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(e.dir, "params-slow.json")); err == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	// The wait ends while the job still runs: the run stays open.
	r := e.runStandalone(ctx, t, standaloneUpdateAction, u, art, nil)
	cancel()
	execID := r.execID
	if run, err := e.db.GetRun(execID, "web-1"); err != nil || run.State == executordb.RunFinished || len(run.SecretRefs) != 1 {
		t.Fatalf("run after the wait ended: %+v %v", run, err)
	}
	e.svc.vault.Lock()
	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	// Give the job time to finish on the host, then reconcile while locked.
	waitFor(t, func() bool {
		_, err := os.Stat(filepath.Join(e.dir, "def-slow.json"))
		return err == nil
	})
	time.Sleep(300 * time.Millisecond)
	for range 3 {
		e.svc.ReconcileOnce(context.Background())
		if run, err := e.db.GetRun(execID, "web-1"); err != nil || run.State == executordb.RunFinished {
			t.Fatalf("the run was finished with the vault locked: %+v %v", run, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		e.svc.ReconcileOnce(context.Background())
		run, err := e.db.GetRun(execID, "web-1")
		return err == nil && run.State == executordb.RunFinished
	})
	run, _ := e.db.GetRun(execID, "web-1")
	if run.Class != hostrun.ClassSuccess || bytes.Contains(run.Log, stored) || bytes.Contains(run.Log, []byte(defPlanted)) ||
		!bytes.Contains(run.Log, []byte("[secret "+definitionSlot+" redacted]")) {
		t.Fatalf("run %+v log %q", run, run.Log)
	}
}

// Common env values of a definition (8080, 1000, state) are no redaction
// entries (Q26): a passing result whose snapshot holds them as ports,
// paths or JSON keys is stored byte for byte as the host printed it and
// judged passing.
func TestCommonEnvValuesDoNotRewriteSnapshot(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	id, v, _ := e.putDefinition(t, &pb.ContainerDefinitionEnv{Name: "PORT", Value: "8080"},
		&pb.ContainerDefinitionEnv{Name: "UID", Value: "1000"}, &pb.ContainerDefinitionEnv{Name: "MODE", Value: "state"})
	art := e.standaloneScript(t, standaloneUpdateAction, "common", 0, false)
	u := testStandaloneUpdate(id, v)
	res := passingStandaloneResultFor(u, e.nextStandaloneExecution())
	res.Baseline[0].Ports = []string{"80/tcp->0.0.0.0:8080", "1000/udp->0.0.0.0:1000"}
	res.After[0].Ports = []string{"80/tcp->0.0.0.0:8080", "1000/udp->0.0.0.0:1000"}
	e.writeResult(t, res)
	printed, err := os.ReadFile(filepath.Join(e.dir, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"8080", "1000", `"state"`, "/state"} {
		if !bytes.Contains(printed, []byte(want)) {
			t.Fatalf("the fixture result lacks %s", want)
		}
	}
	r := e.runStandalone(context.Background(), t, standaloneUpdateAction, u, art, nil)
	if r.err != nil || r.outcome != dispatch.OutcomeSuccess {
		t.Fatalf("%v %v", r.outcome, r.err)
	}
	run, err := e.db.GetRun(r.execID, "web-1")
	if err != nil || !bytes.Equal(run.Result, printed) {
		t.Fatalf("stored result %q, printed %q (%v)", run.Result, printed, err)
	}
	row, err := e.db.GetContainerRecreation(r.execID)
	if err != nil || row.State != executordb.RecreationRecreated || !row.Verdict.Passed {
		t.Fatalf("row %+v %v", row, err)
	}
}

// A definition that no longer is the approved one is refused: a vault
// secret replaced under the bound ID (a second vault version), a definition
// removed and stored again (a new definition ID), and a definition that
// differs from the one read at the claim when it is read again right
// before dispatch.
func TestDefinitionChangedAfterApprovalRefused(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	id, v, stored := e.putDefinition(t)
	u := testStandaloneUpdate(id, v)
	sec, err := e.svc.standaloneDefinition(u, "web-1")
	if err != nil || !bytes.Equal(sec.Value, stored) || sec.Slot != definitionSlot {
		t.Fatalf("bound definition: %v", err)
	}
	// Read again before dispatch: the same bytes pass, others do not.
	if err := e.svc.recheckStandaloneDefinition(&u, "web-1", []hostrun.Secret{{Slot: definitionSlot, Value: bytes.Clone(stored)}}); err != nil {
		t.Fatalf("unchanged definition refused at dispatch: %v", err)
	}
	other := bytes.Replace(bytes.Clone(stored), []byte(defPlanted), []byte("another-value-0000"), 1)
	if err := e.svc.recheckStandaloneDefinition(&u, "web-1", []hostrun.Secret{{Slot: definitionSlot, Value: other}}); !errors.Is(err, errDefinitionChanged) {
		t.Fatalf("changed definition at dispatch: %v", err)
	}
	// The vault secret replaced behind the definition store's back.
	if _, err := e.svc.vault.Put(executordb.ContainerDefinitionSecretID(id, v), other, "intruder"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.standaloneDefinition(u, "web-1"); !errors.Is(err, errDefinitionChanged) {
		t.Fatalf("replaced vault secret: %v", err)
	}
	if err := e.svc.recheckStandaloneDefinition(&u, "web-1", []hostrun.Secret{{Slot: definitionSlot, Value: stored}}); !errors.Is(err, errDefinitionChanged) {
		t.Fatalf("replaced vault secret at dispatch: %v", err)
	}
	// Removed and stored again: a new definition ID, which the binding is not.
	if _, err := e.svc.RemoveContainerDefinition(context.Background(), &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web"}); err != nil {
		t.Fatal(err)
	}
	id2, _, _ := e.putDefinition(t)
	if id2 == id {
		t.Fatal("a re-created definition kept its ID")
	}
	if _, err := e.svc.standaloneDefinition(u, "web-1"); !errors.Is(err, errDefinitionUnavailable) {
		t.Fatalf("re-created definition: %v", err)
	}
	// As a member: refused at the claim-time step, nothing runs.
	art := e.standaloneScript(t, standaloneUpdateAction, "changed", 0, false)
	r := e.runStandalone(context.Background(), t, standaloneUpdateAction, u, art, nil)
	if !errors.Is(r.err, errDefinitionUnavailable) || r.call != nil {
		t.Fatalf("err = %v", r.err)
	}
	// A member whose held definition differs from the store at dispatch
	// (changed between the claim and the handoff) ends not executed, with
	// nothing on the host and the definition gone from the executor.
	u2 := testStandaloneUpdate(id2, 1)
	r = e.runStandalone(context.Background(), t, standaloneUpdateAction, u2, art, func(c *batchMemberCall) {
		c.secrets = []hostrun.Secret{{Slot: definitionSlot, Value: bytes.Clone(other)}}
	})
	if r.err != nil || r.outcome != dispatch.OutcomeFailure || r.call.resp.GetClass() != classBatchNotExecuted ||
		!strings.Contains(r.call.resp.GetDetail(), errDefinitionChanged.Error()) || strings.Contains(r.call.resp.GetDetail(), defPlanted) {
		t.Fatalf("%v %v %+v", r.outcome, r.err, r.call.resp)
	}
	if r.call.dispatched {
		t.Fatal("a changed definition reached the host")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-changed.json")); err == nil {
		t.Fatal("a changed definition ran")
	}
	if _, err := e.db.GetContainerRecreation(r.execID); err == nil {
		t.Fatal("a refused member left a recreation row")
	}
}

// The shape is checked again at dispatch, whatever the store holds: an env
// value with a trailing or inner carriage return, a newline or a NUL byte,
// a Docker-chosen host port, an env option or a definition for another
// container is refused without echoing the value.
func TestDefinitionCarriageReturnEnvRefusedAtDispatch(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	art := e.standaloneScript(t, standaloneUpdateAction, "shape", 0, false)
	base := containerdef.Definition{Format: containerdef.Format, ContainerName: "web", Options: []string{"--name=web"}, Command: []string{},
		Env: []containerdef.EnvVar{{Name: "DB_PASSWORD", Value: defPlanted}}}
	cases := []struct {
		name string
		mod  func(d *containerdef.Definition)
	}{
		{"trailing CR", func(d *containerdef.Definition) { d.Env[0].Value += "\r" }},
		{"inner CR", func(d *containerdef.Definition) { d.Env[0].Value = "a\rb" + defPlanted }},
		{"newline", func(d *containerdef.Definition) { d.Env[0].Value += "\nX=1" }},
		{"NUL", func(d *containerdef.Definition) { d.Env[0].Value += "\x00" }},
		{"chosen host port", func(d *containerdef.Definition) { d.Options = append(d.Options, "--publish=80") }},
		{"env option", func(d *containerdef.Definition) { d.Options = append(d.Options, "--env=X="+defPlanted) }},
		{"another container", func(d *containerdef.Definition) { d.ContainerName = "db"; d.Options = []string{"--name=db"} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := base
			d.Env = append([]containerdef.EnvVar(nil), base.Env...)
			d.Options = append([]string(nil), base.Options...)
			c.mod(&d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			id, v := e.storeRawDefinition(t, raw)
			u := testStandaloneUpdate(id, v)
			if _, err := e.svc.standaloneDefinition(u, "web-1"); !errors.Is(err, errDefinitionShape) && !errors.Is(err, errDefinitionUnavailable) {
				t.Fatalf("err = %v", err)
			}
			// The member is refused before the claim (RunBatchMember answers
			// FailedPrecondition container_member_refused with this error).
			r := e.runStandalone(context.Background(), t, standaloneUpdateAction, u, art, nil)
			if r.err == nil || r.call != nil {
				t.Fatalf("err = %v", r.err)
			}
			if strings.Contains(r.err.Error(), defPlanted) || strings.ContainsAny(r.err.Error(), "\r\n\x00") {
				t.Fatalf("the refusal echoes the value: %q", r.err)
			}
			// And again right before dispatch, should the store change
			// between the claim and the handoff.
			if err := e.svc.recheckStandaloneDefinition(&u, "web-1", []hostrun.Secret{{Slot: definitionSlot, Value: raw}}); err == nil {
				t.Fatal("dispatch recheck passed a refused shape")
			}
			if _, err := e.db.GetRun(r.execID, "web-1"); err == nil {
				t.Fatal("a refused member left a run")
			}
		})
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-shape.json")); err == nil {
		t.Fatal("a refused definition ran")
	}
	noLeakIn(t, e.logs, defPlanted)
}

// A standalone rollback recreates from exactly the definition version the
// recorded update used: a rollback binding naming a later version (or
// another definition) differs from the recorded update and is refused, and
// the bound earlier version is what the executor delivers even when a
// newer one exists.
func TestStandaloneRollbackUsesBoundVersion(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	e.unlockVault(t)
	id, v1, stored1 := e.putDefinition(t)
	_, v2, stored2 := e.putDefinition(t, &pb.ContainerDefinitionEnv{Name: "DB_PASSWORD", Value: "a-newer-value-1234"})
	if v2 == v1 || bytes.Equal(stored1, stored2) {
		t.Fatal("no second version")
	}
	now := time.Now()
	upd := testStandaloneUpdate(id, v1)
	updExec := "00000000-0000-4000-8000-0000000000aa"
	binding, err := json.Marshal(upd)
	if err != nil {
		t.Fatal(err)
	}
	base := passingStandaloneResultFor(upd, updExec)
	baseline, _ := json.Marshal(base.Baseline)
	after := base.After[0]
	row := executordb.ContainerRecreation{ExecutionID: updExec, Kind: canonical.ContainerUpdateKindUpdate, HostID: "web-1",
		Form: canonical.ContainerUpdateFormAlone, Unit: "web", Binding: binding, Baseline: baseline,
		State: executordb.RecreationRecreated, WindowExpiresAt: now.Add(time.Hour),
		Images: []executordb.RecreationImage{{Service: "", Repository: "docker.io/library/nginx", OldTag: "1.27", NewTag: "1.27",
			NewPlatformDigest: digestOf("c"), PriorImageID: digestOf("d"), RetainedTag: retainedTag(updExec, 0),
			RetainedReference: "docker.io/library/nginx:1.27@" + digestOf("a")}},
		Containers: []executordb.RecreationContainer{{Service: "", Replica: "1", Name: "web", IDBefore: hexOf("1"), IDAfter: after.ID,
			ReferenceAfter: after.RunningReference, ConfigAfter: after.ConfigurationDigest, ImageAfter: after.ImageID, Status: executordb.ContainerRecreated}},
	}
	plan := executordb.RecoveryPlan{HostID: "web-1", Unit: "web", Kind: executordb.RecoveryNoData, Actor: "alice", Version: 1, RecordedAt: now}
	rb := canonical.BatchContainerUpdate{Kind: canonical.ContainerUpdateKindRollback, Form: canonical.ContainerUpdateFormAlone,
		Images: []canonical.ContainerUpdateImage{{Service: "", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{digestOf("c")},
			Rollback: &canonical.ContainerRollbackImage{PriorImageID: digestOf("d"), RetainedTag: retainedTagName(updExec, 0),
				RetainedReference: "docker.io/library/nginx:1.27@" + digestOf("a")}}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "", ContainerID: after.ID, ContainerName: "web", ImageID: after.ImageID,
			RunningReference: after.RunningReference, ConfigurationDigest: after.ConfigurationDigest}},
		Dependencies: []canonical.ContainerUpdateDependency{}, DefinitionID: id, DefinitionVersion: v1,
		RollbackOf: updExec, RecoveryPlanDigest: plan.Digest()}
	if err := checkRollbackSource(rb, row, &plan, "web-1", now); err != nil {
		t.Fatalf("rollback with the bound version refused: %v", err)
	}
	for name, mod := range map[string]func(u *canonical.BatchContainerUpdate){
		"a later version":       func(u *canonical.BatchContainerUpdate) { u.DefinitionVersion = v2 },
		"another definition ID": func(u *canonical.BatchContainerUpdate) { u.DefinitionID = "99999999-2222-4333-8444-555555555555" },
	} {
		bad := rb.Clone()
		mod(&bad)
		if err := checkRollbackSource(bad, row, &plan, "web-1", now); !errors.Is(err, errRollbackBindingDiffers) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	sec, err := e.svc.standaloneDefinition(rb, "web-1")
	if err != nil || !bytes.Equal(sec.Value, stored1) {
		t.Fatalf("the rollback did not get the bound version: %v", err)
	}
	// The rollback's result is judged against the update's baseline.
	zero := 0
	b := after
	a := base.Baseline[0]
	a.ID, a.ImageID, a.RunningReference = hexOf("7"), digestOf("d"), rb.Images[0].Rollback.RetainedReference
	res := composeUpdateResult{Format: standaloneRollbackFormat, Phase: phaseAfterSnapshot, RecreateExit: &zero,
		Baseline: []snapshotEntry{b}, After: []snapshotEntry{a}}
	if v := judgeStandaloneRollback(rb, base.Baseline, res); !v.Passed {
		t.Fatalf("passing rollback: %v", v.Findings)
	}
	a.ImageID = digestOf("e")
	res.After = []snapshotEntry{a}
	if v := judgeStandaloneRollback(rb, base.Baseline, res); v.Passed {
		t.Fatal("a rollback onto another image passed")
	}
}

// The standalone judge passes only a clean recreate of the bound container
// and fails every deviation.
func TestJudgeStandaloneUpdate(t *testing.T) {
	u := testStandaloneUpdate("11111111-2222-4333-8444-555555555555", 1)
	exec := "00000000-0000-4000-8000-0000000000cc"
	tag := retainedTag(exec, 0)
	if v := judgeStandaloneUpdate(u, tag, passingStandaloneResultFor(u, exec)); !v.Passed {
		t.Fatalf("clean update: %v", v.Findings)
	}
	one := 1
	cases := map[string]func(r *composeUpdateResult){
		"not recreated":        func(r *composeUpdateResult) { r.After[0].ID = r.Baseline[0].ID },
		"missing after":        func(r *composeUpdateResult) { r.After = []snapshotEntry{} },
		"no after-snapshot":    func(r *composeUpdateResult) { r.After = nil },
		"two after":            func(r *composeUpdateResult) { r.After = append(r.After, r.After[0]) },
		"other name":           func(r *composeUpdateResult) { r.After[0].Name = "web2" },
		"other image":          func(r *composeUpdateResult) { r.After[0].ImageID = digestOf("0") },
		"other reference":      func(r *composeUpdateResult) { r.After[0].RunningReference = "nginx:1.27" },
		"not running":          func(r *composeUpdateResult) { r.After[0].State = "exited" },
		"health regressed":     func(r *composeUpdateResult) { r.After[0].Health = "unhealthy" },
		"ports changed":        func(r *composeUpdateResult) { r.After[0].Ports = []string{"80/tcp->0.0.0.0:9090"} },
		"retained elsewhere":   func(r *composeUpdateResult) { r.Retained[0].Tag = retainedTag(exec, 1) },
		"nothing pulled":       func(r *composeUpdateResult) { r.Pulled = nil },
		"recreate failed":      func(r *composeUpdateResult) { r.RecreateExit = &one },
		"reason reported":      func(r *composeUpdateResult) { r.Reason = "remove_failed" },
		"baseline drifted":     func(r *composeUpdateResult) { r.Baseline[0].ConfigurationDigest = hexOf("0") },
		"baseline other":       func(r *composeUpdateResult) { r.Baseline[0].ID = hexOf("0") },
		"stopped in precheck":  func(r *composeUpdateResult) { r.Phase = phasePrecheck },
		"oversize after entry": func(r *composeUpdateResult) { r.After[0] = snapshotEntry{ID: r.After[0].ID, Oversize: true} },
	}
	for name, mod := range cases {
		r := passingStandaloneResultFor(u, exec)
		mod(&r)
		if v := judgeStandaloneUpdate(u, tag, r); v.Passed {
			t.Errorf("%s passed", name)
		}
	}
	// A compose binding is never judged by the standalone judge.
	if v := judgeStandaloneUpdate(testComposeUpdate(), tag, passingStandaloneResultFor(u, exec)); v.Passed {
		t.Fatal("compose binding judged standalone")
	}
}

// The standalone result formats are parsed strictly: no project, service
// or up_exit, entries and images under service "" with replica "1", and a
// compose result carries no recreate_exit.
func TestStandaloneResultParsing(t *testing.T) {
	u := testStandaloneUpdate("11111111-2222-4333-8444-555555555555", 1)
	good := passingStandaloneResultFor(u, "00000000-0000-4000-8000-0000000000cc")
	if _, err := parseContainerResult(mustResultJSON(t, good), standaloneUpdateFormat); err != nil {
		t.Fatalf("good: %v", err)
	}
	zero := 0
	cases := map[string]func(r *composeUpdateResult){
		"project":         func(r *composeUpdateResult) { r.Project = "site" },
		"service":         func(r *composeUpdateResult) { r.Service = "web" },
		"up_exit":         func(r *composeUpdateResult) { r.UpExit = &zero },
		"entry service":   func(r *composeUpdateResult) { r.After[0].Service = "web" },
		"entry replica":   func(r *composeUpdateResult) { r.After[0].Replica = "2" },
		"pulled service":  func(r *composeUpdateResult) { r.Pulled[0].Service = "web" },
		"compose format":  func(r *composeUpdateResult) { r.Format = composeUpdateFormat },
		"rollback pulled": func(r *composeUpdateResult) { r.Format = standaloneRollbackFormat },
	}
	for name, mod := range cases {
		r := passingStandaloneResultFor(u, "00000000-0000-4000-8000-0000000000cc")
		mod(&r)
		format := standaloneUpdateFormat
		if r.Format == standaloneRollbackFormat {
			format = standaloneRollbackFormat
		}
		if _, err := parseContainerResult(mustResultJSON(t, r), format); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	c := passingComposeResult(testComposeUpdate())
	c.RecreateExit = &zero
	if _, err := parseContainerResult(mustResultJSON(t, c), composeUpdateFormat); err == nil {
		t.Fatal("compose result with recreate_exit accepted")
	}
}
