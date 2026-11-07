// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

func hx(c string) string { return strings.Repeat(c, 64) }
func sd(c string) string { return "sha256:" + hx(c) }

const testPolicyVersion = "stable-v1"

var testPolicyDigest = hx("5")

// sameTagUpdate is a compose same-tag refresh of one service.
func sameTagUpdate() canonical.BatchContainerUpdate {
	return canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormCompose,
		Images: []canonical.ContainerUpdateImage{{Service: "app", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{sd("1")}, NewIndexDigest: sd("2"), NewPlatformDigest: sd("3"), OldImageID: sd("4")}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "app", ContainerID: hx("a"), ContainerName: "shop-app-1", ImageID: sd("4"),
			RunningReference: "nginx:1.27", ConfigurationDigest: hx("b")}},
		Dependencies: []canonical.ContainerUpdateDependency{},
		SourceDigest: hx("2"), Project: "shop", WorkingDirHash: hx("3"), ConfigFilesHash: hx("4"),
	}
}

// tagChangeUpdate moves app from 1.27 to 1.28 under the test policy.
func tagChangeUpdate() canonical.BatchContainerUpdate {
	u := sameTagUpdate()
	u.Images[0].NewTag = "1.28"
	u.Images[0].PolicyVersion = testPolicyVersion
	u.Images[0].PolicyDigest = testPolicyDigest
	return u
}

type tagPolicy struct {
	mu      sync.Mutex
	version string
	digest  string
	major   bool
	err     error
	calls   int
}

func (p *tagPolicy) CompareTags(_, oldTag, newTag string) (TagComparison, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.err != nil {
		return TagComparison{}, p.err
	}
	return TagComparison{PolicyVersion: p.version, PolicyDigest: p.digest, MajorChange: p.major}, nil
}

func (p *tagPolicy) setDigest(d string) { p.mu.Lock(); p.digest = d; p.mu.Unlock() }

// withTagPolicy rebuilds the (still empty) authority with tp.
func (e *environment) withTagPolicy(t *testing.T, tp TagPolicy) {
	t.Helper()
	e.options.TagPolicy = tp
	a, err := New(e.options)
	if err != nil {
		t.Fatal(err)
	}
	e.a = a
}

func defaultTagPolicy() *tagPolicy {
	return &tagPolicy{version: testPolicyVersion, digest: testPolicyDigest}
}

// containerPlan is a one-member batch for action with binding u, whose
// parameters are rendered from u. policyRisk is the executor policy's floor.
func (e *environment) containerPlan(t *testing.T, action string, label, policyRisk canonical.Risk, u *canonical.BatchContainerUpdate) ([]byte, []MemberInput) {
	t.Helper()
	raw, in := e.plan(t, label)
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	m := &b.Members[0]
	m.Request.ActionID = action
	m.ContainerUpdate = u
	if u != nil {
		params, hash, err := canonical.ContainerUpdateParameters(*u)
		if err != nil {
			t.Fatal(err)
		}
		m.Request.ParametersHash = hash
		in[0].ParametersJSON = params
	}
	e.policy.set(m.MemberID, Snapshot{Risk: policyRisk, Trust: sha256.Sum256([]byte("trust"))})
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw, in
}

func (e *environment) proposeContainer(t *testing.T, label canonical.Risk, u canonical.BatchContainerUpdate) Approval {
	t.Helper()
	raw, in := e.containerPlan(t, "docker.compose_update", label, canonical.RiskMedium, &u)
	p, err := e.a.Propose(ctx, raw, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *environment) approve(t *testing.T, p Approval) {
	t.Helper()
	e.dev.Options.UserNotVerified = p.Requirement == permit.RequireAssertionPresence
	if _, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
		t.Fatal(err)
	}
}

func wantRefusal(t *testing.T, err, sentinel error) {
	t.Helper()
	var r *ContainerRefusal
	if !errors.Is(err, sentinel) || !errors.As(err, &r) || r.MemberID != "member-0" {
		t.Fatalf("got %v, want %v for member-0", err, sentinel)
	}
}

func TestContainerSameTagRefreshIsMedium(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := e.proposeContainer(t, canonical.RiskMedium, sameTagUpdate())
	if p.Risk != canonical.RiskMedium || p.Requirement != permit.RequireAssertionPresence {
		t.Fatalf("risk %s requirement %v", p.Risk, p.Requirement)
	}
	e.approve(t, p)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatal(err)
	}
}

func TestContainerTagChangeIsHighWithManualGates(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	e.withTagPolicy(t, defaultTagPolicy())
	p := e.proposeContainer(t, canonical.RiskHigh, tagChangeUpdate())
	if p.Risk != canonical.RiskHigh || p.Requirement != permit.RequireAssertionVerified {
		t.Fatalf("risk %s requirement %v", p.Risk, p.Requirement)
	}
	// A HIGH plan cannot continue automatically.
	e2 := setup(t, permit.ModeStandard)
	e2.withTagPolicy(t, defaultTagPolicy())
	u := tagChangeUpdate()
	raw, in := e2.containerPlan(t, "docker.compose_update", canonical.RiskHigh, canonical.RiskMedium, &u)
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.StagePlan.Stages[0].Gate = canonical.BatchGateAutomatic
	h, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash, b.Members[0].Request.StagePlanHash = h.String(), h.String()
	raw, _ = json.Marshal(b)
	_, err = e2.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeStagePlan)
}

func TestContainerTagChangeBelowHighRefused(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	e.withTagPolicy(t, defaultTagPolicy())
	u := tagChangeUpdate()
	for _, label := range []canonical.Risk{canonical.RiskLow, canonical.RiskMedium} {
		raw, in := e.containerPlan(t, "docker.compose_update", label, canonical.RiskMedium, &u)
		_, err := e.a.Propose(ctx, raw, in)
		wantRefusal(t, err, ErrContainerRiskBelowFloor)
	}
	// A same-tag refresh labelled LOW is below its MEDIUM floor too.
	s := sameTagUpdate()
	raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskLow, canonical.RiskLow, &s)
	_, err := e.a.Propose(ctx, raw, in)
	wantRefusal(t, err, ErrContainerRiskBelowFloor)
	if len(e.a.entries) != 0 || e.store.boundCount() != 0 {
		t.Fatal("refused plan retained or spent IDs")
	}
}

func TestContainerCriticalFloorRefusedNotDowngraded(t *testing.T) {
	t.Run("proposal, executor floor", func(t *testing.T) {
		e := setup(t, permit.ModeStandard)
		u := sameTagUpdate()
		raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskMedium, canonical.RiskCritical, &u)
		_, err := e.a.Propose(ctx, raw, in)
		wantRefusal(t, err, ErrContainerCritical)
		if errors.Is(err, ErrCritical) {
			t.Fatal("container CRITICAL reported as a separately approvable CRITICAL")
		}
		if len(e.a.entries) != 0 || e.store.boundCount() != 0 {
			t.Fatal("refused plan retained or spent IDs")
		}
	})
	t.Run("proposal, server label", func(t *testing.T) {
		e := setup(t, permit.ModeStandard)
		u := sameTagUpdate()
		raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskCritical, canonical.RiskMedium, &u)
		_, err := e.a.Propose(ctx, raw, in)
		wantRefusal(t, err, ErrContainerCritical)
	})
	t.Run("approval", func(t *testing.T) {
		e := setup(t, permit.ModeStandard)
		p := e.proposeContainer(t, canonical.RiskMedium, sameTagUpdate())
		e.policy.set("member-0", Snapshot{Risk: canonical.RiskCritical, Trust: sha256.Sum256([]byte("trust"))})
		e.dev.Options.UserNotVerified = true
		_, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge))
		wantRefusal(t, err, ErrContainerCritical)
		if !errors.Is(err, ErrInvalidated) {
			t.Fatalf("plan not invalidated: %v", err)
		}
		if _, err := e.a.Check(ctx, p.Digest); permit.CodeOf(err) != permit.CodeNotFound {
			t.Fatalf("plan survived: %v", err)
		}
	})
	t.Run("hardened CLI approval", func(t *testing.T) {
		e := setup(t, permit.ModeHardened)
		e.withTagPolicy(t, defaultTagPolicy())
		p := e.proposeContainer(t, canonical.RiskHigh, tagChangeUpdate())
		if p.Requirement != permit.RequireCLI {
			t.Fatalf("requirement %v", p.Requirement)
		}
		if _, err := e.a.ReviewCLI(ctx, p.Digest, 1000); err != nil {
			t.Fatal(err)
		}
		e.policy.set("member-0", Snapshot{Risk: canonical.RiskCritical, Trust: sha256.Sum256([]byte("trust"))})
		_, err := e.a.ApproveCLI(ctx, p.Digest, 1000)
		wantRefusal(t, err, ErrContainerCritical)
	})
	t.Run("claim", func(t *testing.T) {
		e := setup(t, permit.ModeStandard)
		p := e.proposeContainer(t, canonical.RiskMedium, sameTagUpdate())
		e.approve(t, p)
		e.policy.set("member-0", Snapshot{Risk: canonical.RiskCritical, Trust: sha256.Sum256([]byte("trust"))})
		_, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
		wantRefusal(t, err, ErrContainerCritical)
		if _, ok := e.a.Member(p.Digest, "member-0"); ok {
			t.Fatal("member claimed")
		}
	})
}

func TestContainerCriticalAfterApprovalStopsMember(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := e.proposeContainer(t, canonical.RiskMedium, sameTagUpdate())
	e.approve(t, p)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatal(err)
	}
	e.policy.set("member-0", Snapshot{Risk: canonical.RiskCritical, Trust: sha256.Sum256([]byte("trust"))})
	_, err := e.a.RevalidateMember(ctx, p.Digest, "member-0")
	wantRefusal(t, err, ErrContainerCritical)
	if _, ok := e.a.Member(p.Digest, "member-0"); ok {
		t.Fatal("claimed permit survived a CRITICAL floor")
	}
	// Lowering the floor again does not revive the plan.
	e.policy.set("member-0", Snapshot{Risk: canonical.RiskMedium, Trust: sha256.Sum256([]byte("trust"))})
	if _, err := e.a.RevalidateMember(ctx, p.Digest, "member-0"); err == nil {
		t.Fatal("revoked plan revived")
	}
}

func TestContainerPolicyMismatchRefused(t *testing.T) {
	cases := map[string]*tagPolicy{
		"other version": {version: "stable-v2", digest: testPolicyDigest},
		"other digest":  {version: testPolicyVersion, digest: hx("6")},
		"major differs": {version: testPolicyVersion, digest: testPolicyDigest, major: true},
		"not comparable": {version: testPolicyVersion, digest: testPolicyDigest,
			err: errors.New("tags not comparable")},
	}
	for name, tp := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			e.withTagPolicy(t, tp)
			u := tagChangeUpdate()
			raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskHigh, canonical.RiskMedium, &u)
			_, err := e.a.Propose(ctx, raw, in)
			wantRefusal(t, err, ErrContainerPolicy)
		})
	}
	t.Run("no executor policy", func(t *testing.T) {
		e := setup(t, permit.ModeStandard)
		u := tagChangeUpdate()
		raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskHigh, canonical.RiskMedium, &u)
		_, err := e.a.Propose(ctx, raw, in)
		wantRefusal(t, err, ErrContainerPolicy)
	})
	t.Run("same tag needs no comparison", func(t *testing.T) {
		e := setup(t, permit.ModeStandard)
		tp := defaultTagPolicy()
		e.withTagPolicy(t, tp)
		e.proposeContainer(t, canonical.RiskMedium, sameTagUpdate())
		if tp.calls != 0 {
			t.Fatal("same-tag refresh compared tags")
		}
	})
}

func TestImplicitMajorUpgradeRefused(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	e.withTagPolicy(t, &tagPolicy{version: testPolicyVersion, digest: testPolicyDigest, major: true})
	u := tagChangeUpdate()
	u.Images[0].NewTag = "2.0"
	raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskHigh, canonical.RiskMedium, &u)
	_, err := e.a.Propose(ctx, raw, in)
	wantRefusal(t, err, ErrContainerPolicy)
	// The explicit major selection is a HIGH proposal like any tag change.
	u.Images[0].MajorChange = true
	p := e.proposeContainer(t, canonical.RiskHigh, u)
	if p.Risk != canonical.RiskHigh {
		t.Fatalf("risk %s", p.Risk)
	}
}

func TestContainerVariantChangeRefused(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	e.withTagPolicy(t, &tagPolicy{err: errors.New("variant change")})
	u := tagChangeUpdate()
	u.Images[0].OldTag, u.Images[0].NewTag = "1.27-alpine", "1.28-bookworm"
	u.Targets[0].RunningReference = "nginx:1.27-alpine"
	raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskHigh, canonical.RiskMedium, &u)
	_, err := e.a.Propose(ctx, raw, in)
	wantRefusal(t, err, ErrContainerPolicy)
}

func TestContainerPolicyChangedAfterApproval(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	tp := defaultTagPolicy()
	e.withTagPolicy(t, tp)
	p := e.proposeContainer(t, canonical.RiskHigh, tagChangeUpdate())
	e.approve(t, p)
	tp.setDigest(hx("7"))
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
	wantRefusal(t, err, ErrContainerPolicy)
	if !errors.Is(err, ErrInvalidated) {
		t.Fatalf("plan not invalidated: %v", err)
	}
	tp.setDigest(testPolicyDigest)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err == nil {
		t.Fatal("revoked plan revived")
	}
}

func TestRestartMemberCannotCarryUpdateBinding(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	u := sameTagUpdate()
	for _, action := range []string{"docker.restart", "docker.stop", "docker.start"} {
		raw, in := e.containerPlan(t, action, canonical.RiskMedium, canonical.RiskMedium, &u)
		_, err := e.a.Propose(ctx, raw, in)
		wantCode(t, err, permit.CodeInvalidRequest)
	}
}

func TestContainerBindingDiffersFromParameters(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	u := sameTagUpdate()
	// Parameters of another binding, with their own matching hash: the
	// canonical plan refuses a hash that is not the binding's rendering.
	raw, in := e.containerPlan(t, "docker.compose_update", canonical.RiskMedium, canonical.RiskMedium, &u)
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	other := sameTagUpdate()
	other.Targets[0].ContainerID = hx("c")
	params, hash, err := canonical.ContainerUpdateParameters(other)
	if err != nil {
		t.Fatal(err)
	}
	b.Members[0].Request.ParametersHash = hash
	in[0].ParametersJSON = params
	raw, _ = json.Marshal(b)
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeInvalidRequest)
	// The plan's hash with substituted parameter bytes.
	raw, in = e.containerPlan(t, "docker.compose_update", canonical.RiskMedium, canonical.RiskMedium, &u)
	in[0].ParametersJSON = params
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeParametersMismatch)
}

func TestRollbackMemberWithoutBindingRefused(t *testing.T) {
	for _, action := range []string{"docker.rollback", "docker.compose_rollback"} {
		e := setup(t, permit.ModeStandard)
		raw, in := e.containerPlan(t, action, canonical.RiskHigh, canonical.RiskMedium, nil)
		_, err := e.a.Propose(ctx, raw, in)
		wantCode(t, err, permit.CodeInvalidRequest)
	}
}

func TestRollbackMemberWithKindUpdateRefused(t *testing.T) {
	for _, action := range []string{"docker.rollback", "docker.compose_rollback"} {
		e := setup(t, permit.ModeStandard)
		u := sameTagUpdate()
		if action == "docker.rollback" {
			u.Form = canonical.ContainerUpdateFormAlone
		}
		raw, in := e.containerPlan(t, action, canonical.RiskHigh, canonical.RiskMedium, &u)
		_, err := e.a.Propose(ctx, raw, in)
		wantCode(t, err, permit.CodeInvalidRequest)
	}
}

func TestContainerFormsWithoutExecutorChecksRefused(t *testing.T) {
	rollback := sameTagUpdate()
	rollback.Kind = canonical.ContainerUpdateKindRollback
	rollback.RollbackOf = "00000000-0000-4000-8000-000000000099"
	rollback.RecoveryPlanDigest = hx("6")
	img := &rollback.Images[0]
	img.NewIndexDigest, img.NewPlatformDigest, img.OldImageID = "", "", ""
	img.Rollback = &canonical.ContainerRollbackImage{PriorImageID: sd("4"), RetainedTag: "nos-retained-1", RetainedReference: "nginx:nos-retained-1"}

	standalone := sameTagUpdate()
	standalone.Form = canonical.ContainerUpdateFormAlone
	standalone.SourceDigest, standalone.Project, standalone.WorkingDirHash, standalone.ConfigFilesHash = "", "", "", ""
	standalone.Images[0].Service, standalone.Targets[0].Service = "", ""
	standalone.DefinitionID, standalone.DefinitionVersion = "00000000-0000-4000-8000-000000000098", 1

	private := sameTagUpdate()
	private.Registry = &canonical.ContainerUpdateRegistry{RegistryID: "ghcr", RecordDigest: hx("1"), CredentialID: "ghcr-ci", CredentialVersion: 1}

	cases := map[string]struct {
		action string
		u      canonical.BatchContainerUpdate
	}{
		"compose rollback (cu03)":  {"docker.compose_rollback", rollback},
		"standalone update (cu05)": {"docker.update", standalone},
		"private registry (cu06)":  {"docker.compose_update", private},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			raw, in := e.containerPlan(t, c.action, canonical.RiskMedium, canonical.RiskMedium, &c.u)
			_, err := e.a.Propose(ctx, raw, in)
			if !errors.Is(err, ErrContainerUnsupported) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// A claim must present exactly the approved binding: any substituted
// container, configuration, digest or tag is refused and claims nothing.
func TestContainerSubstitutionAndTagDriftAtClaimRejected(t *testing.T) {
	cases := map[string]func(*canonical.BatchContainerUpdate){
		"container id":        func(u *canonical.BatchContainerUpdate) { u.Targets[0].ContainerID = hx("c") },
		"container name":      func(u *canonical.BatchContainerUpdate) { u.Targets[0].ContainerName = "shop-app-9" },
		"configuration":       func(u *canonical.BatchContainerUpdate) { u.Targets[0].ConfigurationDigest = hx("c") },
		"new platform digest": func(u *canonical.BatchContainerUpdate) { u.Images[0].NewPlatformDigest = sd("c") },
		"new index digest":    func(u *canonical.BatchContainerUpdate) { u.Images[0].NewIndexDigest = sd("c") },
		"new tag drift":       func(u *canonical.BatchContainerUpdate) { u.Images[0].NewTag = "1.29" },
		"old digests":         func(u *canonical.BatchContainerUpdate) { u.Images[0].OldDigests = []string{sd("0")} },
		"source digest":       func(u *canonical.BatchContainerUpdate) { u.SourceDigest = hx("c") },
		"added dependency": func(u *canonical.BatchContainerUpdate) {
			u.Dependencies = []canonical.ContainerUpdateDependency{{Service: "db", Relation: canonical.ContainerDependencyRequires,
				Containers: []canonical.ContainerDependencyMember{{ContainerID: hx("d"), ContainerName: "shop-db-1", ConfigurationDigest: hx("e")}}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := setup(t, permit.ModeStandard)
			e.withTagPolicy(t, defaultTagPolicy())
			p := e.proposeContainer(t, canonical.RiskHigh, tagChangeUpdate())
			e.approve(t, p)
			candidate := cloneMember(p.Plan.Members[0])
			mutate(candidate.ContainerUpdate)
			// Even with parameters rendered from the substituted binding.
			if _, hash, err := canonical.ContainerUpdateParameters(*candidate.ContainerUpdate); err == nil {
				candidate.Request.ParametersHash = hash
			}
			_, err := e.a.ClaimMember(ctx, p.Digest, 0, candidate)
			wantCode(t, err, permit.CodeInvalidRequest)
			if _, ok := e.a.Member(p.Digest, "member-0"); ok {
				t.Fatal("substituted member claimed")
			}
			if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
				t.Fatalf("approved member no longer claimable: %v", err)
			}
		})
	}
}

func TestReturnedContainerBindingCannotMutateFrozenPlan(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := e.proposeContainer(t, canonical.RiskMedium, sameTagUpdate())
	e.approve(t, p)
	p.Plan.Members[0].ContainerUpdate.Targets[0].ContainerID = hx("c")
	p.Plan.Members[0].ContainerUpdate.Images[0].OldDigests[0] = sd("0")
	again, err := e.a.Check(ctx, p.Digest)
	if err != nil {
		t.Fatal(err)
	}
	u := again.Plan.Members[0].ContainerUpdate
	if u.Targets[0].ContainerID != hx("a") || u.Images[0].OldDigests[0] != sd("1") {
		t.Fatal("caller mutated the frozen binding")
	}
}
