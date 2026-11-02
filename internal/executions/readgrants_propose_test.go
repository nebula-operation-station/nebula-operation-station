// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	testHostFP = "SHA256:" + "hosthosthosthosthosthosthosthosthosthosthos"
	testCredFP = "SHA256:" + "credcredcredcredcredcredcredcredcredcredcre"
)

// proposeFake is a read-grant executor that echoes the proposed document
// back as the canonical grant (optionally altered) and records commits.
type proposeFake struct {
	*readGrantFake
	requirement pb.ApprovalRequirement
	proposeErr  error
	keyErr      error
	keyFP       string
	keyCalls    []string
	sent        permit.ReadGrantDoc
	alter       func(*permit.ReadGrantDoc)
	commitErr   error
	committed   *pb.CommitReadGrantRequest
}

func (f *proposeFake) ProposeReadGrant(_ context.Context, in *pb.ProposeReadGrantRequest, _ ...grpc.CallOption) (*pb.ProposeReadGrantResponse, error) {
	if f.proposeErr != nil {
		return nil, f.proposeErr
	}
	if err := json.Unmarshal(in.GetGrantJson(), &f.sent); err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad")
	}
	back := f.sent
	if f.alter != nil {
		f.alter(&back)
	}
	raw, _ := json.Marshal(back)
	r := &pb.ProposeReadGrantResponse{GrantDigest: testDigest, CanonicalGrant: raw, ApprovalRequirement: f.requirement}
	if f.requirement != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY {
		r.RequestOptionsJson = []byte(`{"publicKey":{"challenge":"abc"}}`)
		r.ChallengeExpiryUnix = time.Now().Add(5 * time.Minute).Unix()
	}
	return r, nil
}

func (f *proposeFake) CommitReadGrant(_ context.Context, in *pb.CommitReadGrantRequest, _ ...grpc.CallOption) (*pb.CommitReadGrantResponse, error) {
	f.committed = in
	if f.commitErr != nil {
		return nil, f.commitErr
	}
	return &pb.CommitReadGrantResponse{}, nil
}

func (f *proposeFake) GetSSHPublicKey(_ context.Context, in *pb.GetSSHPublicKeyRequest, _ ...grpc.CallOption) (*pb.GetSSHPublicKeyResponse, error) {
	f.keyCalls = append(f.keyCalls, in.GetCredentialRef())
	if f.keyErr != nil {
		return nil, f.keyErr
	}
	return &pb.GetSSHPublicKeyResponse{Fingerprint: f.keyFP}, nil
}

// newProposeFake pins web, db and dev (testInventory) except blocked ones.
func newProposeFake(blocked ...string) *proposeFake {
	fe := &fakeExec{}
	for _, h := range []string{"web", "db", "dev"} {
		p := &pb.HostKeyPin{HostId: h, Fingerprint: testHostFP, CredentialRef: "default"}
		for _, b := range blocked {
			if b == h {
				p.Blocked = true
			}
		}
		fe.pins = append(fe.pins, p)
	}
	return &proposeFake{readGrantFake: &readGrantFake{fakeExec: fe}, keyFP: testCredFP,
		requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED}
}

func proposeService(t *testing.T, f Executor, inv []inventory.Host) (*Service, *bytes.Buffer) {
	t.Helper()
	s := newReadGrantService(t, f, readGrantHostsFrom(inv))
	var audit bytes.Buffer
	s.log = slog.New(slog.NewTextHandler(&audit, nil))
	return s, &audit
}

func previewHosts(v ReadGrantPreview) []string {
	var out []string
	for _, t := range v.Targets {
		out = append(out, t.HostID)
	}
	return out
}

func TestProposeReadGrantFreezesScope(t *testing.T) {
	for _, tc := range []struct {
		name, kind, value string
		want              []string
	}{
		{"all", ScopeAll, "", []string{"db", "dev", "web"}},
		{"tag", ScopeTag, "tier=front", []string{"dev", "web"}},
		{"environment", ScopeEnvironment, "prod", []string{"db", "web"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProposeFake()
			s, audit := proposeService(t, f, testInventory())
			now := time.Unix(1_800_000_000, 0)
			s.now = func() time.Time { return now }
			v, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: tc.kind, ScopeValue: tc.value,
				Actions: []string{"core.facts", "package.list_updates"}, Days: ReadGrantShortDays})
			if err != nil {
				t.Fatal(err)
			}
			if got := previewHosts(v); !sameStrings(got, tc.want) {
				t.Errorf("hosts %v, want %v", got, tc.want)
			}
			if v.Digest != testDigest || v.CLI || len(v.Options) == 0 {
				t.Errorf("digest %q cli %v options %q", v.Digest, v.CLI, v.Options)
			}
			if !v.Expiry.Equal(now.Add(7*24*time.Hour)) || !v.Created.Equal(now) {
				t.Errorf("created %v expiry %v", v.Created, v.Expiry)
			}
			for _, tg := range v.Targets {
				if tg.HostKeyFingerprint != testHostFP || tg.CredentialRef != "default" || tg.CredentialVersion != testCredFP {
					t.Errorf("target %+v lacks its key bindings", tg)
				}
			}
			if len(v.Actions) != 2 || v.Actions[0].ArtifactSHA256 == "" || v.Actions[0].ParametersHash == "" {
				t.Errorf("actions %+v", v.Actions)
			}
			// The sent document is the strict read-grant-v2 form.
			d := f.sent
			if d.Grant != permit.ReadGrantFormat || d.RateProfile != "ordinary" || d.Trigger != permit.TriggerBoth ||
				d.MinIntervalS != 900 || d.RunBudget != permit.DefaultRunBudget || len(d.Credentials) != len(d.Targets) {
				t.Errorf("sent document %+v", d)
			}
			if _, _, _, err := permit.ParseReadGrant(marshalDoc(t, d), now); err != nil {
				t.Errorf("the sent document does not parse as a read grant: %v", err)
			}
			if len(f.keyCalls) != 1 {
				t.Errorf("credential versions read %d times, want once per reference", len(f.keyCalls))
			}
			if !strings.Contains(audit.String(), "read_grant_proposed") {
				t.Errorf("proposal not audited: %s", audit.String())
			}
		})
	}
}

func TestProposeReadGrantExcludesUnusableHosts(t *testing.T) {
	f := newProposeFake("db")
	inv := append(testInventory(), inventory.Host{ID: "new", Environment: "prod"})
	s, _ := proposeService(t, f, inv)
	v, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeEnvironment, ScopeValue: "prod",
		Actions: []string{"core.facts"}, Days: ReadGrantLongDays})
	if err != nil {
		t.Fatal(err)
	}
	if got := previewHosts(v); !sameStrings(got, []string{"web"}) {
		t.Errorf("frozen hosts %v, want [web]", got)
	}
	if len(v.Excluded) != 2 {
		t.Errorf("excluded %+v, want db (blocked) and new (not enrolled)", v.Excluded)
	}
}

func TestProposeReadGrantHardenedNeedsCLI(t *testing.T) {
	f := newProposeFake()
	f.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	s, _ := proposeService(t, f, testInventory())
	v, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !v.CLI || len(v.Options) != 0 {
		t.Errorf("cli %v options %q", v.CLI, v.Options)
	}
}

func TestProposeReadGrantRejectsInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   ReadGrantRequest
	}{
		{"unknown kind", ReadGrantRequest{ScopeKind: "hosts", Actions: []string{"core.facts"}, Days: 7}},
		{"all with value", ReadGrantRequest{ScopeKind: ScopeAll, ScopeValue: "x", Actions: []string{"core.facts"}, Days: 7}},
		{"tag without =", ReadGrantRequest{ScopeKind: ScopeTag, ScopeValue: "tier", Actions: []string{"core.facts"}, Days: 7}},
		{"tag control char", ReadGrantRequest{ScopeKind: ScopeTag, ScopeValue: "tier=fr\x00ont", Actions: []string{"core.facts"}, Days: 7}},
		{"long environment", ReadGrantRequest{ScopeKind: ScopeEnvironment, ScopeValue: strings.Repeat("p", maxScopeValueLen+1), Actions: []string{"core.facts"}, Days: 7}},
		{"days", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 31}},
		{"no action", ReadGrantRequest{ScopeKind: ScopeAll, Days: 7}},
		{"write action", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"package.refresh"}, Days: 7}},
		{"parameterized action", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"service.status"}, Days: 7}},
		{"telemetry action", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"host.metrics"}, Days: 7}},
		{"duplicate action", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts", "core.facts"}, Days: 7}},
		{"no matching host", ReadGrantRequest{ScopeKind: ScopeEnvironment, ScopeValue: "staging", Actions: []string{"core.facts"}, Days: 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProposeFake()
			s, _ := proposeService(t, f, testInventory())
			_, err := s.ProposeReadGrant(context.Background(), "alice", tc.in)
			var ie *ReadGrantInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err %v, want an input error", err)
			}
			if f.sent.ID != "" {
				t.Error("an invalid request reached the executor")
			}
		})
	}
}

func TestProposeReadGrantAllBlockedIsRefused(t *testing.T) {
	f := newProposeFake("web", "db", "dev")
	s, _ := proposeService(t, f, testInventory())
	_, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 7})
	var ie *ReadGrantInputError
	if !errors.As(err, &ie) {
		t.Fatalf("err %v, want an input error", err)
	}
}

func TestProposeReadGrantExecutorErrorsAreFixed(t *testing.T) {
	secret := "executor detail <script>"
	f := newProposeFake()
	f.proposeErr = status.Error(codes.InvalidArgument, secret)
	s, _ := proposeService(t, f, testInventory())
	_, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 7})
	if !errors.Is(err, ErrReadGrantProposeFailed) || strings.Contains(err.Error(), secret) {
		t.Fatalf("err %v", err)
	}

	f = newProposeFake()
	f.keyErr = status.Error(codes.PermissionDenied, secret)
	s, _ = proposeService(t, f, testInventory())
	_, err = s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 7})
	if !errors.Is(err, ErrReadGrantCredentials) {
		t.Fatalf("err %v, want ErrReadGrantCredentials", err)
	}
	if f.sent.ID != "" {
		t.Error("a document without credential versions was proposed")
	}

	f = newProposeFake()
	f.keyFP = "not a fingerprint"
	s, _ = proposeService(t, f, testInventory())
	if _, err = s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 7}); !errors.Is(err, ErrReadGrantCredentials) {
		t.Fatalf("err %v, want ErrReadGrantCredentials", err)
	}
}

func TestProposeReadGrantRejectsDifferentCanonicalScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*permit.ReadGrantDoc)
	}{
		{"extra host", func(d *permit.ReadGrantDoc) {
			d.Targets = append(d.Targets, d.Targets[0])
			d.Targets[len(d.Targets)-1].HostID = "extra"
		}},
		{"dropped host", func(d *permit.ReadGrantDoc) { d.Targets = d.Targets[1:] }},
		{"other key", func(d *permit.ReadGrantDoc) { d.Targets[0].HostKeyFingerprint = testCredFP }},
		{"other credential", func(d *permit.ReadGrantDoc) { d.Credentials[0].CredentialRef = "other" }},
		{"other action", func(d *permit.ReadGrantDoc) { d.Actions[0].ActionID = "docker.list" }},
		{"longer expiry", func(d *permit.ReadGrantDoc) { d.ExpiryUnix += 3600 }},
		{"other budget", func(d *permit.ReadGrantDoc) { d.RunBudget = 240 }},
		{"other id", func(d *permit.ReadGrantDoc) { d.ID = testGrantID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProposeFake()
			f.alter = tc.alter
			s, _ := proposeService(t, f, testInventory())
			_, err := s.ProposeReadGrant(context.Background(), "alice", ReadGrantRequest{ScopeKind: ScopeAll, Actions: []string{"core.facts"}, Days: 7})
			if !errors.Is(err, ErrReadGrantProposalMismatch) {
				t.Fatalf("err %v, want ErrReadGrantProposalMismatch", err)
			}
		})
	}
}

func TestPreviewFromResponseRejectsMalformedAnswers(t *testing.T) {
	doc := grantDocValue(permit.ReadGrantFormat, []string{"web"}, time.Unix(100, 0), time.Unix(100+3600, 0))
	raw := marshalDoc(t, doc)
	ok := &pb.ProposeReadGrantResponse{GrantDigest: testDigest, CanonicalGrant: raw,
		ApprovalRequirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED, RequestOptionsJson: []byte(`{}`)}
	if _, err := previewFromResponse(ok, doc); err != nil {
		t.Fatalf("valid answer rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		mod  func(r *pb.ProposeReadGrantResponse)
	}{
		{"bad digest", func(r *pb.ProposeReadGrantResponse) { r.GrantDigest = "ABC" }},
		{"empty document", func(r *pb.ProposeReadGrantResponse) { r.CanonicalGrant = nil }},
		{"duplicate member", func(r *pb.ProposeReadGrantResponse) {
			r.CanonicalGrant = append([]byte(`{"id":"x",`), raw[1:]...)
		}},
		{"unknown member", func(r *pb.ProposeReadGrantResponse) {
			r.CanonicalGrant = append([]byte(`{"extra":1,`), raw[1:]...)
		}},
		{"trailing data", func(r *pb.ProposeReadGrantResponse) {
			r.CanonicalGrant = append(append([]byte{}, raw...), []byte(`{}`)...)
		}},
		{"invalid utf8", func(r *pb.ProposeReadGrantResponse) {
			r.CanonicalGrant = append(append([]byte{}, raw[:len(raw)-1]...), 0xff, '}')
		}},
		{"no approval", func(r *pb.ProposeReadGrantResponse) {
			r.ApprovalRequirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_NONE
		}},
		{"browser without options", func(r *pb.ProposeReadGrantResponse) { r.RequestOptionsJson = nil }},
		{"options not json", func(r *pb.ProposeReadGrantResponse) { r.RequestOptionsJson = []byte(`{"a":`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &pb.ProposeReadGrantResponse{GrantDigest: ok.GrantDigest, CanonicalGrant: ok.CanonicalGrant,
				ApprovalRequirement: ok.ApprovalRequirement, RequestOptionsJson: ok.RequestOptionsJson}
			tc.mod(r)
			if _, err := previewFromResponse(r, doc); !errors.Is(err, ErrReadGrantProposalMismatch) {
				t.Fatalf("err %v, want ErrReadGrantProposalMismatch", err)
			}
		})
	}
}

func TestCommitReadGrant(t *testing.T) {
	f := newProposeFake()
	s, audit := proposeService(t, f, testInventory())
	if err := s.CommitReadGrant(context.Background(), "alice", testDigest, []byte(`{"id":"x"}`)); err != nil {
		t.Fatal(err)
	}
	if f.committed.GetGrantDigest() != testDigest || string(f.committed.GetAssertionJson()) != `{"id":"x"}` {
		t.Errorf("committed %+v", f.committed)
	}
	if !strings.Contains(audit.String(), "read_grant_approved") {
		t.Errorf("approval not audited: %s", audit.String())
	}
}

func TestCommitReadGrantRejections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		digest    string
		assertion []byte
		execErr   error
		want      error
	}{
		{"bad digest", "zz", []byte(`{}`), nil, ErrReadGrantProposalNotFound},
		{"unknown digest", testDigest, []byte(`{}`), status.Error(codes.NotFound, "x"), ErrReadGrantProposalNotFound},
		{"refused", testDigest, []byte(`{}`), status.Error(codes.PermissionDenied, "x"), ErrReadGrantApprovalRefused},
		{"unavailable", testDigest, []byte(`{}`), status.Error(codes.Unavailable, "x"), ErrReadGrantCommitFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProposeFake()
			f.commitErr = tc.execErr
			s, audit := proposeService(t, f, testInventory())
			if err := s.CommitReadGrant(context.Background(), "alice", tc.digest, tc.assertion); !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if strings.Contains(audit.String(), "read_grant_approved") {
				t.Error("a refused approval was audited as approved")
			}
		})
	}
	for _, a := range [][]byte{nil, []byte(`{`), []byte("\xff"), bytes.Repeat([]byte(" "), maxReadGrantAssertionSize+1)} {
		f := newProposeFake()
		s, _ := proposeService(t, f, testInventory())
		var ie *ReadGrantInputError
		if err := s.CommitReadGrant(context.Background(), "alice", testDigest, a); !errors.As(err, &ie) {
			t.Errorf("assertion %q: err %v, want an input error", a, err)
		}
		if f.committed != nil {
			t.Error("a malformed assertion reached the executor")
		}
	}
}

func TestReadGrantActionIDs(t *testing.T) {
	ids := ReadGrantActionIDs()
	if len(ids) == 0 {
		t.Fatal("no leaseable actions")
	}
	for _, id := range ids {
		if !permit.InReadOnlyAllowlist(id) || id == "package.refresh" || id == "docker.logs" {
			t.Errorf("%s is offered for a read lease", id)
		}
	}
}
