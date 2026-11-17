// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeIndex is a SuggestionIndex with fixed answers.
type fakeIndex struct {
	steps    map[string][3]string // ref -> action, family, host
	families map[string]string    // action ID -> family
	notes    map[string]string    // family + "|" + host -> note ID
}

func (x fakeIndex) Step(ref string) (string, string, string, bool) {
	v, ok := x.steps[ref]
	return v[0], v[1], v[2], ok
}

func (x fakeIndex) Match(family, host string) (string, bool) {
	n, ok := x.notes[family+"|"+host]
	return n, ok
}

func (x fakeIndex) Family(action string) (string, bool) {
	f, ok := x.families[action]
	return f, ok
}

// suggestionIndex knows one fix step (core.facts on web, family "facts"),
// one note covering package.refresh on web (family "packages") and the
// HIGH reboot on web (family "reboot").
func suggestionIndex() fakeIndex {
	return fakeIndex{
		steps: map[string][3]string{
			"note1.1": {"core.facts", "facts", "web"},
			"note2.1": {"system.reboot", "reboot", "web"},
		},
		families: map[string]string{"core.facts": "facts", "package.refresh": "packages", "system.reboot": "reboot"},
		notes:    map[string]string{"packages|web": "note9"},
	}
}

// proposeOnce creates one execution and returns the request the executor
// received, the response and the stored origin.
func proposeOnce(t *testing.T, s *Service, db *sql.DB, f *fakeExec, action string, plan Plan) (Created, *pb.ExecutionRequest, string) {
	t.Helper()
	c, err := s.CreateStaged(context.Background(), "axel", action, []string{"web"}, nil, plan)
	if err != nil {
		t.Fatalf("CreateStaged(%s, %+v): %v", action, plan, err)
	}
	var origin string
	if err := db.QueryRow(`SELECT origin FROM executions WHERE id = ?`, c.ID).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	return c, f.proposed.GetRequest(), origin
}

func TestSuggestionReferenceRaisesLowActionToMedium(t *testing.T) {
	f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_MEDIUM, requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE}
	s, db := setup(t, f)
	s.SetSuggestionIndex(suggestionIndex())
	c, req, origin := proposeOnce(t, s, db, f, "core.facts", Plan{SuggestionRef: "note1.1"})
	if req.GetRiskClass() != pb.RiskClass_RISK_CLASS_MEDIUM {
		t.Fatalf("proposed class %v, want MEDIUM", req.GetRiskClass())
	}
	if c.Risk != "MEDIUM" || c.Requirement != "assertion_presence" || c.Origin != "suggestion:note1.1" || origin != "suggestion:note1.1" {
		t.Fatalf("created %+v, stored origin %q", c, origin)
	}
}

func TestSuggestionMatchRaisesLowActionWithoutReference(t *testing.T) {
	f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_MEDIUM, requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_PRESENCE}
	s, db := setup(t, f)
	s.SetSuggestionIndex(suggestionIndex())
	c, req, origin := proposeOnce(t, s, db, f, "package.refresh", Plan{})
	if req.GetRiskClass() != pb.RiskClass_RISK_CLASS_MEDIUM || c.Requirement != "assertion_presence" {
		t.Fatalf("proposed class %v, created %+v", req.GetRiskClass(), c)
	}
	if origin != "suggestion-match:note9" || c.Origin != "suggestion-match:note9" {
		t.Fatalf("origin %q, created %+v", origin, c)
	}
}

func TestLowActionWithoutSuggestionStaysLow(t *testing.T) {
	cases := []struct {
		name string
		idx  SuggestionIndex
	}{
		{"nil index", nil},
		{"index without a matching note", suggestionIndex()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_LOW}
			s, db := setup(t, f)
			s.SetSuggestionIndex(tc.idx)
			action := "core.facts"
			if tc.idx != nil {
				action = "service.list" // family without a note on web
			}
			c, req, origin := proposeOnce(t, s, db, f, action, Plan{})
			if req.GetRiskClass() != pb.RiskClass_RISK_CLASS_LOW || c.Risk != "LOW" || origin != "" || c.Origin != "" {
				t.Fatalf("proposed class %v, origin %q, created %+v", req.GetRiskClass(), origin, c)
			}
		})
	}
}

func TestUnknownSuggestionReferenceIsRefusedWithoutExecutorCall(t *testing.T) {
	cases := []struct {
		name string
		ref  string
		idx  SuggestionIndex
	}{
		{"unknown reference", "nope9.1", suggestionIndex()},
		{"malformed reference", "note1 1", suggestionIndex()},
		{"reference without step", "note1", suggestionIndex()},
		{"empty note ID", ".1", suggestionIndex()},
		{"overlong reference", strings.Repeat("a", MaxSuggestionRefLen) + ".1", suggestionIndex()},
		{"reference with no index", "note1.1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeExec{}
			s, _ := setup(t, f)
			s.SetSuggestionIndex(tc.idx)
			_, err := s.CreateStaged(context.Background(), "axel", "core.facts", []string{"web"}, nil, Plan{SuggestionRef: tc.ref})
			if !errors.Is(err, ErrUnknownSuggestion) {
				t.Fatalf("err = %v, want ErrUnknownSuggestion", err)
			}
			if f.proposed != nil {
				t.Fatalf("executor was called for a refused reference: %v", f.proposed)
			}
		})
	}
}

func TestSuggestionKeepsHighRiskUnchanged(t *testing.T) {
	f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_HIGH}
	s, db := setup(t, f)
	s.SetSuggestionIndex(suggestionIndex())
	_, req, origin := proposeOnce(t, s, db, f, "system.reboot", Plan{SuggestionRef: "note2.1"})
	if req.GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH {
		t.Fatalf("proposed class %v, want HIGH", req.GetRiskClass())
	}
	if origin != "suggestion:note2.1" {
		t.Fatalf("origin %q", origin)
	}
}

func TestSuggestionReferenceMarksWhenHumanChangedAction(t *testing.T) {
	// The reference names core.facts on web; the form submits package.refresh
	// (LOW) on web. The valid reference still marks the execution.
	f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_MEDIUM}
	s, db := setup(t, f)
	s.SetSuggestionIndex(suggestionIndex())
	_, req, origin := proposeOnce(t, s, db, f, "package.refresh", Plan{SuggestionRef: "note1.1"})
	if req.GetRiskClass() != pb.RiskClass_RISK_CLASS_MEDIUM || origin != "suggestion:note1.1" {
		t.Fatalf("class %v, origin %q", req.GetRiskClass(), origin)
	}
}

func TestSuggestionMatchNeedsTheSameFamily(t *testing.T) {
	f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_LOW}
	s, db := setup(t, f)
	s.SetSuggestionIndex(suggestionIndex())
	// The note covers family "packages" on web; core.facts is family
	// "facts" and has no note, so the match does not apply.
	c, err := s.CreateStaged(context.Background(), "axel", "core.facts", []string{"web"}, nil, Plan{})
	if err != nil {
		t.Fatal(err)
	}
	if f.proposed.GetRequest().GetRiskClass() != pb.RiskClass_RISK_CLASS_LOW || c.Origin != "" {
		t.Fatalf("class %v, created %+v", f.proposed.GetRequest().GetRiskClass(), c)
	}
	var origin string
	if err := db.QueryRow(`SELECT origin FROM executions WHERE id = ?`, c.ID).Scan(&origin); err != nil || origin != "" {
		t.Fatalf("stored origin %q, %v", origin, err)
	}
}

func TestOriginIsStoredAndAudited(t *testing.T) {
	f := &fakeExec{risk: pb.RiskClass_RISK_CLASS_MEDIUM}
	s, _ := setup(t, f)
	s.SetSuggestionIndex(suggestionIndex())
	var logs bytes.Buffer
	s.log = slog.New(slog.NewJSONHandler(&logs, nil))
	if _, err := s.CreateStaged(context.Background(), "axel", "core.facts", []string{"web"}, nil, Plan{SuggestionRef: "note1.1"}); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	for _, want := range []string{`"kind":"execution_proposed"`, `"origin":"suggestion:note1.1"`, `"declared_risk":"LOW"`, `"risk":"MEDIUM"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit line lacks %s: %s", want, out)
		}
	}
}

// batchSuggestionRequest is a one-member batch: package.refresh (LOW) on host.
func batchSuggestionRequest(host string) BatchRequest {
	return BatchRequest{Stages: []BatchStageSpec{{Gate: canonical.BatchGateManual,
		Members: []BatchMemberSpec{{ActionID: "package.refresh", HostID: host}}}}}
}

func TestBatchMemberWithSuggestionMatchIsProposedAsMedium(t *testing.T) {
	f := &fakeBatchExec{}
	idx := fakeIndex{
		families: map[string]string{"package.refresh": "packages"},
		notes:    map[string]string{"packages|h01": "note9"},
	}
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Suggestions = idx })
	c, err := b.ProposeBatch(context.Background(), "axel", batchSuggestionRequest("h01"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Risk != "MEDIUM" || c.Requirement != "assertion_presence" {
		t.Fatalf("batch %+v, want MEDIUM presence", c)
	}
	plan, _, _, err := canonical.ParseBatch(f.proposed[0].GetBatchJson(), batchNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Members[0].Request.RiskClass; got != canonical.RiskMedium {
		t.Fatalf("proposed member class %s, want MEDIUM", got)
	}
}

func TestBatchMemberWithoutSuggestionStaysLow(t *testing.T) {
	f := &fakeBatchExec{}
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Suggestions = fakeIndex{families: map[string]string{}} })
	if _, err := b.ProposeBatch(context.Background(), "axel", batchSuggestionRequest("h02")); err != nil {
		t.Fatal(err)
	}
	plan, _, _, err := canonical.ParseBatch(f.proposed[0].GetBatchJson(), batchNow)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Members[0].Request.RiskClass; got != canonical.RiskLow {
		t.Fatalf("proposed member class %s, want LOW", got)
	}
}

func TestBatchExecutorAnswerBelowRaisedMemberIsRefused(t *testing.T) {
	f := &fakeBatchExec{tamper: func(p *canonical.Batch) {
		for i := range p.Members {
			if p.Members[i].Request.ResolvedTargets[0].HostID == "h01" {
				p.Members[i].Request.RiskClass = canonical.RiskLow
			}
		}
	}}
	idx := fakeIndex{families: map[string]string{"package.refresh": "packages"}, notes: map[string]string{"packages|h01": "note9"}}
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Suggestions = idx })
	_, err := b.ProposeBatch(context.Background(), "axel", batchSuggestionRequest("h01"))
	if !errors.Is(err, ErrBatchAnswer) {
		t.Fatalf("err = %v, want ErrBatchAnswer", err)
	}
}
