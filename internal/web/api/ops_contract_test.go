// SPDX-License-Identifier: AGPL-3.0-or-later

package api_test

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsagent/prompt"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/opsfacts"
)

// TestOpsWorkQuestionAndSummaryDecodeInNosclient runs the real work list of
// the server through the real agent decoder (nosclient.Client.Work, strict
// decoding). A question item and the summary item share one list; a decode
// failure here means the agent answers nothing (work_unavailable).
func TestOpsWorkQuestionAndSummaryDecodeInNosclient(t *testing.T) {
	const text = "Ist " + opsHost + " betroffen?"
	tests := []struct {
		name  string
		class string
		lab   bool
	}{
		{"class lab", opsconfig.DataClassLab, true},
		{"class external", opsconfig.DataClassExternal, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpsEnv(t)
			e.settings.row.Settings.DataClass = tc.class
			e.facts.groups = []opsfacts.Group{labGroup(opsHost, "CVE-2026-0001", opsfacts.TierCritical, false, 90)}
			e.facts.fleet = opsfacts.ExternalProjection{Fleet: opsfacts.Counts{Critical: 1, KEV: 1}}
			askOpsQuestion(t, e, text)

			srv := httptest.NewServer(e.h)
			t.Cleanup(srv.Close)
			c := newAgentClient(t, srv.URL)
			items, err := c.Work(t.Context())
			if err != nil {
				t.Fatalf("agent decodes the work list: %v", err)
			}
			// Questions come first, then the summary; class lab adds fix items.
			if len(items) < 2 || items[0].Kind != "question" || items[1].Kind != "summary" {
				t.Fatalf("items = %+v, want question then summary", items)
			}
			q := items[0]
			if q.Question == nil || q.Question.Text != text || q.Fleet == nil || q.Ref == "" || q.Digest == "" {
				t.Fatalf("question item = %+v", q)
			}
			if tc.lab {
				if len(q.Question.Hosts) != 1 || q.Question.Hosts[0].Host.ID != opsHost {
					t.Errorf("question hosts = %+v, want the named host", q.Question.Hosts)
				}
			} else if len(q.Question.Hosts) != 0 {
				t.Errorf("class external carries host facts: %+v", q.Question.Hosts)
			}
			if s := items[1]; s.Fleet == nil || s.Question != nil || s.Group != nil {
				t.Errorf("summary item = %+v", s)
			}
		})
	}
}

// ctrSources are the inputs of a real opsfacts.Projector in the contract test:
// one host with one open OS finding whose fix is verified.
type ctrSources struct{}

func (ctrSources) Hosts(context.Context) ([]opsfacts.Host, error) {
	return []opsfacts.Host{{ID: opsHost, Label: "Web 01", Environment: "lab",
		Criticality: opsfacts.CriticalityHigh, Exposure: opsfacts.ExposureInternet}}, nil
}

func (ctrSources) Listeners(context.Context, string) ([]opsfacts.Port, error) { return nil, nil }

func (ctrSources) Findings(context.Context) ([]opsfacts.Finding, error) {
	return []opsfacts.Finding{{Subject: opsfacts.SubjectOS, HostID: opsHost, VulnID: "CVE-2026-0001",
		Package: "openssl", Installed: "3.0.1-1", Fixed: "3.0.2-1", Tier: opsfacts.TierCritical, Score: 90,
		State: opsfacts.StateOpen, Fix: opsfacts.FixDecision{Outcome: opsfacts.OutcomeVerified,
			Link: opsfacts.LinkInstallSecurity}}}, nil
}

func (ctrSources) HasAction(string) bool { return true }

func (ctrSources) Skipped(context.Context, opsfacts.Skip) error { return nil }

// TestOpsFixCandidatesCarryLabelsThroughNosclient runs the candidates of a
// real opsfacts projection (not a hand-built group) through the server's work
// list and the agent's decoder: every candidate of every fix item has a
// non-empty label that fits the prompt bound (ADR 0016 D4).
func TestOpsFixCandidatesCarryLabelsThroughNosclient(t *testing.T) {
	p, err := opsfacts.New(opsfacts.Sources{Inventory: ctrSources{}, Listeners: ctrSources{},
		Findings: ctrSources{}, Catalog: ctrSources{}, Audit: ctrSources{}})
	if err != nil {
		t.Fatalf("opsfacts.New: %v", err)
	}
	groups, err := p.EligibleGroups(t.Context())
	if err != nil {
		t.Fatalf("EligibleGroups: %v", err)
	}
	e := newOpsEnv(t)
	e.facts.groups = groups
	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close)
	items, err := newAgentClient(t, srv.URL).Work(t.Context())
	if err != nil {
		t.Fatalf("agent decodes the work list: %v", err)
	}
	candidates := 0
	for _, it := range items {
		if it.Kind != "fix" {
			continue
		}
		for _, c := range it.Group.Candidates {
			candidates++
			if c.Label == "" || len(c.Label) > prompt.MaxCandidateLabelBytes {
				t.Errorf("candidate %s of %s: label %q, want 1..%d bytes", c.Key, it.Ref, c.Label, prompt.MaxCandidateLabelBytes)
			}
		}
	}
	if candidates == 0 {
		t.Fatal("no fix candidates reached the agent: the contract is not exercised")
	}
}

// newAgentClient returns the agent's API client for base, with a token file
// in a private temporary directory.
func newAgentClient(t *testing.T, base string) *nosclient.Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(oaTok), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := nosclient.New(nosclient.Config{BaseURL: base, TokenFile: path})
	if err != nil {
		t.Fatalf("nosclient.New: %v", err)
	}
	return c
}
