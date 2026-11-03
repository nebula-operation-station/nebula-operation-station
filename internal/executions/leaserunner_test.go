// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// leaseRunFake serves read grants and records RunReadGrant calls.
type leaseRunFake struct {
	*readGrantFake
	runs []*pb.RunReadGrantRequest
	// runErr answers every RunReadGrant; errFor answers one host.
	runErr error
	errFor map[string]error
}

func (f *leaseRunFake) RunReadGrant(_ context.Context, in *pb.RunReadGrantRequest, _ ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	f.runs = append(f.runs, in)
	if err := f.errFor[in.GetRun().GetHostId()]; err != nil {
		return nil, err
	}
	if f.runErr != nil {
		return nil, f.runErr
	}
	return &pb.RunReadGrantResponse{ExecutionId: fmt.Sprintf("00000000-0000-4000-9000-%012d", len(f.runs)),
		Result: &pb.RunAttachedResponse{Class: "success", Result: []byte(`{"ok":true}`)}}, nil
}

// Fingerprints in the executor's real form (permit validates them).
var (
	leaseWebKey = "SHA256:" + strings.Repeat("A", 43)
	leaseDBKey  = "SHA256:" + strings.Repeat("B", 43)
	leaseCred   = "SHA256:" + strings.Repeat("C", 43)
)

// leaseDoc is an approved ordinary read-grant-v2 lease on hosts for actionIDs,
// created a minute before now and valid for seven days.
func leaseDoc(t *testing.T, now time.Time, hosts []string, actionIDs ...string) permit.ReadGrantDoc {
	t.Helper()
	empty, err := canonical.HashParameters([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	doc := permit.ReadGrantDoc{
		Grant: permit.ReadGrantFormat, ID: testGrantID, Issuer: readGrantIssuer,
		CreatedUnix: now.Add(-time.Minute).Unix(), ExpiryUnix: now.Add(7 * 24 * time.Hour).Unix(),
		Trigger: permit.TriggerBoth, RateProfile: schedgrant.OrdinaryReadProfile,
		MinIntervalS: int64(schedgrant.MinInterval / time.Second), RunBudget: permit.DefaultRunBudget,
	}
	for _, id := range actionIDs {
		a, ok := actions.Lookup(id)
		if !ok {
			t.Fatalf("unknown action %s", id)
		}
		doc.Actions = append(doc.Actions, permit.ReadGrantAction{ActionID: a.ID, ModuleVersion: a.Version, ArtifactSHA256: a.SHA256(), ParametersHash: empty})
	}
	keys := map[string]string{"web": leaseWebKey, "db": leaseDBKey}
	for _, h := range hosts {
		doc.Targets = append(doc.Targets, canonical.Target{HostID: h, HostKeyFingerprint: keys[h]})
		doc.Credentials = append(doc.Credentials, permit.ReadGrantCredential{HostID: h, CredentialRef: "nebula-default", CredentialVersion: leaseCred})
	}
	return doc
}

// leaseEntry is the executor's registry entry for doc (digest computed the
// way the executor does).
func leaseEntry(t *testing.T, doc permit.ReadGrantDoc, now time.Time) *pb.ReadGrant {
	t.Helper()
	raw := marshalDoc(t, doc)
	digest := strings.Repeat("ab", 32)
	if _, _, d, err := permit.ParseReadGrant(raw, now); err == nil {
		digest = d
	}
	return &pb.ReadGrant{GrantId: doc.ID, GrantDigest: digest, CanonicalGrant: raw, ApprovedBy: testApprover,
		CreatedUnix: doc.CreatedUnix, ExpiryUnix: doc.ExpiryUnix}
}

// setupLeases is a service whose executor holds grants, with web and db
// enrolled under the lease's host keys.
func setupLeases(t *testing.T, now *time.Time, grants ...func(time.Time) *pb.ReadGrant) (*Service, *leaseRunFake) {
	t.Helper()
	base := &fakeExec{}
	f := &leaseRunFake{readGrantFake: &readGrantFake{fakeExec: base}}
	s, _ := setup(t, base)
	s.exec = f
	base.pins = []*pb.HostKeyPin{
		{HostId: "web", Fingerprint: leaseWebKey, CredentialRef: "nebula-default"},
		{HostId: "db", Fingerprint: leaseDBKey, CredentialRef: "nebula-default"},
	}
	s.now = func() time.Time { return *now }
	for _, g := range grants {
		f.grants = append(f.grants, g(*now))
	}
	return s, f
}

func TestOrdinaryLeaseRunsOnItsMinInterval(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	var doc permit.ReadGrantDoc
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		doc = leaseDoc(t, n, []string{"web"}, "core.facts")
		return leaseEntry(t, doc, n)
	})
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	s.RunDueReadGrants(ctx) // not due again within the interval
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1", len(f.runs))
	}
	r := f.runs[0]
	a, _ := actions.Lookup("core.facts")
	if r.GetGrantId() != testGrantID || r.GetTrigger() != pb.ReadGrantTrigger_READ_GRANT_TRIGGER_SCHEDULED ||
		r.GetRun().GetHostId() != "web" || r.GetRun().GetHostKeyFingerprint() != leaseWebKey ||
		r.GetRun().GetActionId() != a.ID || r.GetRun().GetModuleVersion() != a.Version ||
		string(r.GetRun().GetArtifact()) != string(a.Script) || string(r.GetRun().GetParametersJson()) != "{}" ||
		r.GetRun().GetCredentialRef() != "nebula-default" || r.GetRun().GetExecutionDigest() != "" ||
		len(r.GetEndpoints()) != 2 || r.GetTimeoutSeconds() != uint32(a.Timeout/time.Second) {
		t.Fatalf("%v", r)
	}
	if len(f.scheduled) != 0 {
		t.Fatal("an ordinary lease ran through the legacy schedule RPC")
	}
	// The result lands where legacy scheduled results land.
	list, _ := s.List(ctx, 10)
	if len(list) != 1 || list[0].CreatedBy != "schedule" || list[0].State != "finished" || list[0].ActionID != "core.facts" {
		t.Fatalf("%+v", list)
	}
	var sched string
	if err := s.db.QueryRowContext(ctx, `SELECT schedule_id FROM executions WHERE id = ?`, list[0].ID).Scan(&sched); err != nil || sched != testGrantID {
		t.Fatalf("schedule_id %q %v", sched, err)
	}

	now = now.Add(14 * time.Minute)
	s.RunDueReadGrants(ctx)
	if len(f.runs) != 1 {
		t.Fatalf("ran before min_interval_s: %d runs", len(f.runs))
	}
	now = now.Add(time.Minute)
	s.RunDueReadGrants(ctx)
	if len(f.runs) != 2 {
		t.Fatalf("not run after min_interval_s: %d runs", len(f.runs))
	}
}

func TestOrdinaryLeaseRespectsTheRollingHourBudget(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		doc := leaseDoc(t, n, []string{"web", "db"}, "core.facts", "package.list_updates", "docker.list")
		doc.RunBudget = 4
		return leaseEntry(t, doc, n)
	})
	ctx := context.Background()
	perHost := func() map[string]int {
		m := map[string]int{}
		for _, r := range f.runs {
			m[r.GetRun().GetHostId()]++
		}
		return m
	}
	s.RunDueReadGrants(ctx) // 3 actions due, budget 4: all 3 per host
	if m := perHost(); m["web"] != 3 || m["db"] != 3 {
		t.Fatalf("%v", m)
	}
	now = now.Add(16 * time.Minute)
	s.RunDueReadGrants(ctx) // 3 due again, 1 left in the hour
	if m := perHost(); m["web"] != 4 || m["db"] != 4 {
		t.Fatalf("%v", m)
	}
	now = now.Add(16 * time.Minute)
	s.RunDueReadGrants(ctx) // budget spent for the rolling hour
	if m := perHost(); m["web"] != 4 || m["db"] != 4 {
		t.Fatalf("budget exceeded: %v", m)
	}
	now = now.Add(29 * time.Minute) // the first three runs leave the hour
	s.RunDueReadGrants(ctx)
	if m := perHost(); m["web"] != 7 || m["db"] != 7 {
		t.Fatalf("%v", m)
	}
}

func TestOnlyActiveScheduledOrdinaryLeasesRun(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	for name, mk := range map[string]func(time.Time) *pb.ReadGrant{
		"telemetry profile": func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"web"}, "core.facts")
			d.Actions[0].ActionID = "host.metrics"
			d.RateProfile = schedgrant.TelemetryReadProfile
			return leaseEntry(t, d, n)
		},
		"provider profile": func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"web"}, "core.facts")
			d.RateProfile = permit.ProviderReadProfile
			return leaseEntry(t, d, n)
		},
		"on-demand only": func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"web"}, "core.facts")
			d.Trigger = permit.TriggerOnDemand
			return leaseEntry(t, d, n)
		},
		"revoked": func(n time.Time) *pb.ReadGrant {
			g := leaseEntry(t, leaseDoc(t, n, []string{"web"}, "core.facts"), n)
			g.RevokedUnix = n.Unix()
			return g
		},
		"expired": func(n time.Time) *pb.ReadGrant {
			g := leaseEntry(t, leaseDoc(t, n, []string{"web"}, "core.facts"), n)
			g.ExpiryUnix = n.Unix()
			return g
		},
		"digest mismatch": func(n time.Time) *pb.ReadGrant {
			g := leaseEntry(t, leaseDoc(t, n, []string{"web"}, "core.facts"), n)
			g.GrantDigest = strings.Repeat("cd", 32)
			return g
		},
		"legacy schedule": func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"web"}, "core.facts")
			return &pb.ReadGrant{GrantId: d.ID, GrantDigest: testDigest, ApprovedBy: testApprover,
				CanonicalGrant: grantDoc(t, schedgrant.Format, []string{"web"}, n, n.Add(time.Hour), n),
				CreatedUnix:    n.Unix(), ExpiryUnix: n.Add(time.Hour).Unix()}
		},
		"stale host key": func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"web"}, "core.facts")
			d.Targets[0].HostKeyFingerprint = leaseDBKey
			return leaseEntry(t, d, n)
		},
		"artifact not the local built-in": func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"web"}, "core.facts")
			d.Actions[0].ArtifactSHA256 = strings.Repeat("0", 64)
			return leaseEntry(t, d, n)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, f := setupLeases(t, &now, mk)
			s.RunDueReadGrants(context.Background())
			if len(f.runs) != 0 {
				t.Fatalf("%d runs", len(f.runs))
			}
		})
	}
}

func TestLeaseRunnerFollowsExecutorRefusals(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	twoHosts := func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, leaseDoc(t, n, []string{"web", "db"}, "core.facts", "docker.list"), n)
	}
	ctx := context.Background()

	t.Run("budget exhausted skips the host, keeps the others", func(t *testing.T) {
		s, f := setupLeases(t, &now, twoHosts)
		f.errFor = map[string]error{"web": status.Error(codes.ResourceExhausted, "read_grant_budget_exhausted: rolling hour")}
		s.RunDueReadGrants(ctx)
		web, db := 0, 0
		for _, r := range f.runs {
			if r.GetRun().GetHostId() == "web" {
				web++
			} else {
				db++
			}
		}
		if web != 1 || db != 2 {
			t.Fatalf("web %d db %d", web, db)
		}
		if list, _ := s.List(ctx, 10); len(list) != 2 {
			t.Fatalf("%d stored", len(list))
		}
	})
	t.Run("revoked or paused stops the lease for this tick", func(t *testing.T) {
		s, f := setupLeases(t, &now, twoHosts)
		f.runErr = status.Error(codes.PermissionDenied, "read_grant_inactive: the read grant was revoked or has expired")
		s.RunDueReadGrants(ctx)
		if len(f.runs) != 1 {
			t.Fatalf("%d runs", len(f.runs))
		}
		if list, _ := s.List(ctx, 10); len(list) != 0 {
			t.Fatal("a refused run was stored")
		}
		// The executor stays the authority: once it accepts again, the
		// lease runs on the next tick.
		f.runErr = nil
		s.RunDueReadGrants(ctx)
		if len(f.runs) != 5 {
			t.Fatalf("%d runs", len(f.runs))
		}
	})
	t.Run("locked executor stops all leases for this tick", func(t *testing.T) {
		second := func(n time.Time) *pb.ReadGrant {
			d := leaseDoc(t, n, []string{"db"}, "core.facts")
			d.ID = "7f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f8"
			return leaseEntry(t, d, n)
		}
		s, f := setupLeases(t, &now, twoHosts, second)
		f.runErr = status.Error(codes.FailedPrecondition, "credential unavailable for read")
		s.RunDueReadGrants(ctx)
		if len(f.runs) != 1 {
			t.Fatalf("%d runs while locked", len(f.runs))
		}
	})
	t.Run("a target not covered is skipped, the lease goes on", func(t *testing.T) {
		s, f := setupLeases(t, &now, twoHosts)
		f.errFor = map[string]error{"web": status.Error(codes.PermissionDenied, "read_grant_does_not_cover: host or host key")}
		s.RunDueReadGrants(ctx)
		if len(f.runs) != 4 {
			t.Fatalf("%d runs", len(f.runs))
		}
	})
}

func TestLeaseRunnerNeedsTheReadGrantAPI(t *testing.T) {
	// An executor without the read-grant API (an older test double) runs
	// legacy schedules only; the lease runner does nothing.
	f := &fakeExec{}
	s, _ := setup(t, f)
	s.RunDueReadGrants(context.Background())
	if len(f.scheduled) != 0 {
		t.Fatal("ran without the read-grant API")
	}
}
