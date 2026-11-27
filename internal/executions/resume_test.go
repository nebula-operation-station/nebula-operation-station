// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestResumeLeavesDurableLeaseJobsToTheCollection checks that a fim.scan job
// of a lease, still running when the server restarts, is not restarted through
// the dispatcher: collectLeaseJobs reads its outcome. A user's running
// execution is still resumed.
func TestResumeLeavesDurableLeaseJobsToTheCollection(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	ctx := context.Background()
	base := f.readGrantFake.fakeExec

	user, err := s.Create(ctx, "axel", "core.facts", []string{"web"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE executions SET state = 'running' WHERE id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE execution_hosts SET state = 'running' WHERE execution_id = ?`, user.ID); err != nil {
		t.Fatal(err)
	}
	const jobID = "00000000-0000-4000-8000-0000000000d1"
	insertLeaseJob(t, s, jobID, now)

	if err := s.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	s.Wait()

	base.mu.Lock()
	calls := base.polls + len(base.attached) + len(base.durable)
	base.mu.Unlock()
	if calls != 0 {
		t.Fatalf("resume called the executor %d times for the lease job, want 0", calls)
	}
	var state, hostState string
	if err := s.db.QueryRow(`SELECT e.state, h.state FROM executions e JOIN execution_hosts h ON h.execution_id = e.id
		WHERE e.id = ?`, jobID).Scan(&state, &hostState); err != nil {
		t.Fatal(err)
	}
	if state != "running" || hostState != "running" {
		t.Fatalf("lease job after resume: execution %q host %q; want running and left to the collection", state, hostState)
	}
	got, err := s.Get(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "finished" {
		t.Fatalf("user running execution after resume is %q, want finished: it must be resumed", got.State)
	}
}

// insertLeaseJob stores the execution and host rows of a durable fim.scan job
// that a lease started on web and that is still running, as storeLeaseJob
// stores it.
func insertLeaseJob(t *testing.T, s *Service, id string, startedAt time.Time) {
	t.Helper()
	canon, _, ok := fimScanModeParams("full")
	if !ok {
		t.Fatal(`no fim.scan mode "full"`)
	}
	a, ok := actions.Lookup(permit.FimScanActionID)
	if !ok {
		t.Fatal("fim.scan is not in the catalog")
	}
	if _, err := s.db.Exec(`INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
			durable, timeout_s, created_by, created_at, params, schedule_id) VALUES (?, '', ?, ?, ?, 'LOW', ?, 'running', 1, ?, 'schedule', ?, ?, ?)`,
		id, a.ID, a.Version, a.SHA256(), leaseRunRequirement, int64(a.Timeout/time.Second), startedAt.Unix(), string(canon), testGrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, started_at)
			VALUES (?, 'web', ?, 'nebula-default', '[]', 'running', ?)`, id, leaseWebKey, startedAt.Unix()); err != nil {
		t.Fatal(err)
	}
}
