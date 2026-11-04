// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestPveRunExpiredMapsToDeadlineExceededInEveryRPC: a run that ended
// before its next step reads the same in every mutation RPC: DeadlineExceeded
// with a fixed text, never Internal "failed" or a target change.
func TestPveRunExpiredMapsToDeadlineExceededInEveryRPC(t *testing.T) {
	mappers := map[string]func(error) error{
		"guest power":     pveGuestPowerRPCError,
		"guest snapshot":  pveGuestSnapshotRPCError,
		"guest provision": pveGuestProvisionRPCError,
	}
	for name, mapErr := range mappers {
		for _, err := range []error{ErrPveRunExpired, fmt.Errorf("step 2: %w", ErrPveRunExpired)} {
			st := status.Convert(mapErr(err))
			if st.Code() != codes.DeadlineExceeded || !strings.Contains(st.Message(), "the run ended before the next step was sent") {
				t.Errorf("%s: %v -> %v %q, want DeadlineExceeded", name, err, st.Code(), st.Message())
			}
			if strings.Contains(st.Message(), "changed") || strings.Contains(st.Message(), "executor:") {
				t.Errorf("%s: message %q reads like a target change or carries the internal error", name, st.Message())
			}
		}
		// The new case does not swallow the neighbouring ones.
		if c := status.Code(mapErr(ErrPveTargetChanged)); c != codes.FailedPrecondition {
			t.Errorf("%s: target changed -> %v, want FailedPrecondition", name, c)
		}
		if c := status.Code(mapErr(vault.ErrLocked)); c != codes.FailedPrecondition {
			t.Errorf("%s: vault locked -> %v, want FailedPrecondition", name, c)
		}
	}
}

// TestServiceGuestPowerRunEndedBeforeItsStepIsDeadlineExceeded: a commit
// whose context ends during the read right before the only intent gets
// DeadlineExceeded (not Internal), sends nothing, and the unused approval
// commits later.
func TestServiceGuestPowerRunEndedBeforeItsStepIsDeadlineExceeded(t *testing.T) {
	e, client, _, _, _ := newServicePowerEnv(t)
	target := &pb.PVEGuestPowerTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Verb: "shutdown"}
	out, err := e.svc.ProposePVEGuestPower(context.Background(), &pb.ProposePVEGuestPowerRequest{Target: target})
	if err != nil {
		t.Fatal(err)
	}
	p := out.GetPermit()
	if _, err := e.svc.auth.ApproveCLI(digestOfPermit(t, p), 0, "admin"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.mu.Lock()
	reads := client.reads
	client.statusFn = func(n int) string {
		if n == reads+3 {
			// The engine's read right before the intent.
			cancel()
		}
		return "running"
	}
	client.mu.Unlock()
	_, err = e.svc.CommitPVEGuestPower(ctx, &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: p.GetExecutionDigest()})
	if st := status.Convert(err); st.Code() != codes.DeadlineExceeded || !strings.Contains(st.Message(), "run ended") {
		t.Fatalf("commit: %v, want DeadlineExceeded", err)
	}
	client.mu.Lock()
	got := client.reads - reads
	client.statusFn = nil
	client.mu.Unlock()
	if got != 3 || client.dispatchCount() != 0 {
		t.Fatalf("%d reads, %d dispatched; want the run to end at the pre-intent read with nothing sent", got, client.dispatchCount())
	}
	if _, err := e.svc.CommitPVEGuestPower(context.Background(), &pb.CommitPVEGuestPowerRequest{Target: target, ExecutionDigest: p.GetExecutionDigest()}); err != nil {
		t.Fatalf("the unused approval does not commit: %v", err)
	}
	if n := client.dispatchCount(); n != 1 {
		t.Fatalf("dispatched %d, want 1", n)
	}
}

func digestOfPermit(t *testing.T, p *pb.ProposeExecutionResponse) canonical.Digest {
	t.Helper()
	d, err := canonical.ParseDigest(p.GetExecutionDigest())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestPveMutationRunEndsInsideLiveCheck: when the run's context ends inside
// the typed action's live check (backup, migrate, snapshot) right after the
// pre-intent read, the run stops with ErrPveRunExpired, logs the end of the
// run and no precondition failure or target change, and records and sends
// nothing more. Before the first step the approval stays usable; after a
// recorded step the permit stays consumed.
func TestPveMutationRunEndsInsideLiveCheck(t *testing.T) {
	for _, tc := range []struct {
		name     string
		steps    []string
		cancelAt int // the liveCheck call (in Run) that ends the context
		recorded int
	}{
		// Call 1 is Run's check before authorization, call 2 the one
		// before step 1's intent, call 3 the one before step 2's.
		{name: "before the first step", steps: []string{"guest.start"}, cancelAt: 2, recorded: 0},
		{name: "before the second step", steps: []string{"guest.config", "guest.start"}, cancelAt: 3, recorded: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, armed := 0, false
			req := mutRequest(tc.steps...)
			req.liveCheck = func(cctx context.Context, _ executordb.PveRemote, _ PveTargetState, _ pveapi.TokenSupplier) error {
				if !armed {
					return nil
				}
				calls++
				if calls == tc.cancelAt {
					cancel()
				}
				// A real check's read fails once its context ended; the
				// engine must not take that for a changed target.
				if cctx.Err() != nil {
					return ErrPveTargetChanged
				}
				return nil
			}
			req = e.approve(req)
			armed = true
			res, err := e.m.Run(ctx, req)
			if !errors.Is(err, ErrPveRunExpired) || errors.Is(err, ErrPveTargetChanged) {
				t.Fatalf("run: %v, want ErrPveRunExpired", err)
			}
			if calls != tc.cancelAt {
				t.Fatalf("%d live checks, want %d", calls, tc.cancelAt)
			}
			if n := e.client.dispatchCount(); n != tc.recorded || len(res.Steps) != tc.recorded {
				t.Fatalf("dispatched %d, steps %+v; want %d", n, res.Steps, tc.recorded)
			}
			logs := e.logs.String()
			if strings.Contains(logs, "pve_mutation_precondition") || strings.Contains(logs, "pve_mutation_target_changed") || !strings.Contains(logs, "pve_mutation_run_expired") {
				t.Fatalf("logs:\n%s", logs)
			}
			if tc.recorded > 0 {
				if !res.PermitConsumed || strings.Contains(logs, "pve_mutation_permit_released") {
					t.Fatalf("permit released after a recorded step: consumed %v\n%s", res.PermitConsumed, logs)
				}
				if _, err := e.m.Run(context.Background(), req); err == nil {
					t.Fatal("a consumed permit ran again")
				}
				return
			}
			if res.PermitConsumed || !strings.Contains(logs, "pve_mutation_permit_released") {
				t.Fatalf("permit not released before the first step: consumed %v\n%s", res.PermitConsumed, logs)
			}
			if _, err := e.m.Run(context.Background(), req); err != nil {
				t.Fatalf("the unused approval does not run: %v", err)
			}
			if n := e.client.dispatchCount(); n != 1 {
				t.Fatalf("dispatched %d, want 1", n)
			}
		})
	}
}
