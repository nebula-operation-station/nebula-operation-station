// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
)

// TestServicePveAdminUsesTheServiceMutationEngine: every admin the
// service builds carries the one engine the service runs mutations with,
// so CloseOpenJobs sees the runs in flight in this executor.
func TestServicePveAdminUsesTheServiceMutationEngine(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	m := e.svc.pveMutations()
	if m == nil {
		t.Fatal("service has no mutation engine")
	}
	if e.svc.pveMutations() != m {
		t.Fatal("service built a second mutation engine")
	}
	for range 2 {
		if a := e.svc.pveAdmin(); a.Mutations != m {
			t.Fatalf("admin engine %p, service engine %p", a.Mutations, m)
		}
	}
	if m.DB != e.svc.db || m.Auth != e.svc.auth || m.Vault != e.svc.vault {
		t.Fatal("engine not built from the service state")
	}
}

// TestServicePveAdminRefusesInFlightClose: through the admin the service
// builds, a step of a run still in flight in the service's engine is not
// closed, even with its remote blocked and its match window over; once the
// run checked out, the close goes through.
func TestServicePveAdminRefusesInFlightClose(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	const execID = "00000000-0000-4000-a000-0000000000c1"
	if err := e.db.CreatePveJobIntent(executordb.PveJob{
		ExecutionID: execID, Step: 1, Digest: strings.Repeat("ab", 32), Action: "pve.test.mutation",
		RemoteID: pveReadRemote, TrustGeneration: 1, Kind: "qemu", Node: "pve1", VMID: 101,
		RequestDigest: strings.Repeat("cd", 32), TaskType: "qmstart", TaskUser: "nebula@pve!action",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.BlockRemote(pveReadRemote, "trust verification failed", "admin"); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(pveTaskMatchWindow + pveTaskMatchSkew + time.Hour)
	e.svc.Now = func() time.Time { return later }
	in := PveCloseJobs{RemoteID: pveReadRemote, Reason: "remote blocked during dispatch", By: "alice"}

	m := e.svc.pveMutations()
	m.begin(execID)
	if _, err := e.svc.pveAdmin().CloseOpenJobs(context.Background(), in); !errors.Is(err, ErrPveJobInFlight) {
		t.Fatalf("close of an in-flight run: %v", err)
	}
	if open, _ := e.db.OpenPveJobs(); len(open) != 1 {
		t.Fatalf("in-flight step was closed: %+v", open)
	}
	m.end(execID)
	closed, err := e.svc.pveAdmin().CloseOpenJobs(context.Background(), in)
	if err != nil || len(closed) != 1 || closed[0].ExecutionID != execID {
		t.Fatalf("close after the run: %v %+v", err, closed)
	}
}
