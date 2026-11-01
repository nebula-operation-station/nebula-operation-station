// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// BACKUPS limits (ADR 0006 P1-19/P1-20).
const (
	// pveBackupWindow is how far back BACKUPS looks for vzdump tasks; it
	// spans a weekly backup schedule.
	pveBackupWindow = 7 * 24 * time.Hour
	// pveBackupTasksPerNode bounds the vzdump tasks of one guest read from
	// one node. Tasks are newest first, so a cut keeps the most recent
	// evidence; the evidence is never a complete backup history.
	pveBackupTasksPerNode = 20
	// pveBackupTaskType is the PVE task type of a backup run.
	pveBackupTaskType = "vzdump"
)

// pveReasonCatalogScope is the fixed catalog reason. PVE filters storage
// content listings silently for tokens without VM.Backup and
// Datastore.AllocateSpace (pveapi.ReadScope.FullContent), and the executor
// registry does not record the read token's privileges, so a listing could
// look complete while omitting volumes. The catalog therefore stays
// unavailable, never empty, until the scope is probed and recorded with the
// read credential version, so that a token rotation invalidates it.
const pveReasonCatalogScope = "catalog completeness unknown: the read token's backup privileges are not recorded"

// readPveBackups reads backup task evidence for one guest: vzdump task
// summaries whose target is exactly vmid, from every online node within
// pveBackupWindow. A node whose task list cannot be read makes the task
// evidence unavailable, since a missing success elsewhere must not look
// like "never backed up". The catalog part is always unavailable with
// pveReasonCatalogScope.
func readPveBackups(ctx context.Context, remoteID, base string, hc *http.Client, token pveapi.TokenSupplier, vmid uint64, at time.Time) *pb.PVEBackups {
	out := &pb.PVEBackups{Vmid: vmid, CatalogState: pveUnavailable, CatalogReason: pveReasonCatalogScope}
	unavailable := func(reason string) *pb.PVEBackups {
		out.State, out.Reason, out.Backups = pveUnavailable, reason, nil
		return out
	}
	inv, err := pveapi.New(base, hc, token, pveapi.WithTimeout(pveReadRequestTimeout))
	if err != nil {
		return unavailable(pveReasonRead)
	}
	ref, reason := resolvePveGuest(ctx, inv, vmid)
	if reason != "" {
		return unavailable(reason)
	}
	nodes, err := inv.ListNodes(ctx)
	if err != nil {
		return unavailable(pveReasonRead)
	}
	c := &pveapi.Client{HTTP: hc, BaseURL: base + "/api2/json", Token: token, Timeout: pveReadRequestTimeout}
	evidence := []pvecontract.BackupEvidence{}
	for _, n := range nodes {
		if n.Status != "online" {
			continue
		}
		list, err := c.NodeTasks(ctx, n.Name, pveapi.TaskFilter{
			Since: at.Add(-pveBackupWindow), Limit: pveBackupTasksPerNode, Type: pveBackupTaskType, VMID: vmid,
		})
		if err != nil || !list.Available {
			return unavailable(pveReasonPartial)
		}
		for _, t := range list.Tasks {
			evidence = append(evidence, pveBackupTaskEvidence(t))
		}
	}
	slices.SortStableFunc(evidence, func(a, b pvecontract.BackupEvidence) int {
		switch {
		case a.StartedUnix > b.StartedUnix:
			return -1
		case a.StartedUnix < b.StartedUnix:
			return 1
		}
		return 0
	})
	g := ref.observation()
	g.Backups = pvecontract.AvailableDataset(evidence)
	if !pveGuestValid(remoteID, at, g) {
		return unavailable(pveReasonInvalid)
	}
	out.State = pveAvailable
	for _, b := range evidence {
		out.Backups = append(out.Backups, &pb.PVEBackupEvidence{Source: b.Source, Kind: b.Kind, Status: b.Status,
			StartedUnix: b.StartedUnix, FinishedUnix: b.FinishedUnix, Verified: string(b.Verified)})
	}
	return out
}

// pveBackupTaskEvidence maps one vzdump task summary onto the contract:
//
//   - no end time: "running" while PVE reports it running (or nothing),
//     otherwise "unknown";
//   - ended with "OK": "success";
//   - ended with "WARNINGS: n" or without a status: "unknown" (a run with
//     warnings may have skipped volumes, so it is not counted as success);
//   - any other result: "failed".
//
// Task evidence never verifies a backup; verified is always "unknown".
func pveBackupTaskEvidence(t pveapi.TaskSummary) pvecontract.BackupEvidence {
	b := pvecontract.BackupEvidence{Source: pvecontract.BackupVZDump, Kind: pvecontract.BackupKindTask,
		StartedUnix: t.Start.Unix(), Verified: pvecontract.Unknown}
	switch {
	case t.End.IsZero():
		b.Status = "unknown"
		if t.Status == "" || t.Status == "RUNNING" {
			b.Status = "running"
		}
	case t.Status == pveapi.TaskExitOK:
		b.Status = "success"
	case t.Status == "" || strings.HasPrefix(t.Status, "WARNINGS:"):
		b.Status = "unknown"
	default:
		b.Status = "failed"
	}
	if !t.End.IsZero() {
		b.FinishedUnix = t.End.Unix()
	}
	return b
}
