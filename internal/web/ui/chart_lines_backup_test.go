// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// plainPVEStore is a PVE store without the backup freshness read.
type plainPVEStore struct{}

func (plainPVEStore) ListRemotes(context.Context, int) ([]pveinventory.Remote, error) {
	return nil, nil
}
func (plainPVEStore) GetRemote(context.Context, string) (pveinventory.Remote, error) {
	return pveinventory.Remote{}, pveinventory.ErrRemoteNotFound
}
func (plainPVEStore) ListNodes(context.Context, string, int) ([]pveinventory.Node, error) {
	return nil, nil
}
func (plainPVEStore) ListGuests(context.Context, string, pveinventory.GuestFilter, int) ([]pveinventory.Guest, error) {
	return nil, nil
}
func (plainPVEStore) ListDatasetStatus(context.Context, string) ([]pveinventory.DatasetStatus, error) {
	return nil, nil
}

// backupPVEStore adds the backup freshness read, per VMID.
type backupPVEStore struct {
	plainPVEStore
	byVMID map[uint64]pveinventory.Freshness
	err    error
	calls  int
}

func (s *backupPVEStore) GuestBackupFreshness(_ context.Context, remoteID string, vmid, generation uint64, _ time.Duration) (pveinventory.Freshness, error) {
	s.calls++
	if s.err != nil {
		return pveinventory.Freshness{}, s.err
	}
	if remoteID != "lab" || generation != 1 {
		return pveinventory.Freshness{}, fmt.Errorf("unexpected incarnation %s/%d/%d", remoteID, vmid, generation)
	}
	f, ok := s.byVMID[vmid]
	if !ok {
		return pveinventory.Freshness{State: pveinventory.FreshnessUnknown}, nil
	}
	return f, nil
}

// backupTree is one PVE node with n guests (VMID 101..), generation 1.
func backupTree(n int) pveinventory.Tree {
	node := pveinventory.Box{Kind: pveinventory.KindPVENode, Name: "pve1", RemoteID: "lab",
		State: pveinventory.StateOK, Worst: pveinventory.StateOK}
	for i := 0; i < n; i++ {
		node.Children = append(node.Children, pveinventory.Box{Kind: pveinventory.KindGuest,
			Name: fmt.Sprintf("vm%d", 101+i), VMID: uint64(101 + i), Generation: 1,
			State: pveinventory.StateOK, Worst: pveinventory.StateOK})
	}
	return pveinventory.Tree{Roots: []pveinventory.Box{node}}
}

// backupBody renders the chart with the given PVE store and tree.
func backupBody(t *testing.T, store ui.PVEStore, tree pveinventory.Tree) string {
	t.Helper()
	o := linesOptions(t, map[string]map[string]executions.LastResultRow{})
	o.PVE = store
	o.PVEChart = func(context.Context) (pveinventory.Tree, error) { return tree, nil }
	return getBody(t, newTestHandler(t, o).Handler(), "/inventory/chart")
}

func TestChartBackupLineStates(t *testing.T) {
	recent := linesNow.Add(-3 * time.Hour).Unix()
	old := linesNow.Add(-50 * time.Hour).Unix()
	cases := []struct {
		name   string
		f      pveinventory.Freshness
		state  string
		text   string
		border string
	}{
		{"ok", pveinventory.Freshness{State: pveinventory.FreshnessOK, LastSuccessUnix: recent,
			Task: pveinventory.TaskConfidence{Count: 4}, Catalog: pveinventory.CatalogConfidence{Present: true},
			Verification: pveinventory.VerificationConfidence{State: pvecontract.Yes}},
			"ok", "ok · last 3h ago", "chart__node--neutral"},
		{"overdue", pveinventory.Freshness{State: pveinventory.FreshnessOverdue, LastSuccessUnix: old},
			"warn", "overdue · last 2d ago", "chart__node--warning"},
		{"never", pveinventory.Freshness{State: pveinventory.FreshnessOverdue},
			"warn", "overdue · no successful backup", "chart__node--warning"},
		{"failed", pveinventory.Freshness{State: pveinventory.FreshnessFailed, LastSuccessUnix: old},
			"warn", "failed · last success 2d ago", "chart__node--warning"},
		{"stale evidence", pveinventory.Freshness{State: pveinventory.FreshnessStaleData},
			"stale", "backup data stale", "chart__node--neutral"},
		{"unknown", pveinventory.Freshness{State: pveinventory.FreshnessUnknown},
			"unknown", "backup unknown", "chart__node--neutral"},
		{"expected off", pveinventory.Freshness{State: pveinventory.FreshnessExpectedOff},
			"ok", "expected off", "chart__node--neutral"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &backupPVEStore{byVMID: map[uint64]pveinventory.Freshness{101: tc.f}}
			body := backupBody(t, store, backupTree(1))
			if !strings.Contains(body, `chart__line chart__line--backup chart__line--`+tc.state) {
				t.Errorf("backup line should be %s", tc.state)
			}
			if !strings.Contains(body, tc.text) {
				t.Errorf("chart body missing %q", tc.text)
			}
			if !hostNodeHas(body, tc.border) {
				t.Errorf("node border should be %s", tc.border)
			}
		})
	}
	// The confidence channels stay visible, separately, in the details.
	store := &backupPVEStore{byVMID: map[uint64]pveinventory.Freshness{101: cases[0].f}}
	if body := backupBody(t, store, backupTree(1)); !strings.Contains(body, "tasks 4 · catalog present · verified yes") {
		t.Error("backup confidence channels missing from the details title")
	}
}

func TestChartBackupLineHiddenWithoutSource(t *testing.T) {
	if body := backupBody(t, plainPVEStore{}, backupTree(2)); strings.Contains(body, "chart__line--backup") {
		t.Error("backup line rendered although the store has no freshness read")
	}
	if body := backupBody(t, nil, backupTree(2)); strings.Contains(body, "chart__line--") {
		t.Error("backup line rendered without a PVE store")
	}
}

func TestChartBackupLineReadErrorIsUnknown(t *testing.T) {
	store := &backupPVEStore{err: errors.New("db locked")}
	body := backupBody(t, store, backupTree(1))
	if !strings.Contains(body, `chart__line--backup chart__line--unknown`) || !strings.Contains(body, "backup unknown") {
		t.Error("a failed freshness read should render backup unknown")
	}
	if strings.Contains(body, "db locked") {
		t.Error("read error detail must stay in the log")
	}
}

func TestChartBackupLineReadBudget(t *testing.T) {
	store := &backupPVEStore{byVMID: map[uint64]pveinventory.Freshness{}}
	body := backupBody(t, store, backupTree(201))
	if store.calls != 200 {
		t.Errorf("freshness reads = %d, want 200 (the per-page bound)", store.calls)
	}
	if got := strings.Count(body, "backup unknown (not loaded)"); got != 1 {
		t.Errorf("not-loaded lines = %d, want 1", got)
	}
}

func TestChartBackupLineEscapesReason(t *testing.T) {
	store := &backupPVEStore{byVMID: map[uint64]pveinventory.Freshness{101: {
		State: pveinventory.FreshnessUnknown, Reason: `catalog denied: "<script>alert(1)</script>"`}}}
	body := backupBody(t, store, backupTree(1))
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("stored reason rendered as markup")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("stored reason not escaped in the title")
	}
}
