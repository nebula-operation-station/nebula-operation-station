// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"testing"
)

// A server that ignores typefilter/vmid can never widen the result: the
// filter is re-applied to every returned task.
func TestNodeTasksTypeAndVMIDFilterReappliedClientSide(t *testing.T) {
	f := newFakePVE(t, map[string]fakeRoute{tasksPath: {body: fixture(t, "tasklist_pve8.json")}})
	c := clusterTestClient(t, f)

	got, err := c.NodeTasks(context.Background(), "pve1", TaskFilter{Type: "vzdump", VMID: 200})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if len(got.Tasks) == 0 {
		t.Fatal("no vzdump task for 200 returned")
	}
	for _, task := range got.Tasks {
		if task.Type != "vzdump" || task.ID != "200" {
			t.Errorf("task %+v passed the filter", task)
		}
	}
	got, err = c.NodeTasks(context.Background(), "pve1", TaskFilter{Type: "vzdump", VMID: 2000})
	if err != nil {
		t.Fatalf("NodeTasks: %v", err)
	}
	if len(got.Tasks) != 0 {
		t.Errorf("prefix VMID matched: %+v", got.Tasks)
	}
}

func TestNodeTasksRejectsMalformedFilter(t *testing.T) {
	c := clusterTestClient(t, newFakePVE(t, map[string]fakeRoute{}))
	for name, f := range map[string]TaskFilter{
		"type with query":  {Type: "vzdump&vmid=1"},
		"uppercase type":   {Type: "VZDump"},
		"type too long":    {Type: "a234567890123456789012345678901234"},
		"vmid above range": {VMID: MaxVMID + 1},
	} {
		if _, err := c.NodeTasks(context.Background(), "pve1", f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
