// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestVZDumpCatalogUsesNativeContentSchema(t *testing.T) {
	const volid = "local:backup/vzdump-qemu-100-2026_10_29-06_00_00.vma.zst"
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/nodes/pve1/storage/local/content": []byte(`{"data":[{"volid":"` + volid + `","content":"backup","format":"vma.zst","subtype":"qemu","vmid":100,"ctime":1793253600,"size":1024}]}`),
		"/api2/json/cluster/backup":                   loadFixture(t, "jobs-empty.json"),
	}))
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{
		Sources: []BackupSource{{Node: "pve1", Storage: "local", Type: "dir"}},
		Scope:   ReadScope{FullContent: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Catalog.Value) != 1 || obs.Catalog.Value[0].VolID != volid || obs.Catalog.Value[0].Source != SourceVZDump {
		t.Fatalf("catalog = %+v, want native vzdump entry", obs.Catalog)
	}
}

func TestCatalogUsesContentAndRealVerification(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		verified    TriState
		invalid     bool
	}{
		{"absent", "", TriUnknown, false},
		{"success", `,"verification":{"state":"ok","upid":"UPID:pbs:1:verify:"}`, TriYes, false},
		{"failed", `,"verification":{"state":"failed","upid":"UPID:pbs:1:verify:"}`, TriNo, false},
		{"invented boolean ignored", `,"verified":true`, TriUnknown, false},
		{"null", `,"verification":null`, "", true},
		{"boolean", `,"verification":true`, "", true},
		{"array", `,"verification":[]`, "", true},
		{"missing state", `,"verification":{}`, "", true},
		{"null state", `,"verification":{"state":null}`, "", true},
		{"wrong state type", `,"verification":{"state":1}`, "", true},
		{"unknown state", `,"verification":{"state":"unknown"}`, "", true},
		{"wrong upid type", `,"verification":{"state":"ok","upid":{}}`, "", true},
		{"oversized upid", `,"verification":{"state":"ok","upid":"` + strings.Repeat("a", maxVolidBytes+1) + `"}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":[{"volid":"pbs1:backup/vm/100/2026-10-29T06:00:00Z","content":"backup","format":"pbs-vm","vmid":100,"ctime":1793253600,"size":1024` + tc.extra + `}]}`
			c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
				"/api2/json/nodes/pve1/storage/pbs1/content": []byte(body),
				"/api2/json/cluster/backup":                  loadFixture(t, "jobs-empty.json"),
			}))
			obs, err := c.ReadBackups(context.Background(), BackupsOptions{
				Sources: []BackupSource{{Node: "pve1", Storage: "pbs1", Type: "pbs"}},
				Scope:   ReadScope{FullContent: true},
			})
			if tc.invalid {
				if err == nil {
					t.Fatal("malformed verification accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(obs.Catalog.Value) != 1 || obs.Catalog.Value[0].Verified != tc.verified {
				t.Fatalf("catalog = %+v, want verification %s", obs.Catalog, tc.verified)
			}
			wantStatus := StatusCatalog
			if tc.verified == TriYes {
				wantStatus = StatusVerified
			}
			if obs.Guests[0].Catalog.Value[0].Status != wantStatus {
				t.Fatalf("unexpected evidence status: %+v", obs.Guests[0].Catalog.Value)
			}
		})
	}
}

func TestJSONNestingIsBoundedBeforeDescent(t *testing.T) {
	for _, container := range []struct{ open, close string }{{"[", "]"}, {`{"nested":`, "}"}} {
		for _, depth := range []int{maxJSONDepth, maxJSONDepth + 1, 5000} {
			body := strings.Repeat(container.open, depth) + "0" + strings.Repeat(container.close, depth)
			err := strictJSON([]byte(body))
			if depth == maxJSONDepth && err != nil {
				t.Fatalf("depth at limit rejected: %v", err)
			}
			if depth > maxJSONDepth && (err == nil || !strings.Contains(err.Error(), "depth")) {
				t.Fatalf("depth %d: error = %v, want depth rejection", depth, err)
			}
		}
	}
	// Unknown fields must be bounded before schema decoding can ignore them.
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
		"/api2/json/cluster/backup": []byte(`{"data":[{"unknown":` + strings.Repeat("[", maxJSONDepth) + `0` + strings.Repeat("]", maxJSONDepth) + `}]}`),
	}))
	if _, err := c.ReadBackups(context.Background(), BackupsOptions{}); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Fatalf("nested response: %v", err)
	}
}

func TestRealJobSelectionAndCalendarSchedules(t *testing.T) {
	for _, tc := range []struct {
		name, fields string
		want         []uint64
	}{
		{"explicit comma list", `"vmid":"100,200"`, []uint64{100, 200}},
		{"explicit space list", `"vmid":"100 200"`, []uint64{100, 200}},
		{"all exclusions", `"all":1,"exclude":"100,300"`, []uint64{200}},
		{"pool takes precedence over all", `"all":1,"pool":"webservers"`, []uint64{100, 200, 300}},
		{"exclude implies all", `"exclude":"100 300"`, []uint64{200}},
		{"disabled integer", `"all":1,"enabled":0`, nil},
		{"disabled boolean", `"all":true,"enabled":false`, nil},
		{"enabled boolean", `"all":true,"enabled":true`, []uint64{100, 200, 300}},
		{"node restriction", `"all":1,"node":"pve1"`, []uint64{100}},
		{"explicit node restriction", `"vmid":"100,200,300","node":"pve1"`, []uint64{100}},
		{"pool node restriction", `"pool":"webservers","node":"pve1"`, []uint64{100}},
		{"invented volumes ignored", `"volumes":["local:backup/vm-100.vzdump"]`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"data":[{"storage":"local","schedule":"mon..fri 02:00",` + tc.fields + `}]}`
			c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
				"/api2/json/nodes/pve1/storage/local/content": loadFixture(t, "content-vzdump-pve8.json"),
				"/api2/json/cluster/backup":                   []byte(body),
			}))
			obs, err := c.ReadBackups(context.Background(), BackupsOptions{
				Sources:    []BackupSource{{Node: "pve1", Storage: "local", Type: "dir"}},
				Scope:      ReadScope{FullContent: true},
				GuestNodes: map[uint64]string{100: "pve1", 200: "pve2"},
				Pools:      map[string]map[uint64]bool{"webservers": {100: true, 200: true, 300: true, 400: false}},
				Tasks:      []TaskSummary{{Node: "pve1", Type: "vzdump", VMID: 300, StartedUnix: 1, FinishedUnix: 2, ExitStatus: TaskExitOK}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(obs.Jobs.Value) != 1 || obs.Jobs.Value[0].Schedule != "mon..fri 02:00" {
				t.Fatalf("jobs = %+v", obs.Jobs)
			}
			var covered []uint64
			for _, g := range obs.Guests {
				if len(g.Jobs.Value) > 0 {
					covered = append(covered, g.VMID)
				}
				if g.VMID == 400 {
					t.Fatal("false pool membership enumerated a guest")
				}
			}
			if fmt.Sprint(covered) != fmt.Sprint(tc.want) {
				t.Fatalf("covered = %v, want %v", covered, tc.want)
			}
		})
	}
}

func TestJobsRejectMalformedRealFields(t *testing.T) {
	for _, fields := range []string{
		`"vmid":"0"`, `"vmid":"2147483648"`, `"vmid":"100,bad"`,
		`"vmid":[100]`, `"vmid":"100,,200"`, `"exclude":"bad"`,
		`"node":"bad node"`, `"enabled":2`, `"enabled":null`, `"all":null`, `"schedule":"mon\n02:00"`,
		`"vmid":"100","all":1`, `"vmid":"100","pool":"webservers"`,
		`"vmid":"100","exclude":"200"`,
		`"vmid":"` + strings.Repeat("100,", maxVMIDsPerJob) + `100"`,
		`"exclude":"` + strings.Repeat("100,", maxVMIDsPerJob) + `100"`,
		`"vmid":"` + strings.Repeat("1", maxVMIDListBytes+1) + `"`,
	} {
		t.Run(fields[:min(len(fields), 50)], func(t *testing.T) {
			c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
				"/api2/json/cluster/backup": []byte(`{"data":[{"storage":"local",` + fields + `}]}`),
			}))
			if _, err := c.ReadBackups(context.Background(), BackupsOptions{}); err == nil {
				t.Fatal("malformed job accepted")
			}
		})
	}
}

func TestOnlyCompletedBackupTasksEmitEvidence(t *testing.T) {
	for _, typ := range []string{"backup", "vzdump"} {
		for _, tc := range []struct {
			name, exitStatus string
			start, finish    int64
			want             string
		}{
			{"success", "OK", 1, 2, StatusSuccess},
			{"failure", "ERROR: backup failed", 1, 2, StatusFailed},
			{"no completion", "", 1, 0, ""},
			{"no terminal status", "", 1, 2, ""},
			{"OK without finish", "OK", 1, 0, ""},
			{"failure without finish", "ERROR", 1, 0, ""},
			{"no start", "OK", 0, 2, ""},
		} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
					"/api2/json/cluster/backup": loadFixture(t, "jobs-empty.json"),
				}))
				obs, err := c.ReadBackups(context.Background(), BackupsOptions{
					GuestNodes: map[uint64]string{100: "pve1"},
					Tasks: []TaskSummary{{Node: "pve1", Type: typ, VMID: 100, Target: "100",
						StartedUnix: tc.start, FinishedUnix: tc.finish, ExitStatus: tc.exitStatus}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if len(obs.Guests) != 1 || !obs.Guests[0].Tasks.IsAvailable() {
					t.Fatalf("guest tasks unavailable: %+v", obs.Guests)
				}
				evs := obs.Guests[0].Tasks.Value
				if tc.want == "" {
					if len(evs) != 0 {
						t.Fatalf("incomplete task emitted evidence: %+v", evs)
					}
				} else if len(evs) != 1 || evs[0].Status != tc.want || evs[0].Source != SourceVZDump {
					t.Fatalf("evidence = %+v, want %s", evs, tc.want)
				}
			})
		}
	}
}

func TestMalformedBooleansNeverEchoResponseValues(t *testing.T) {
	const marker = "UNTRUSTED-REDACTION-MARKER"
	for _, field := range []string{"all", "enabled"} {
		for _, value := range []string{`{"notes":"` + marker + `"}`, `"` + marker + `"`, `["` + marker + `"]`} {
			c, _ := newTestClient(t, jsonServer(t, map[string][]byte{
				"/api2/json/cluster/backup": []byte(`{"data":[{"storage":"local","` + field + `":` + value + `}]}`),
			}))
			_, err := c.ReadBackups(context.Background(), BackupsOptions{})
			if err == nil || !strings.HasSuffix(err.Error(), "pveapi: expected boolean or 0/1") || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "notes") {
				t.Fatalf("expected fixed schema error without response values; got %v", err)
			}
		}
	}
}

func TestCorrelationBoundsSelectionAndPoolScanning(t *testing.T) {
	for _, poolSelection := range []bool{false, true} {
		t.Run(fmt.Sprintf("pool=%t", poolSelection), func(t *testing.T) {
			entries := make([]CatalogEntry, 100)
			for i := range entries {
				entries[i] = CatalogEntry{VMID: uint64(i + 1)}
			}
			jobs := make([]BackupJob, 1000)
			pools := map[string]map[uint64]bool{"webservers": {}}
			for i := 1; i <= 1100; i++ {
				pools["webservers"][uint64(i)] = false
			}
			for i := range jobs {
				jobs[i] = BackupJob{Enabled: true}
				if poolSelection {
					jobs[i].Pool = "webservers"
				} else {
					jobs[i].All = true
					jobs[i].Exclude = make([]uint64, 100)
					for k := range jobs[i].Exclude {
						jobs[i].Exclude[k] = uint64(k + 1)
					}
				}
			}
			got, err := correlate(AvailableDataset(entries), AvailableDataset(jobs), nil, pools, nil)
			if err == nil || !strings.Contains(err.Error(), "work limit") || got != nil {
				t.Fatalf("expected bounded selection work, got %d guests, error %v", len(got), err)
			}
		})
	}
}

func TestCorrelationRejectsExcessiveWorkAndOutput(t *testing.T) {
	for _, tc := range []struct {
		name         string
		guests, jobs int
		selected     bool
		longFields   bool
		wantError    string
	}{
		{"all job amplification", maxListings, maxListings, true, false, "limit"},
		{"nonmatching work", 1100, 1000, false, false, "work limit"},
		{"record count", 225, 225, true, false, "record limit"},
		{"output bytes", 200, 200, true, true, "output limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entries := make([]CatalogEntry, tc.guests)
			for i := range entries {
				entries[i] = CatalogEntry{VMID: uint64(i + 1)}
			}
			jobs := make([]BackupJob, tc.jobs)
			for i := range jobs {
				jobs[i] = BackupJob{Enabled: true, All: tc.selected}
				if tc.longFields {
					jobs[i].Schedule = strings.Repeat("<", maxFieldBytes)
					jobs[i].Storage = strings.Repeat("a", maxFieldBytes)
				}
			}
			got, err := correlate(AvailableDataset(entries), AvailableDataset(jobs), nil, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) || got != nil {
				t.Fatalf("guests length %d, error %v; want no partial output and %s", len(got), err, tc.wantError)
			}
		})
	}
}

func TestReadBackupsRejectsCorrelationAmplification(t *testing.T) {
	jobs := make([]map[string]any, maxListings)
	for i := range jobs {
		jobs[i] = map[string]any{"storage": "local", "all": 1}
	}
	body, err := json.Marshal(map[string]any{"data": jobs})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := newTestClient(t, jsonServer(t, map[string][]byte{"/api2/json/cluster/backup": body}))
	nodes := make(map[uint64]string, maxListings)
	for i := 1; i <= maxListings; i++ {
		nodes[uint64(i)] = "pve1"
	}
	obs, err := c.ReadBackups(context.Background(), BackupsOptions{GuestNodes: nodes})
	if err == nil || obs.Guests != nil || obs.Jobs.Value != nil {
		t.Fatalf("expected correlation rejection without partial observation: error %v", err)
	}
}
