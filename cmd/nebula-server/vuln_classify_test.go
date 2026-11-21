// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Versions of the classifier fixtures: openssl is installed at clsOld and
// the episode fix is clsNew.
const (
	clsOld  = "3.0.15-1~deb12u1"
	clsNew  = "3.0.16-1~deb12u1"
	clsHost = "web01"
)

// clsRecord is a host record of source package src installed at ver with
// the fix version fix; an empty fix is a record with no fix yet.
func clsRecord(cve, src, ver, fix string) map[string]any {
	r := vtRecord(cve, false)
	r["component"] = map[string]any{"source_package": src, "source_version": ver}
	if fix == "" {
		r["fix"] = map[string]any{"state": "no_fix_yet"}
		r["tracker_state"] = "unfixed"
	} else {
		r["fix"] = map[string]any{"state": "fixed", "version": fix}
	}
	return r
}

// clsKernel is the running kernel of a read: mapped to the kernel source
// linux at version, or unmapped when state is not osdebian.KernelMapped.
func clsKernel(version string) vulninventory.Kernel {
	return vulninventory.Kernel{Release: "6.1.0-28-amd64", State: string(osdebian.KernelMapped), Source: "linux", Version: version}
}

// clsUnmappedKernel is a running kernel NOS could not map to a source.
var clsUnmappedKernel = vulninventory.Kernel{Release: "6.1.0-28-amd64", State: string(osdebian.KernelVersionUnknown)}

// clsComp is an installed source package with one binary.
func clsComp(src, ver string) vulninventory.Component {
	return vulninventory.Component{Source: src, SourceVersion: ver,
		Binaries: []vulninventory.Binary{{Name: src, Version: ver, Arch: "amd64"}}}
}

// clsRead is a read of clsHost at at; a partial read carries its reason.
func clsRead(exec string, at time.Time, complete bool, kernel vulninventory.Kernel, comps ...vulninventory.Component) vulninventory.Read {
	r := vulninventory.Read{HostID: clsHost, ExecutionID: exec, ReadAt: at, Complete: complete,
		Ecosystem: "debian:bookworm", Kernel: kernel, Components: comps}
	if !complete {
		r.Reason = vulninventory.ReasonIncomplete
	}
	return r
}

// clsPut stores a read as the package list observer does.
func clsPut(t *testing.T, e *vtEnv, r vulninventory.Read) {
	t.Helper()
	st, err := vulninventory.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Put(context.Background(), r); err != nil {
		t.Fatalf("store read %s: %v", r.ExecutionID, err)
	}
}

// clsFinding submits rec as the only finding of a run and returns the
// stored finding of clsHost. Its last write is the clock's time now.
func clsFinding(t *testing.T, e *vtEnv, rec map[string]any) vulnstore.Finding {
	t.Helper()
	e.startAndSubmit(t, rec)
	fs, err := e.svc.store.SubjectFindings(context.Background(), vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings of %s = %d, %v; want one", clsHost, len(fs), err)
	}
	return fs[0]
}

// clsRunCovering starts a run over the snapshot of vtInventory and submits
// one batch that names the host web01 as covered, with records as its
// findings. A host the run covers and does not report is a closure request
// (D5). It returns the run ID.
func clsRunCovering(t *testing.T, e *vtEnv, records ...map[string]any) string {
	t.Helper()
	at := e.clk.Now().Add(-time.Hour).Format(time.RFC3339)
	var sources []any
	for _, id := range []string{"debian-tracker", "kev", "osv"} {
		sources = append(sources, map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none", "date_kind": "data", "content_date": at})
	}
	rec := e.do(t, http.MethodPost, "/api/v1/vuln/runs", vtToken, vtHermes,
		map[string]any{"inventory_snapshot_id": "snap-1", "matcher_version": "1.4.0", "sources": sources})
	if rec.Code != http.StatusCreated {
		t.Fatalf("start run: %d %s", rec.Code, rec.Body)
	}
	var started struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	recs := make([]any, len(records))
	for i, r := range records {
		recs[i] = r
	}
	subjects := []any{map[string]any{"subject_kind": "host", "subject_ref": map[string]any{"id": clsHost}, "part": 1, "last_part": true}}
	rec = e.do(t, http.MethodPost, "/api/v1/vuln/runs/"+started.RunID+"/findings", vtToken, vtHermes,
		map[string]any{"batch_seq": 0, "subjects": subjects, "findings": recs})
	if rec.Code != http.StatusOK {
		t.Fatalf("submit batch: %d %s", rec.Code, rec.Body)
	}
	return started.RunID
}

// clsComplete completes runID and fails the test if the store refuses it.
func clsComplete(t *testing.T, e *vtEnv, runID string) {
	t.Helper()
	if _, err := e.svc.store.Complete(context.Background(), runID); err != nil {
		t.Fatalf("complete run: %v", err)
	}
}

// TestVulnClassifyClosureClasses pins the D5 class of a finding against the
// stored inventory: evidence only from a complete read taken after the last
// write, the basis from the newest read naming the component, and fail
// closed on a missing inventory.
func TestVulnClassifyClosureClasses(t *testing.T) {
	tests := []struct {
		name    string
		rec     map[string]any
		reads   func(t0 time.Time) []vulninventory.Read
		want    vulnstore.Class
		wantNOS string
		wantErr bool
	}{
		{
			name: "row 1 evidenced: complete read after the write shows the fixed version",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassEvidenced, wantNOS: clsNew,
		},
		{
			name: "row 2 evidenced: complete read after the write no longer names the component",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassEvidenced,
		},
		{
			name: "contradicted: newest complete read below the fixed version",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld))}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "contradicted by a newer partial read that still names the old version",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)),
					clsRead("r2", t0.Add(2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "newer partial read without the component: last complete basis contradicts",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)),
					clsRead("r2", t0.Add(2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "newer partial read without the component: last complete fixed version evidences",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)),
					clsRead("r2", t0.Add(2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
				}
			},
			want: vulnstore.ClassEvidenced, wantNOS: clsNew,
		},
		{
			name: "read older than the last write never evidences",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r0", t0.Add(-time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name: "partial newest read naming the fixed version without a complete read is unconfirmed",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: clsNew,
		},
		{
			name: "only a partial read not naming the component is unconfirmed",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name:    "no inventory read at all fails closed",
			rec:     clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads:   func(time.Time) []vulninventory.Read { return nil },
			wantErr: true,
		},
		{
			name: "no fixed version and the same basis is unchanged",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld))}
			},
			want: vulnstore.ClassUnconfirmedUnchanged, wantNOS: clsOld,
		},
		{
			name: "no fixed version and a changed basis is unconfirmed",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: clsNew,
		},
		{
			name: "no fixed version and the package removed is evidenced by row 2",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassEvidenced,
		},
		{
			name: "kernel: mapped running kernel at the fixed version is evidenced",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.120-1"))}
			},
			want: vulnstore.ClassEvidenced, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: mapped running kernel below the fixed version is contradicted",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"))}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
		{
			name: "kernel: a partial read at the fixed version does not evidence",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), false, clsKernel("6.1.120-1"))}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: an unmapped running kernel is unconfirmed",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsUnmappedKernel, clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name: "kernel: a complete read without the kernel package never evidences",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newVTEnv(t)
			f := clsFinding(t, e, tt.rec)
			for _, r := range tt.reads(e.clk.Now()) {
				clsPut(t, e, r)
			}
			a, err := e.svc.classifier.assess(context.Background(), f)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("assess = %+v, want an error (fail closed)", a)
				}
				if _, cerr := e.svc.classifier.Classify(context.Background(), f); cerr == nil {
					t.Fatal("Classify returned no error for a fail-closed case")
				}
				return
			}
			if err != nil {
				t.Fatalf("assess: %v", err)
			}
			if a.class != tt.want || a.nosVersion != tt.wantNOS {
				t.Fatalf("assess = class %d version %q, want class %d version %q", a.class, a.nosVersion, tt.want, tt.wantNOS)
			}
			c, err := e.svc.classifier.Classify(context.Background(), f)
			if err != nil || c != tt.want {
				t.Fatalf("Classify = %d, %v; want %d", c, err, tt.want)
			}
		})
	}
}

// TestVulnClassifyUnassessableSubjectsAreUnconfirmed: images, devices and
// records NOS cannot re-check (D5: image packages unknown, vendor, cpe,
// language ecosystems) are unconfirmed, never an error and never closed.
func TestVulnClassifyUnassessableSubjectsAreUnconfirmed(t *testing.T) {
	e := newVTEnv(t)
	host := vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost}
	image := vulnstore.Subject{Kind: vulnfinding.SubjectImage, ID: clsHost, ImageDigest: "sha256:" + strings.Repeat("a", 64)}
	device := vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "router1"}
	comp := vulnfinding.Component{SourcePackage: "openssl", SourceVersion: clsOld}
	debian := vulnfinding.Record{MatchBasis: vulnfinding.MatchDistroTracker, Ecosystem: "debian:bookworm", Component: comp}
	tests := []struct {
		name string
		f    vulnstore.Finding
	}{
		{"image subject", vulnstore.Finding{Subject: image, Record: debian, EpisodeFixedVersion: clsNew}},
		{"device subject", vulnstore.Finding{Subject: device, Record: debian, EpisodeFixedVersion: clsNew}},
		{"vendor advisory basis", vulnstore.Finding{Subject: host, EpisodeFixedVersion: clsNew,
			Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchVendorAdvisory, Ecosystem: "debian:bookworm", Component: comp}}},
		{"cpe basis", vulnstore.Finding{Subject: host, EpisodeFixedVersion: clsNew,
			Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchCPE, Ecosystem: "debian:bookworm", Component: comp}}},
		{"language ecosystem", vulnstore.Finding{Subject: host, EpisodeFixedVersion: clsNew,
			Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchOSVRange, Ecosystem: "PyPI", Component: comp}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := e.svc.classifier.Classify(context.Background(), tt.f)
			if err != nil || c != vulnstore.ClassUnconfirmed {
				t.Fatalf("Classify = %d, %v; want ClassUnconfirmed without error", c, err)
			}
		})
	}
}

// TestVulnRunKeepsContradictedFindingOpen: a run that asks to close a finding
// NOS still sees below the fix leaves it open, held with NOS's version, and
// the findings page shows that version as contradicted.
func TestVulnRunKeepsContradictedFindingOpen(t *testing.T) {
	e := newVTEnv(t)
	f := clsFinding(t, e, clsRecord("CVE-2026-7003", "openssl", clsOld, clsNew))
	clsPut(t, e, clsRead("r1", e.clk.Now().Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	clsComplete(t, e, clsRunCovering(t, e))

	ctx := context.Background()
	got, err := e.svc.store.Get(ctx, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != vulnstore.StateOpen {
		t.Fatalf("state = %s, want open", got.State)
	}
	holds, err := e.svc.store.Holds(ctx, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(holds) != 1 || holds[0].Reason != vulnstore.HoldContradicted {
		t.Fatalf("holds = %+v, want one contradicted hold", holds)
	}
	d, err := (vulnPages{v: e.svc}).VulnFinding(ctx, f.Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Holds) != 1 || d.Holds[0].NOSVersion != clsOld || !d.Holds[0].Contradicted {
		t.Fatalf("page holds = %+v, want NOS version %s and contradicted", d.Holds, clsOld)
	}
}

// TestVulnRunClosesByInventoryWhenFixedVersionIsInstalled: a run closure of
// a finding that NOS's complete read shows at the fixed version closes as
// nos_inventory.
func TestVulnRunClosesByInventoryWhenFixedVersionIsInstalled(t *testing.T) {
	e := newVTEnv(t)
	f := clsFinding(t, e, clsRecord("CVE-2026-7004", "openssl", clsOld, clsNew))
	clsPut(t, e, clsRead("r1", e.clk.Now().Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)))
	clsComplete(t, e, clsRunCovering(t, e))

	got, err := e.svc.store.Get(context.Background(), f.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != vulnstore.StateFixed || got.ClosedBy != vulnstore.ClosedByNOSInventory {
		t.Fatalf("state = %s closed by %s, want fixed by nos_inventory", got.State, got.ClosedBy)
	}
}

// debianWith is the Debian 12 fixture with one more installed source package
// line of openssl at version, before the kernel line.
func debianWith(t *testing.T, version string) string {
	t.Helper()
	text := debian12Text(t)
	line := "P\tinstalled\topenssl\tamd64\t" + version + "\topenssl\t" + version + "\t\t.\n"
	text = strings.Replace(text, "K\t6.1.0-26-amd64", line+"K\t6.1.0-26-amd64", 1)
	return strings.Replace(text, "END\t11", "END\t12", 1)
}

// TestCompleteInventoryReadClosesByInventory: a complete read stored by the
// package list observer closes a finding by inventory, writes the count as
// an audit line, and never closes the kernel finding (D4, D5 path 1 and 2).
func TestCompleteInventoryReadClosesByInventory(t *testing.T) {
	tests := []struct {
		name      string
		installed func(t *testing.T) string
		// want is the state of every finding; closed is the audit count.
		want   map[string]vulnstore.State
		closed int
	}{
		{
			name:      "path 2: a package the read no longer names closes, the kernel stays open",
			installed: func(t *testing.T) string { return debian12Text(t) },
			want: map[string]vulnstore.State{"CVE-2026-7010": vulnstore.StateFixed,
				"CVE-2026-7011": vulnstore.StateFixed, "CVE-2026-7012": vulnstore.StateOpen},
			closed: 2,
		},
		{
			name:      "path 1: a package at the fixed version closes, one without a fix stays open",
			installed: func(t *testing.T) string { return debianWith(t, clsNew) },
			want: map[string]vulnstore.State{"CVE-2026-7010": vulnstore.StateOpen,
				"CVE-2026-7011": vulnstore.StateFixed, "CVE-2026-7012": vulnstore.StateOpen},
			closed: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newVTEnv(t)
			t0 := e.clk.Now()
			clsRunCovering(t, e,
				clsRecord("CVE-2026-7010", "openssl", clsOld, ""),
				clsRecord("CVE-2026-7011", "openssl", clsOld, clsNew),
				clsRecord("CVE-2026-7012", "linux", "6.1.119-1", "6.1.120-1"),
			)
			var buf bytes.Buffer
			svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: t0.Add(2 * time.Minute)},
				slog.New(slog.NewTextHandler(&buf, nil)))
			if err != nil {
				t.Fatal(err)
			}
			svc.setCloser(e.svc.store)
			svc.ObserveInstalled(context.Background(), clsHost, "exec-inv-1", t0.Add(time.Minute), installedEnvelope(t, tt.installed(t), false))

			fs, err := e.svc.store.SubjectFindings(context.Background(), vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost})
			if err != nil {
				t.Fatal(err)
			}
			if len(fs) != len(tt.want) {
				t.Fatalf("findings = %d, want %d", len(fs), len(tt.want))
			}
			for _, f := range fs {
				cve := f.Record.Vuln.ID
				if f.State != tt.want[cve] {
					t.Fatalf("%s state = %s, want %s", cve, f.State, tt.want[cve])
				}
				if f.State == vulnstore.StateFixed && f.ClosedBy != vulnstore.ClosedByNOSInventory {
					t.Fatalf("%s closed by %s, want nos_inventory", cve, f.ClosedBy)
				}
			}
			if !strings.Contains(buf.String(), fmt.Sprintf("closed=%d", tt.closed)) || !strings.Contains(buf.String(), "vuln_closed_by_inventory") {
				t.Fatalf("no audit line with the closed count: %s", buf.String())
			}
		})
	}
}

// TestPartialInventoryReadClosesNothing: an incomplete read closes no finding
// by inventory, even one whose package it does not name.
func TestPartialInventoryReadClosesNothing(t *testing.T) {
	e := newVTEnv(t)
	t0 := e.clk.Now()
	f := clsFinding(t, e, clsRecord("CVE-2026-7013", "openssl", clsOld, ""))
	svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: t0.Add(2 * time.Minute)},
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	svc.setCloser(e.svc.store)
	svc.ObserveInstalled(context.Background(), clsHost, "exec-inv-2", t0.Add(time.Minute), installedEnvelope(t, debian12Text(t), true))
	got, err := e.svc.store.Get(context.Background(), f.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != vulnstore.StateOpen {
		t.Fatalf("state = %s after a partial read, want open", got.State)
	}
}

// TestClassifierErrorsOnlyForHostsWithoutInventory: an unassessable subject
// is unconfirmed without reading the inventory; a host without any read is
// an error, which holds the closure.
func TestClassifierErrorsOnlyForHostsWithoutInventory(t *testing.T) {
	e := newVTEnv(t)
	f := vulnstore.Finding{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectDevice, ID: "router1"},
		Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchDistroTracker, Ecosystem: "debian:bookworm"}}
	if _, err := e.svc.classifier.Classify(context.Background(), f); err != nil {
		t.Fatalf("device Classify err = %v, want none", err)
	}
	host := vulnstore.Finding{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost},
		Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchDistroTracker, Ecosystem: "debian:bookworm",
			Component: vulnfinding.Component{SourcePackage: "openssl", SourceVersion: clsOld}}}
	if _, err := e.svc.classifier.Classify(context.Background(), host); !errors.Is(err, errVulnNoInventory) {
		t.Fatalf("host Classify err = %v, want errVulnNoInventory", err)
	}
}
