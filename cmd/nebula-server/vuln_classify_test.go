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

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
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
	// clsIncomparable is a version the store keeps but no scheme compares:
	// its epoch is not a number.
	clsIncomparable = "x:3.0.15-1"
)

// clsLag is how long after a finding's write a complete read must finish
// before it can evidence the finding: the classifier's listing lag. Fixtures
// that expect evidence read at clsLag or later after the write.
const clsLag = vulnListLag

// clsSettle advances the clock past the listing lag of the write just made,
// so that a read finishing clsLag after that write is within the store's clock
// tolerance (vulninventory.MaxReadSkew). Reads are then placed relative to the
// write's time (finding.Updated), not to the clock.
func clsSettle(e *vtEnv) {
	e.clk.Add(clsLag + 2*time.Minute)
}

// clsClockBack is how far clsEnv moves the test clock behind the real time.
// The store refuses a read that finishes more than vulninventory.MaxReadSkew
// after the real clock (not the test clock), so writes must sit far enough in
// the past for a read finishing a listing lag after them to be accepted.
const clsClockBack = 15 * time.Minute

// clsEnv is newVTEnv with the test clock moved clsClockBack into the past.
func clsEnv(t *testing.T) *vtEnv {
	t.Helper()
	e := newVTEnv(t)
	e.clk.Add(-clsClockBack)
	return e
}

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

// clsFailure is a read-failure marker of clsHost: no components, no kernel
// data and no ecosystem, as the observer stores a list it could not read.
func clsFailure(exec string, at time.Time, reason string) vulninventory.Read {
	return vulninventory.Read{HostID: clsHost, ExecutionID: exec, ReadAt: at, Reason: reason}
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
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassEvidenced, wantNOS: clsNew,
		},
		{
			name: "row 2 evidenced: complete read after the write no longer names the component",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassEvidenced,
		},
		{
			name: "contradicted: newest complete read below the fixed version",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld))}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "contradicted by a newer partial read that still names the old version",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "newer partial read without the component: last complete basis contradicts",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "newer partial read without the component: last complete fixed version evidences",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
				}
			},
			want: vulnstore.ClassEvidenced, wantNOS: clsNew,
		},
		{
			name: "no fixed version: a newer partial read still naming the package holds row 2",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)),
				}
			},
			want: vulnstore.ClassUnconfirmedUnchanged, wantNOS: clsOld,
		},
		{
			name: "fixed version: a newer partial read still naming the package at the fix holds row 2",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)),
				}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: clsNew,
		},
		{
			name: "read finished inside the listing lag of the write does not evidence",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name: "complete read without ecosystem holds",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				r := clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))
				r.Ecosystem = ""
				return []vulninventory.Read{r}
			},
			wantErr: true,
		},
		{
			name: "partial read without ecosystem naming the package holds",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				r := clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsOld))
				r.Ecosystem = ""
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")), r}
			},
			wantErr: true,
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
			name: "partial newest read naming the fixed version without a complete read holds",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			wantErr: true,
		},
		{
			name: "only a partial read not naming the component holds like no read",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			wantErr: true,
		},
		{
			name: "only failure markers hold like no read",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsFailure("r1", t0.Add(clsLag+time.Minute), vulninventory.ReasonRefused)}
			},
			wantErr: true,
		},
		{
			name: "failure marker after a complete read keeps the contradiction",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)),
					clsFailure("r2", t0.Add(clsLag+2*time.Minute), vulninventory.ReasonStoreUnavailable),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: clsOld,
		},
		{
			name: "read in the same second as the write does not evidence",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0, true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: clsNew,
		},
		{
			name: "row 2 in the same second as the write does not evidence",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0, true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name: "newest read from another ecosystem holds",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				r := clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))
				r.Ecosystem = "debian:trixie"
				return []vulninventory.Read{r}
			},
			wantErr: true,
		},
		{
			name: "last complete read from another ecosystem holds even when a partial read names the component",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				r := clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))
				r.Ecosystem = "debian:trixie"
				return []vulninventory.Read{r,
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("openssl", clsOld))}
			},
			wantErr: true,
		},
		{
			// clsIncomparable passes the store's version pattern but is not
			// a dpkg version (its epoch is not a number).
			name: "incomparable installed version holds against the fixed version",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsIncomparable))}
			},
			wantErr: true,
		},
		{
			name: "incomparable installed version in the last complete read holds",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, clsNew),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsIncomparable)),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
				}
			},
			wantErr: true,
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
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld))}
			},
			want: vulnstore.ClassUnconfirmedUnchanged, wantNOS: clsOld,
		},
		{
			name: "no fixed version and a changed basis is unconfirmed",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: clsNew,
		},
		{
			name: "no fixed version and the package removed is evidenced by row 2",
			rec:  clsRecord("CVE-2026-7001", "openssl", clsOld, ""),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassEvidenced,
		},
		{
			name: "kernel: mapped running kernel at the fixed version is evidenced",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.120-1"))}
			},
			want: vulnstore.ClassEvidenced, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: mapped running kernel below the fixed version is contradicted",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"))}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
		{
			name: "kernel: a newer partial read at the fixed version over an older complete read below it is unconfirmed",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.120-1")),
				}
			},
			want: vulnstore.ClassUnconfirmed, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: a newer partial read at the fixed version over an older complete read at the fix is evidenced",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.120-1")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.120-1")),
				}
			},
			want: vulnstore.ClassEvidenced, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: a newer complete read at the fixed version over an older complete read below it is evidenced",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), true, clsKernel("6.1.120-1"), clsComp("zlib", "1.2.13")),
				}
			},
			want: vulnstore.ClassEvidenced, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: a newer partial read below the fix contradicts a complete read at the fix",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.120-1")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsKernel("6.1.119-1")),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
		{
			name: "kernel: a newer complete read below the fix contradicts a complete read at the fix",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.120-1")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
		{
			name: "kernel: a newer partial read with an unmapped kernel does not evidence",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.120-1")),
					clsRead("r2", t0.Add(clsLag+2*time.Minute), false, clsUnmappedKernel),
				}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name: "kernel: only a partial read holds like no read",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), false, clsKernel("6.1.120-1"))}
			},
			wantErr: true,
		},
		{
			name: "kernel: failure marker after a complete read below the fix stays contradicted",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1")),
					clsFailure("r2", t0.Add(clsLag+2*time.Minute), vulninventory.ReasonRefused),
				}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
		{
			name: "kernel: failure marker after a complete read at the fix is evidenced",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{
					clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.120-1")),
					clsFailure("r2", t0.Add(clsLag+2*time.Minute), vulninventory.ReasonFactsOlder),
				}
			},
			want: vulnstore.ClassEvidenced, wantNOS: "6.1.120-1",
		},
		{
			name: "kernel: complete read without kernel data holds",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, vulninventory.Kernel{}, clsComp("openssl", clsNew))}
			},
			wantErr: true,
		},
		{
			name: "kernel: an unmapped running kernel is unconfirmed",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsUnmappedKernel, clsComp("openssl", clsNew))}
			},
			want: vulnstore.ClassUnconfirmed,
		},
		{
			name: "kernel: a complete read without the kernel package never evidences",
			rec:  clsRecord("CVE-2026-7002", "linux", "6.1.119-1", "6.1.120-1"),
			reads: func(t0 time.Time) []vulninventory.Read {
				return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
			},
			want: vulnstore.ClassContradicted, wantNOS: "6.1.119-1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := clsEnv(t)
			f := clsFinding(t, e, tt.rec)
			clsSettle(e)
			for _, r := range tt.reads(f.Updated) {
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
	e := clsEnv(t)
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
	e := clsEnv(t)
	f := clsFinding(t, e, clsRecord("CVE-2026-7003", "openssl", clsOld, clsNew))
	clsSettle(e)
	clsPut(t, e, clsRead("r1", f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
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
	e := clsEnv(t)
	f := clsFinding(t, e, clsRecord("CVE-2026-7004", "openssl", clsOld, clsNew))
	clsSettle(e)
	clsPut(t, e, clsRead("r1", f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)))
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
			e := clsEnv(t)
			t0 := e.clk.Now()
			clsRunCovering(t, e,
				clsRecord("CVE-2026-7010", "openssl", clsOld, ""),
				clsRecord("CVE-2026-7011", "openssl", clsOld, clsNew),
				clsRecord("CVE-2026-7012", "linux", "6.1.119-1", "6.1.120-1"),
			)
			clsSettle(e)
			var buf bytes.Buffer
			svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: t0.Add(clsLag + 2*time.Minute)},
				slog.New(slog.NewTextHandler(&buf, nil)))
			if err != nil {
				t.Fatal(err)
			}
			svc.setCloser(e.svc.store)
			svc.ObserveInstalled(context.Background(), clsHost, "exec-inv-1", t0.Add(clsLag+time.Minute).Add(-time.Minute), t0.Add(clsLag+time.Minute), installedEnvelope(t, tt.installed(t), false))

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
	e := clsEnv(t)
	t0 := e.clk.Now()
	f := clsFinding(t, e, clsRecord("CVE-2026-7013", "openssl", clsOld, ""))
	clsSettle(e)
	svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: t0.Add(clsLag + 2*time.Minute)},
		slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	svc.setCloser(e.svc.store)
	svc.ObserveInstalled(context.Background(), clsHost, "exec-inv-2", t0.Add(clsLag+time.Minute).Add(-time.Minute), t0.Add(clsLag+time.Minute), installedEnvelope(t, debian12Text(t), true))
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
	e := clsEnv(t)
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

// TestInventoryReadClosesNothingAtTheWriteSecondAndOfAnotherRelease: a complete
// read taken in the same second as the finding's last write is no evidence
// of it (D5: strictly newer), and a read of another release than the
// finding's ecosystem is no basis for it either. Both leave the finding open.
// The other-release case has a positive control with the finding's release,
// which closes the same absent package.
func TestInventoryReadClosesNothingAtTheWriteSecondAndOfAnotherRelease(t *testing.T) {
	t.Run("read in the same second as the write", func(t *testing.T) {
		e := clsEnv(t)
		t0 := e.clk.Now()
		clsRunCovering(t, e, clsRecord("CVE-2026-7020", "openssl", clsOld, clsNew))
		svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: t0},
			slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		svc.setCloser(e.svc.store)
		svc.ObserveInstalled(context.Background(), clsHost, "exec-inv-3", t0.Add(-time.Minute), t0, installedEnvelope(t, debian12Text(t), false))
		fs, err := e.svc.store.SubjectFindings(context.Background(), vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost})
		if err != nil || len(fs) != 1 {
			t.Fatalf("findings = %d, %v; want one", len(fs), err)
		}
		if fs[0].State != vulnstore.StateOpen {
			t.Fatalf("state = %s, want open", fs[0].State)
		}
	})
	t.Run("read finished inside the listing lag of the write", func(t *testing.T) {
		// The list may have been taken before the write, although the read
		// finished a minute after it: the close must hold.
		e := clsEnv(t)
		t0 := e.clk.Now()
		f := clsFinding(t, e, clsRecord("CVE-2026-7023", "openssl", clsOld, clsNew))
		svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: t0.Add(time.Minute)},
			slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		svc.setCloser(e.svc.store)
		svc.ObserveInstalled(context.Background(), clsHost, "exec-inv-4", t0, t0.Add(time.Minute), installedEnvelope(t, debian12Text(t), false))
		got, err := e.svc.store.Get(context.Background(), f.Key)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != vulnstore.StateOpen {
			t.Fatalf("state = %s, want open", got.State)
		}
	})
	t.Run("read of another release than the finding", func(t *testing.T) {
		for _, tt := range []struct {
			eco  string
			want vulnstore.State
		}{
			{"debian:trixie", vulnstore.StateOpen},
			{"debian:bookworm", vulnstore.StateFixed}, // control: same release closes
		} {
			e := clsEnv(t)
			t0 := e.clk.Now()
			f := clsFinding(t, e, clsRecord("CVE-2026-7021", "openssl", clsOld, clsNew))
			read := vulnstore.InventoryRead{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost},
				Complete: true, ReadAt: t0.Add(clsLag + time.Minute), Ecosystem: tt.eco,
				SourceVersions: map[string]string{"zlib": "1.2.13"}}
			closed, err := e.svc.store.CloseByInventory(context.Background(), read)
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.svc.store.Get(context.Background(), f.Key)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tt.want {
				t.Fatalf("eco %s: state = %s (closed %d), want %s", tt.eco, got.State, len(closed), tt.want)
			}
		}
	})
}

// TestClassifyMalformedFixedVersionHolds: a fixed version that does not parse
// holds the closure whatever the reads say, including when the package is gone
// (D5, fail closed). Hermes rejects such a version at submit, so the
// classifier is called on a finding with the version set directly.
func TestClassifyMalformedFixedVersionHolds(t *testing.T) {
	tests := []struct {
		name  string
		reads func(t0 time.Time) []vulninventory.Read
	}{
		{"package gone", func(t0 time.Time) []vulninventory.Read {
			return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))}
		}},
		{"installed at the fixed version", func(t0 time.Time) []vulninventory.Read {
			return []vulninventory.Read{clsRead("r1", t0.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew))}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := clsEnv(t)
			f := clsFinding(t, e, clsRecord("CVE-2026-7022", "openssl", clsOld, clsNew))
			clsSettle(e)
			for _, r := range tt.reads(f.Updated) {
				clsPut(t, e, r)
			}
			f.EpisodeFixedVersion = clsIncomparable
			if _, err := e.svc.classifier.Classify(context.Background(), f); err == nil {
				t.Fatal("Classify returned no error for a malformed episode fixed version")
			}
		})
	}
}

// TestVulnListLagCoversTheListTimeout: the listing lag must cover the whole
// run of package.list_installed, or a list could be taken before a write the
// lag is meant to order it after.
func TestVulnListLagCoversTheListTimeout(t *testing.T) {
	a, ok := actions.Lookup("package.list_installed")
	if !ok {
		t.Fatal("package.list_installed is not registered")
	}
	if vulnListLag < a.Timeout {
		t.Fatalf("vulnListLag = %s, shorter than the action timeout %s", vulnListLag, a.Timeout)
	}
}

// TestCloseByInventoryHoldsReadWithoutEcosystem: a complete read stored
// without an ecosystem is no basis for closing (fail closed). With the
// ecosystem set the same read closes the absent package (control).
func TestCloseByInventoryHoldsReadWithoutEcosystem(t *testing.T) {
	for _, tt := range []struct {
		eco  string
		want vulnstore.State
	}{
		{"", vulnstore.StateOpen},
		{"debian:bookworm", vulnstore.StateFixed}, // control
	} {
		t.Run("ecosystem "+tt.eco, func(t *testing.T) {
			e := clsEnv(t)
			f := clsFinding(t, e, clsRecord("CVE-2026-7024", "openssl", clsOld, clsNew))
			clsSettle(e)
			svc, err := newVulnInventoryService(e.db, staticFacts{result: factsResult(t, debian12Release), at: e.clk.Now()},
				slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
			if err != nil {
				t.Fatal(err)
			}
			svc.setCloser(e.svc.store)
			r := clsRead("exec-inv-5", f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("zlib", "1.2.13"))
			r.Ecosystem = tt.eco
			svc.closeByInventory(context.Background(), context.Background(), clsHost, "exec-inv-5", r)
			got, err := e.svc.store.Get(context.Background(), f.Key)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != tt.want {
				t.Fatalf("state = %s, want %s", got.State, tt.want)
			}
		})
	}
}

// TestVulnClassifyPairsLatestAndLastCompleteFromOneState: a read stored between
// the newest read and the last complete read must not pair stale and new data.
// The classifier re-reads the newest read after the complete read and retries
// when it moved, so the basis is the state that held at one instant.
func TestVulnClassifyPairsLatestAndLastCompleteFromOneState(t *testing.T) {
	e := clsEnv(t)
	f := clsFinding(t, e, clsRecord("CVE-2026-7004", "openssl", clsOld, clsNew))
	clsSettle(e)
	clsPut(t, e, clsRead("r1", f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	st, err := vulninventory.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	inserted := false
	c := vulnClassifier{inv: st, betweenReads: func() {
		if inserted {
			return
		}
		inserted = true
		clsPut(t, e, clsRead("r2", f.Updated.Add(clsLag+2*time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)))
	}}
	a, err := c.assess(context.Background(), f)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	// Stale pairing (r1 newest, r2 complete) would read openssl at clsOld and
	// contradict; the consistent state is r2 newest and complete, at the fix.
	if a.class != vulnstore.ClassEvidenced || a.nosVersion != clsNew {
		t.Fatalf("assess = class %d version %q, want evidenced at %q", a.class, a.nosVersion, clsNew)
	}
}

// TestVulnClassifyHoldsWhenReadsKeepMoving: when the newest read keeps moving
// between the two reads, the classifier gives up and holds (fail closed).
func TestVulnClassifyHoldsWhenReadsKeepMoving(t *testing.T) {
	e := clsEnv(t)
	f := clsFinding(t, e, clsRecord("CVE-2026-7005", "openssl", clsOld, clsNew))
	clsSettle(e)
	clsPut(t, e, clsRead("r1", f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	st, err := vulninventory.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	c := vulnClassifier{inv: st, betweenReads: func() {
		n++
		clsPut(t, e, clsRead(fmt.Sprintf("m%d", n), f.Updated.Add(clsLag+time.Duration(n+1)*time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	}}
	if _, err := c.assess(context.Background(), f); !errors.Is(err, errVulnReadRace) {
		t.Fatalf("assess error = %v, want errVulnReadRace (fail closed)", err)
	}
}
