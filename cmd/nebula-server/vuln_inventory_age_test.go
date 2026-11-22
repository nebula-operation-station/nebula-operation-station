// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// TestVulnExportReadAgeHasNoTimeLimit pins decision E2 (count-based, no time
// limit; docs/implementation/vuln-inventory-decisions.md, 2026-11-20): a host
// read keeps its completeness however old it is. Reads just under and just
// over a day, and a read a year old, are all exported complete. The snapshot
// ID stays immutable: a later export call with the same ID returns the same
// subject. The clock is injected (newSrcEnv follows the real clock and Add
// moves it).
func TestVulnExportReadAgeHasNoTimeLimit(t *testing.T) {
	ages := []struct {
		name string
		age  time.Duration
	}{
		{"just under 24 h", 24*time.Hour - time.Second},
		{"just over 24 h", 24*time.Hour + time.Second},
		{"a year", 365 * 24 * time.Hour},
	}
	for _, tt := range ages {
		t.Run(tt.name, func(t *testing.T) {
			e := newSrcEnv(t)
			e.addHost(t, srcHost)
			e.addRead(t, srcRead(srcHost, "exec-1", e.clk.Now().Add(-tt.age), true, "openssl"))
			p, body := e.exportPage(t)
			if len(p.Subjects) != 1 || !p.Subjects[0].Complete {
				t.Fatalf("subjects = %+v, want one complete subject: %s", p.Subjects, body)
			}
			e.clk.Add(time.Hour)
			again, err := e.inv.VulnSnapshot(context.Background(), p.SnapshotID)
			if err != nil {
				t.Fatalf("same snapshot later: %v", err)
			}
			if len(again.Subjects) != 1 || !again.Subjects[0].Complete {
				t.Fatalf("same snapshot later = %+v, want the same complete subject", again.Subjects)
			}
		})
	}
}

// TestVulnClassifyOldCompleteReadStillBasesTheClosure: a host whose only
// read is a year old is not held for age (no time limit, E2). Its complete
// read is a basis like any other, so the classifier returns no error.
func TestVulnClassifyOldCompleteReadStillBasesTheClosure(t *testing.T) {
	e := clsEnv(t)
	at := e.clk.Now().Add(-365 * 24 * time.Hour)
	clsPut(t, e, clsRead("exec-1", at, true, clsKernel(""), clsComp("openssl", clsOld)))
	f := vulnstore.Finding{Subject: vulnstore.Subject{Kind: vulnfinding.SubjectHost, ID: clsHost},
		Record: vulnfinding.Record{MatchBasis: vulnfinding.MatchDistroTracker, Ecosystem: "debian:bookworm",
			Component: vulnfinding.Component{SourcePackage: "openssl", SourceVersion: clsOld}}}
	if _, err := e.svc.classifier.Classify(context.Background(), f); err != nil {
		t.Fatalf("Classify of a host with a year-old complete read err = %v, want none", err)
	}
}
