// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
	"golang.org/x/sys/unix"
)

// Only the document's own invalidity or the store's refusal as stale may
// delete a file. Every other ingest error, also one that comes with an empty
// report, says nothing about the observation.
func TestImporterDeletesOnlyForInvalidOrStaleIngestErrors(t *testing.T) {
	failed := map[string]error{"tasks": errors.New("injected-store-failure")}
	cases := []struct {
		name   string
		report pveinventory.IngestReport
		err    error
		check  func(ImportReport) bool
		kept   bool
	}{
		{
			name:  "validation sentinel",
			err:   fmt.Errorf("pveinventory: ingest: %w", pvecontract.ErrInvalid),
			check: func(r ImportReport) bool { return r.Rejected == 1 },
		},
		{
			name:  "validation error type",
			err:   &pvecontract.ValidationError{},
			check: func(r ImportReport) bool { return r.Rejected == 1 },
		},
		{
			name:  "stale",
			err:   pveinventory.ErrStaleObservation,
			check: func(r ImportReport) bool { return r.Replayed == 1 },
		},
		{
			name:  "unknown error with an empty report",
			err:   errors.New("injected-store-failure"),
			check: func(r ImportReport) bool { return r.Partial == 1 && r.Rejected == 0 },
			kept:  true,
		},
		{
			name:   "dataset failure",
			report: pveinventory.IngestReport{Errors: failed},
			err:    errors.New("injected-store-failure"),
			check:  func(r ImportReport) bool { return r.Partial == 1 && r.Rejected == 0 },
			kept:   true,
		},
		{
			name:   "invalid text from a dataset failure",
			report: pveinventory.IngestReport{Errors: failed},
			err:    fmt.Errorf("pveinventory: ingest: %w", pvecontract.ErrInvalid),
			check:  func(r ImportReport) bool { return r.Partial == 1 && r.Rejected == 0 },
			kept:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			im, spool, _, _, _ := newRetryImporter(t)
			ctx := context.Background()
			oneObservation(t, spool)
			im.ingest = func(context.Context, pvecontract.Observation) (pveinventory.IngestReport, error) {
				return tc.report, tc.err
			}

			rep, err := im.ImportOnce(ctx)
			if err != nil {
				t.Fatalf("ImportOnce: %v", err)
			}
			if !tc.check(rep) {
				t.Fatalf("report = %+v", rep)
			}
			names, err := spool.List(ctx)
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if kept := len(names) == 1; kept != tc.kept {
				t.Fatalf("spool = %v, want kept = %v", names, tc.kept)
			}
			if len(im.stuck) != 0 {
				t.Fatalf("stuck = %v, want a kept file left out", im.stuck)
			}
		})
	}
}

// A real permission error from the kernel goes through the unmodified readAt:
// the file is unjudged, so it stays and imports once it can be read.
func TestImporterKeepsFileReadAtCannotOpen(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	im, spool, store, _, _ := newRetryImporter(t)
	ctx := context.Background()
	oneObservation(t, spool)
	names, err := spool.List(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("List = %v, %v", names, err)
	}
	path := filepath.Join(spool.ResultsDir(), names[0])
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}

	_, err = readAt(spool.resultsDir, names[0], maxSpoolFileBytes)
	if !errors.Is(err, unix.EACCES) {
		t.Fatalf("readAt = %v, want EACCES", err)
	}
	if fileFault(err) {
		t.Fatalf("fileFault(%v) = true, want an unjudged file", err)
	}
	_, err = spool.ReadFile(ctx, names[0])
	if !errors.Is(err, unix.EACCES) || errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("ReadFile = %v, want EACCES alone", err)
	}

	rep, err := im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Failed != 1 || rep.Rejected != 0 || rep.Imported != 0 {
		t.Fatalf("report = %+v, want 1 failed", rep)
	}
	if left, _ := spool.List(ctx); len(left) != 1 {
		t.Fatalf("spool = %v, want the file kept", left)
	}
	if len(im.stuck) != 0 {
		t.Fatalf("stuck = %v, want an unread file left out", im.stuck)
	}

	if err := os.Chmod(path, spoolFileMode); err != nil {
		t.Fatal(err)
	}
	rep, err = im.ImportOnce(ctx)
	if err != nil {
		t.Fatalf("ImportOnce: %v", err)
	}
	if rep.Imported != 1 || rep.Failed != 0 {
		t.Fatalf("retry = %+v, want 1 imported", rep)
	}
	if _, err := store.GetRemote(ctx, "remote-a"); err != nil {
		t.Fatalf("GetRemote: %v", err)
	}
}
