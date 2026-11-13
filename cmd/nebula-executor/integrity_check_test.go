// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
)

func TestSetupIntegrityCheckWiresLoop(t *testing.T) {
	svc := &executor.Service{}
	var buf bytes.Buffer
	loop := setupIntegrityCheck(svc, t.TempDir(), t.TempDir(), slog.New(slog.NewJSONHandler(&buf, nil)))
	if loop == nil {
		t.Fatalf("loop not wired: %s", buf.String())
	}
	if st := svc.IntegrityCheckStatus(); !st.Configured || st.Lock.Open {
		t.Fatalf("status = %+v", st)
	}
	// A canceled context ends the loop without a run.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	loop(ctx)
	if st := svc.IntegrityCheckStatus(); st.Total != 0 {
		t.Fatalf("runs after canceled loop = %d", st.Total)
	}
}

func TestSetupIntegrityCheckFailureIsLoggedNotFatal(t *testing.T) {
	svc := &executor.Service{}
	var buf bytes.Buffer
	if loop := setupIntegrityCheck(svc, "relative/dir", "/", slog.New(slog.NewJSONHandler(&buf, nil))); loop != nil {
		t.Fatal("loop wired with a relative state path")
	}
	if !strings.Contains(buf.String(), "integrity check unavailable") {
		t.Fatalf("log = %s", buf.String())
	}
}
