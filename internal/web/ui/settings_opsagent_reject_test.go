// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsconfig"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// opsRecovery is the recovery state the TOTP status reports. A test changes
// it between begin and commit to model a recovery login that starts later.
type opsRecovery struct {
	pending bool
	// unknown makes the status read fail.
	unknown bool
}

// opsAgentHandlerRecovery builds the handler with a TOTP status that reads
// rec on every request.
func opsAgentHandlerRecovery(t *testing.T, ops *fakeOpsAgent, rec *opsRecovery) http.Handler {
	t.Helper()
	totp := func(context.Context) (*pb.GetTOTPStatusResponse, error) {
		if rec.unknown {
			return nil, errors.New("executor down")
		}
		return &pb.GetTOTPStatusResponse{Configured: true, Activated: true, RecoveryPending: rec.pending}, nil
	}
	clock := &opsAgentClock{t: vulnNow}
	return newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, OpsAgent: ops, TOTPStatus: totp,
		Now: func() time.Time { return clock.now() }}).Handler()
}

// A non-maintainer cannot begin a change: the request is refused before any
// backend call. A removal of the maintainer check would fail this test.
func TestOpsAgentBeginRefusedForNonMaintainer(t *testing.T) {
	ops := opsAgentFixture(false)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	if code, _ := vulnPost(t, h, opsBegin, opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })); code != http.StatusForbidden {
		t.Fatalf("begin as non-maintainer = %d, want 403", code)
	}
	if len(ops.begun) != 0 {
		t.Fatal("a non-maintainer's change reached the backend")
	}
}

// The maintainer role is re-checked at commit: a challenge begun as the
// maintainer does not commit once the user no longer holds the role.
func TestOpsAgentCommitRefusedWhenMaintainerRoleIsGone(t *testing.T) {
	ops := opsAgentFixture(true)
	h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
	body := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
	id := beginOpsAgent(t, h, body)
	ops.maintainer = false
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusForbidden {
		t.Fatalf("commit as non-maintainer = %d, want 403", code)
	}
	if len(ops.committed) != 0 {
		t.Fatal("a non-maintainer's commit was stored")
	}
}

// A recovery login that starts between begin and commit refuses the commit,
// even with a valid assertion for the bound change.
func TestOpsAgentCommitRefusedWhenRecoveryStartsAfterBegin(t *testing.T) {
	ops := opsAgentFixture(true)
	rec := &opsRecovery{}
	h := opsAgentHandlerRecovery(t, ops, rec)
	body := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
	id := beginOpsAgent(t, h, body)
	rec.pending = true
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusForbidden {
		t.Fatalf("commit during a recovery login = %d, want 403", code)
	}
	if len(ops.committed) != 0 {
		t.Fatal("a change was stored during a recovery login")
	}
}

// An unreadable recovery status at commit refuses the change as well.
func TestOpsAgentCommitRefusedWhenRecoveryStatusBecomesUnknown(t *testing.T) {
	ops := opsAgentFixture(true)
	rec := &opsRecovery{}
	h := opsAgentHandlerRecovery(t, ops, rec)
	body := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
	id := beginOpsAgent(t, h, body)
	rec.unknown = true
	if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != http.StatusServiceUnavailable {
		t.Fatalf("commit with unknown recovery status = %d, want 503", code)
	}
	if len(ops.committed) != 0 {
		t.Fatal("a change was stored with unknown recovery status")
	}
}

// Without any recovery status source the state is unknown: begin is refused
// and the page says so instead of offering the form.
func TestOpsAgentChangeRefusedWithoutRecoveryStatusSource(t *testing.T) {
	ops := opsAgentFixture(true)
	h := newTestHandler(t, ui.Options{PublicOrigin: leaseOrigin, OpsAgent: ops}).Handler()
	if code, _ := vulnPost(t, h, opsBegin, opsAgentBody(nil)); code != http.StatusServiceUnavailable {
		t.Fatalf("begin with nil recovery status = %d, want 503", code)
	}
	if len(ops.begun) != 0 {
		t.Fatal("a change without a recovery status source reached the backend")
	}
	if body := getBody(t, h, "/settings"); !strings.Contains(body, "could not be read: ops agent changes are refused") {
		t.Error("settings page does not say that the recovery status is unknown")
	}
}

// The backend's commit errors map to fixed statuses; a stale version and an
// invalid input are not reported as a backend failure (502).
func TestOpsAgentCommitBackendErrorsAreMapped(t *testing.T) {
	cases := map[string]struct {
		err  error
		want int
	}{
		"stale version":      {fmt.Errorf("save: %w", opsconfig.ErrStale), http.StatusConflict},
		"invalid input":      {fmt.Errorf("save: %w", opsconfig.ErrInvalidInput), http.StatusBadRequest},
		"not maintainer":     {ui.ErrOpsAgentNotMaintainer, http.StatusForbidden},
		"assertion refused":  {ui.ErrOpsAgentAssertionRefused, http.StatusForbidden},
		"unexpected failure": {errors.New("db locked"), http.StatusBadGateway},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ops := opsAgentFixture(true)
			ops.saveErr = tc.err
			h := opsAgentHandler(t, ops, nil, &opsAgentClock{t: vulnNow}, false)
			body := opsAgentBody(func(m map[string]any) { m["model"] = "llama3.1-8b" })
			id := beginOpsAgent(t, h, body)
			if code, _ := vulnPost(t, h, opsCommit, `{"id":"`+id+`","assertion":`+opsAgentAssertion(t, body)+`}`); code != tc.want {
				t.Fatalf("commit with backend error %v = %d, want %d", tc.err, code, tc.want)
			}
			if len(ops.committed) != 0 {
				t.Fatal("a change with a failed backend commit was recorded as stored")
			}
		})
	}
}
