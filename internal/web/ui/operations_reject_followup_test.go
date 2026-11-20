// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
)

// TestRejectFormLostAnswerSaysOutcomeUnknown: when the executor's answer was
// lost, the row must not say "nothing was rejected": the executor may have
// rejected the proposal, and it is checked again by the sweep.
func TestRejectFormLostAnswerSaysOutcomeUnknown(t *testing.T) {
	f := &fakeOps{rejectErrs: map[string]error{
		idD: fmt.Errorf("%w: %w", executions.ErrRejectOutcomeUnknown, status.Error(codes.Unavailable, "connection refused")),
	}}
	e := newRejectEnv(t, f, true)
	form := url.Values{"id": {idD}, "reason": {"wrong host"}}
	code, body := e.do(t, http.MethodPost, "/operations/reject/form", form, pveOrigin, e.alice)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	want := `<a href="/operations/` + idD + `">` + idD[:8] + `</a>: outcome unknown - the executor may have rejected it; it is checked again</li>`
	if !strings.Contains(body, want) {
		t.Errorf("result misses row %q: %s", want, body)
	}
	if strings.Contains(body, "nothing was rejected") {
		t.Errorf("lost answer shown as nothing rejected: %s", body)
	}
}

// TestRejectFormStorageRefusalSaysNothingWasRejected: the executor's storage
// refusal (rolled back, nothing rejected) is shown as "nothing was rejected".
func TestRejectFormStorageRefusalSaysNothingWasRejected(t *testing.T) {
	f := &fakeOps{rejectErrs: map[string]error{
		idD: status.Error(codes.Unavailable, "storage_error: executor state store unavailable"),
	}}
	e := newRejectEnv(t, f, true)
	form := url.Values{"id": {idD}, "reason": {""}}
	code, body := e.do(t, http.MethodPost, "/operations/reject/form", form, pveOrigin, e.alice)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	want := `</a>: executor unavailable; nothing was rejected</li>`
	if !strings.Contains(body, want) {
		t.Errorf("result misses row %q: %s", want, body)
	}
	if strings.Contains(body, "outcome unknown") {
		t.Errorf("storage refusal shown as outcome unknown: %s", body)
	}
}
