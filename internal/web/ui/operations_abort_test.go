// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
)

const (
	abortOrigin = "https://nebula.example.org"
	idB         = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a01"
	idC         = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a02"
	idD         = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a03"
	// selectionMax is the most operations one abort request names (the
	// handler's limit, pinned here).
	selectionMax = 100
	// formMax is the form body limit (the handler's limit, pinned here).
	formMax = 4 << 10
)

// distinctIDs returns n different well-formed operation IDs.
func distinctIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b%04x", i)
	}
	return out
}

// postAbortForm posts the form the way the browser does and returns the
// status and the body.
func postAbortForm(t *testing.T, h http.Handler, form url.Values, origin string) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/operations/abort/form", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// TestAbortFormRejectsForeignOrMissingOrigin: the abort is a state
// change, so the security middleware refuses a POST without this
// server's Origin before the handler runs.
func TestAbortFormRejectsForeignOrMissingOrigin(t *testing.T) {
	f := &fakeOps{}
	h := middleware.Handler(middleware.Options{PublicOrigin: abortOrigin}, opsHandler(t, f, nil))
	form := url.Values{"id": {opID}}
	for _, origin := range []string{"", "https://evil.example.net", "null"} {
		if code, _ := postAbortForm(t, h, form, origin); code != http.StatusForbidden {
			t.Errorf("origin %q: status %d, want 403", origin, code)
		}
	}
	if len(f.gates) != 0 {
		t.Fatalf("refused posts reached the service: %v", f.gates)
	}
	if code, body := postAbortForm(t, h, form, abortOrigin); code != http.StatusOK || !strings.Contains(body, "aborted") {
		t.Fatalf("own origin: %d %s", code, body)
	}
	if want := []string{"abort " + opID}; !reflect.DeepEqual(f.gates, want) {
		t.Fatalf("gates %v, want %v", f.gates, want)
	}
}

// TestAbortFormAnswersEachRowWithItsOwnError: a mixed selection aborts
// what can be aborted and reports every other row with its reason, in
// the wording of the staged endpoints. Malformed IDs never reach the
// service.
func TestAbortFormAnswersEachRowWithItsOwnError(t *testing.T) {
	f := &fakeOps{abortErrs: map[string]error{
		idB: executions.ErrNotStaged,
		idC: executions.ErrNotFound,
		idD: status.Error(codes.FailedPrecondition, "lock held"),
	}}
	h := opsHandler(t, f, nil)
	form := url.Values{"id": {opID, idB, idC, idD, "not an id"}}
	code, body := postAbortForm(t, h, form, abortOrigin)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	want := []string{"abort " + opID, "abort " + idB, "abort " + idC, "abort " + idD}
	if !reflect.DeepEqual(f.gates, want) {
		t.Fatalf("gates %v, want %v", f.gates, want)
	}
	for _, msg := range []string{"aborted", "the execution has no stages", "operation not found", "the executor refused: lock held", "invalid operation id"} {
		if !strings.Contains(body, msg) {
			t.Errorf("result misses %q: %s", msg, body)
		}
	}
	if strings.Count(body, "the execution has no stages") != 1 {
		t.Errorf("the error should appear on its own row only: %s", body)
	}
}

// TestAbortFormHidesExecutorInternals: an error that is not an executor
// refusal is answered with a fixed text, not with its message.
func TestAbortFormHidesExecutorInternals(t *testing.T) {
	f := &fakeOps{abortErrs: map[string]error{opID: errors.New("socket /run/secret.sock: refused")}}
	code, body := postAbortForm(t, opsHandler(t, f, nil), url.Values{"id": {opID}}, abortOrigin)
	if code != http.StatusOK || !strings.Contains(body, "executor unavailable") || strings.Contains(body, "secret") {
		t.Fatalf("status %d, body %s", code, body)
	}
}

// TestAbortFormLimitsTheSelection: an empty or oversized selection and a
// body beyond the form limit are refused before the service is called.
func TestAbortFormLimitsTheSelection(t *testing.T) {
	f := &fakeOps{}
	h := opsHandler(t, f, nil)
	if code, _ := postAbortForm(t, h, url.Values{}, abortOrigin); code != http.StatusBadRequest {
		t.Errorf("no ids: status %d, want 400", code)
	}
	many := url.Values{"id": distinctIDs(selectionMax + 1)}
	if code, _ := postAbortForm(t, h, many, abortOrigin); code != http.StatusBadRequest {
		t.Errorf("%d ids: status %d, want 400", selectionMax+1, code)
	}
	huge := url.Values{"id": {strings.Repeat("x", formMax)}}
	if code, _ := postAbortForm(t, h, huge, abortOrigin); code != http.StatusRequestEntityTooLarge {
		t.Errorf("huge body: status %d, want 413", code)
	}
	if len(f.gates) != 0 {
		t.Fatalf("rejected selections reached the service: %v", f.gates)
	}
}

// TestAbortConfirmPageOffersOnlyAbortableRows: the confirmation page
// carries a hidden field for each row that can be aborted and says why
// the others are not in the choice. It is a GET and changes nothing.
func TestAbortConfirmPageOffersOnlyAbortableRows(t *testing.T) {
	f := &fakeOps{abortable: map[string]bool{opID: true}}
	h := opsHandler(t, f, nil)
	body := getBody(t, h, "/operations/abort/confirm?id="+opID+"&id="+idB)
	if !strings.Contains(body, `<input type="hidden" name="id" value="`+opID+`">`) {
		t.Fatalf("abortable row not offered: %s", body)
	}
	if strings.Contains(body, `name="id" value="`+idB+`"`) {
		t.Fatalf("row that cannot be aborted is submitted: %s", body)
	}
	if !strings.Contains(body, "cannot be aborted") || !strings.Contains(body, `action="/operations/abort/form"`) {
		t.Fatalf("confirm page misses the reason or the form: %s", body)
	}
	if strings.Contains(body, "data-fetch") {
		t.Errorf("the confirmation form must post without script: %s", body)
	}
	if len(f.gates) != 0 {
		t.Fatalf("GET aborted something: %v", f.gates)
	}
}

// TestAbortConfirmWithNothingAbortable: no submit form when no row can
// be aborted.
func TestAbortConfirmWithNothingAbortable(t *testing.T) {
	h := opsHandler(t, &fakeOps{}, nil)
	body := getBody(t, h, "/operations/abort/confirm?id="+idB)
	if strings.Contains(body, `action="/operations/abort/form"`) || !strings.Contains(body, "cannot be aborted") {
		t.Fatalf("page: %s", body)
	}
}

// TestAbortConfirmRejectsBadSelections: no IDs, a malformed ID and too
// many IDs are bad requests.
func TestAbortConfirmRejectsBadSelections(t *testing.T) {
	h := opsHandler(t, &fakeOps{}, nil)
	many := "/operations/abort/confirm?"
	for _, id := range distinctIDs(selectionMax + 1) {
		many += "id=" + id + "&"
	}
	for _, p := range []string{"/operations/abort/confirm", "/operations/abort/confirm?id=bad", many} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %.60s: status %d, want 400", p, rec.Code)
		}
	}
}

// TestAbortControlsOnlyOnAbortableListRows: the list shows a button and
// a checkbox for rows that can be aborted and nothing for the others.
func TestAbortControlsOnlyOnAbortableListRows(t *testing.T) {
	t0 := time.Unix(1791960000, 0)
	f := &fakeOps{
		list: []executions.Summary{
			{ID: opID, ActionID: "core.facts", Risk: "HIGH", State: "running", CreatedBy: "axel", CreatedAt: t0, Hosts: 2},
			// Another second: read-only rows created together are grouped.
			{ID: idB, ActionID: "core.facts", Risk: "HIGH", State: "finished", CreatedBy: "axel", CreatedAt: t0.Add(time.Second), Hosts: 1},
		},
		abortable: map[string]bool{opID: true},
	}
	body := getBody(t, opsHandler(t, f, nil), "/operations")
	for _, want := range []string{
		`href="/operations/abort/confirm?id=` + opID + `"`,
		`<input type="checkbox" name="id" value="` + opID + `"`,
		`action="/operations/abort/confirm"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list misses %q", want)
		}
	}
	if strings.Contains(body, `abort/confirm?id=`+idB) || strings.Contains(body, `value="`+idB+`"`) {
		t.Errorf("finished row offers an abort: %s", body)
	}
}
