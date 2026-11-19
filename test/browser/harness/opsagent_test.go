// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

func newTestOps(t *testing.T) *harnessOps {
	t.Helper()
	o, err := newHarnessOps(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// The spec relies on these step lookups: steps 1 and 2 of note 1 resolve
// (service.restart, and package.refresh as the harness's LOW action), step 4
// is not a catalog action, step 0 and unknown notes are refused.
func TestHarnessOpsStepLookup(t *testing.T) {
	o := newTestOps(t)
	ctx := context.Background()
	for _, tc := range []struct {
		note   int64
		index  int
		ok     bool
		action string
	}{
		{1, 1, true, "service.restart"},
		{1, 2, true, "package.refresh"},
		{1, 3, true, "system.reboot"},
		{1, 4, false, ""},
		{1, 0, false, ""},
		{1, 5, false, ""},
		{3, 1, false, ""},
		{99, 1, false, ""},
	} {
		st, ok, err := o.Step(ctx, tc.note, tc.index)
		if err != nil || ok != tc.ok || st.ActionID != tc.action {
			t.Errorf("Step(%d, %d) = %+v, %v, %v; want ok %v action %q", tc.note, tc.index, st, ok, err, tc.ok, tc.action)
		}
	}
}

// Dismissing hides a card and changes nothing else: the step and the
// match still resolve (ADR 0016 D9), like *opsnotes.Store.
func TestHarnessOpsDismissKeepsSteps(t *testing.T) {
	o := newTestOps(t)
	ctx := context.Background()
	if err := o.Dismiss(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if err := o.Dismiss(ctx, 42); !errors.Is(err, opsnotes.ErrNotFound) {
		t.Fatalf("dismiss unknown note: %v", err)
	}
	n, err := o.Get(ctx, 2)
	if err != nil || !n.Dismissed {
		t.Fatalf("note 2 after dismiss: %+v, %v", n, err)
	}
	x := harnessOpsIndex{o: o}
	if a, _, h, ok := x.Step("2.1"); !ok || a != "service.restart" || h != "e2e-two" {
		t.Fatalf("Step(2.1) after dismiss = %q %q %v", a, h, ok)
	}
	if id, ok := x.Match("service-restart", "e2e-two"); !ok || id != "2" {
		t.Fatalf("Match after dismiss = %q %v", id, ok)
	}
	list, err := o.List(ctx)
	if err != nil || len(list) != 3 || list[0].ID != 3 {
		t.Fatalf("List = %d notes, first %+v, %v", len(list), list, err)
	}
}

func TestHarnessOpsIndexRefusesMalformedRefs(t *testing.T) {
	x := harnessOpsIndex{o: newTestOps(t)}
	for _, ref := range []string{"", "1", "1.", ".1", "01.1", "1.01", "1.1.1", "x.1", "1.4", "99.1", "-1.1"} {
		if _, _, _, ok := x.Step(ref); ok {
			t.Errorf("Step(%q) resolved", ref)
		}
	}
	if fam, ok := x.Family("package.refresh"); !ok || fam != "harness-refresh" {
		t.Errorf("Family(package.refresh) = %q %v", fam, ok)
	}
	if _, ok := x.Family("service.list"); ok {
		t.Error("a read-only action has a suggestion family")
	}
	if id, ok := x.Match("harness-refresh", "e2e-host"); !ok || id != "1" {
		t.Errorf("Match(harness-refresh, e2e-host) = %q %v", id, ok)
	}
	if _, ok := x.Match("harness-refresh", "e2e-two"); ok {
		t.Error("match on a host no note names")
	}
}

// TestHarnessSuggestionFormIsWired: the preview harness (no login) opens
// the operation form from step 1.1 with the stored action and host, the
// banner, the reference and no parameter; a step that is not an action, an
// unknown note and a non-admin get 404. opsagent.spec.js relies on this.
func TestHarnessSuggestionFormIsWired(t *testing.T) {
	defer opsAdmin.Store(true)
	h := newHarness(true, "8080", t.TempDir())
	code, body := get(t, h, "/operations/new?suggestion=1.1&action=core.facts&host=e2e-two&param=unit%3Devil.service")
	if code != http.StatusOK {
		t.Fatalf("GET suggestion 1.1 = %d", code)
	}
	for _, want := range []string{
		"Opened from an agent suggestion. This execution needs a security-key touch.",
		`id="operation-suggestion" name="suggestion" value="1.1"`,
		`value="service.restart" checked`,
		`value="e2e-host" checked`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("suggestion form lacks %q", want)
		}
	}
	for _, bad := range []string{`value="e2e-two" checked`, `value="core.facts" checked`, "evil.service"} {
		if strings.Contains(body, bad) {
			t.Errorf("suggestion form took %q from the URL", bad)
		}
	}
	for _, ref := range []string{"1.4", "99.1", "1.3", "abc"} {
		if code, _ := get(t, h, "/operations/new?suggestion="+ref); code != http.StatusNotFound {
			t.Errorf("suggestion %q = %d, want 404", ref, code)
		}
	}
	opsAdmin.Store(false)
	if code, _ := get(t, h, "/operations/new?suggestion=1.1"); code != http.StatusNotFound {
		t.Errorf("suggestion for a non-admin = %d, want 404", code)
	}
}

func TestOpsAdminHook(t *testing.T) {
	defer opsAdmin.Store(true)
	for _, tc := range []struct {
		query string
		code  int
		admin bool
	}{
		{"on=0", http.StatusOK, false},
		{"on=1", http.StatusOK, true},
		{"on=yes", http.StatusBadRequest, true},
	} {
		rec := httptest.NewRecorder()
		opsAdminHook(rec, httptest.NewRequest(http.MethodGet, "/__ops/admin?"+tc.query, nil))
		if rec.Code != tc.code || opsAdmin.Load() != tc.admin {
			t.Errorf("%s: code %d admin %v", tc.query, rec.Code, opsAdmin.Load())
		}
	}
}
