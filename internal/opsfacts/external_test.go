// SPDX-License-Identifier: AGPL-3.0-or-later

package opsfacts

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
)

// secretFixture is a fleet whose host, label, package and CVE values are all
// recognisable. None of them may appear in the external projection.
func secretFixture() ([]Host, []Finding) {
	h := webHost()
	h.ID = "secret-host-7"
	h.Label = "Keller-Server"
	f1 := osFinding("CVE-2026-4242", vulnprio.TierCritical, 95)
	f1.HostID = "secret-host-7"
	f1.Package = "libexample"
	f1.KEV = true
	f2 := osFinding("CVE-2026-4243", vulnprio.TierHigh, 80)
	f2.HostID = "secret-host-7"
	f2.Package = "libexample2"
	f3 := osFinding("CVE-2026-4244", vulnprio.TierMedium, 40)
	f3.HostID = "secret-host-7"
	accepted := osFinding("CVE-2026-4245", vulnprio.TierCritical, 99)
	accepted.HostID = "secret-host-7"
	accepted.State = StateAcceptedRisk
	ghost := osFinding("CVE-2026-4246", vulnprio.TierCritical, 99)
	ghost.HostID = "ghost-9"
	return []Host{h}, []Finding{f1, f2, f3, accepted, ghost}
}

// TestExternalCountsOpenFleetFindings checks the counters: open findings of
// inventory hosts, per tier and KEV. Accepted and unknown-host findings do not
// count.
func TestExternalCountsOpenFleetFindings(t *testing.T) {
	hosts, fs := secretFixture()
	p := newProjector(t, hosts, fs, nil, fullCatalog())
	got, err := p.External(context.Background())
	if err != nil {
		t.Fatalf("External: %v", err)
	}
	want := Counts{Critical: 1, High: 1, Medium: 1, KEV: 1}
	if got.Fleet != want {
		t.Fatalf("fleet = %+v, want %+v", got.Fleet, want)
	}
}

// TestExternalStructHoldsOnlyCounters walks the type of ExternalProjection and
// fails on any field that is not an integer, so a string, slice, map,
// pointer or interface can never be added without this test failing.
func TestExternalStructHoldsOnlyCounters(t *testing.T) {
	var walk func(t *testing.T, path string, typ reflect.Type)
	walk = func(t *testing.T, path string, typ reflect.Type) {
		t.Helper()
		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				if !f.IsExported() {
					t.Errorf("%s.%s is unexported; the external projection must be plain counters", path, f.Name)
				}
				walk(t, path+"."+f.Name, f.Type)
			}
		case reflect.Int:
		default:
			t.Errorf("%s has kind %s; the external projection allows integer counters only", path, typ.Kind())
		}
	}
	walk(t, "ExternalProjection", reflect.TypeOf(ExternalProjection{}))
}

// TestExternalJSONHasNoHostOrCVEData encodes the external projection of a
// fleet with recognisable data and searches the JSON for every host, label,
// package and vulnerability value. It also checks that every JSON leaf is a
// number.
func TestExternalJSONHasNoHostOrCVEData(t *testing.T) {
	hosts, fs := secretFixture()
	p := newProjector(t, hosts, fs, nil, fullCatalog())
	got, err := p.External(context.Background())
	if err != nil {
		t.Fatalf("External: %v", err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)
	for _, secret := range []string{"secret-host-7", "Keller", "CVE-2026", "libexample", "ghost-9", "openssl", "web-01"} {
		if strings.Contains(js, secret) {
			t.Fatalf("external JSON %s contains %q", js, secret)
		}
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	assertNumericLeaves(t, generic, "external")
}

// assertNumericLeaves fails on any JSON value that is not an object or a
// number.
func assertNumericLeaves(t *testing.T, v any, path string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			assertNumericLeaves(t, child, path+"."+k)
		}
	case float64:
	default:
		t.Fatalf("%s is %T; the external projection holds numbers only", path, v)
	}
}

// TestExternalRefusesInvalidFinding checks that an invalid finding stops the
// external count, as it stops the lab projection.
func TestExternalRefusesInvalidFinding(t *testing.T) {
	hosts, fs := secretFixture()
	fs[0].State = "closed"
	p := newProjector(t, hosts, fs, nil, fullCatalog())
	if _, err := p.External(context.Background()); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("External error = %v, want ErrInvalidState", err)
	}
}
