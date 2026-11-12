// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func TestExportReadsEveryPageOfOneSnapshot(t *testing.T) {
	e := newEnv(t)
	e.inv.set(bigSnapshot("inv-big"))
	c := e.client(t)
	var pages []Page
	snap, err := c.Export(context.Background(), func(p Page) error { pages = append(pages, p); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) < 2 || snap.Pages != len(pages) || snap.ID != "inv-big" || snap.Generation != 9 {
		t.Fatalf("pages %d, snapshot %+v", len(pages), snap)
	}
	for i, p := range pages {
		if p.Index != i || p.SnapshotID != "inv-big" || p.Pages != len(pages) {
			t.Fatalf("page %d: %+v", i, p)
		}
	}
	big, ok := snap.Subject(vulnfinding.SubjectHost, vulnfinding.SubjectRef{ID: "big01"})
	if !ok || big.Parts < 2 || !big.Complete {
		t.Fatalf("big01: %+v", big)
	}
	last, ok := snap.Subject(vulnfinding.SubjectHost, vulnfinding.SubjectRef{ID: "last"})
	if !ok || last.Parts != 1 || last.Complete {
		t.Fatalf("last: %+v", last)
	}
	comps := 0
	for _, p := range pages {
		for _, s := range p.Subjects {
			if s.Ref.ID == "big01" {
				comps += len(s.Components)
			}
		}
	}
	if comps != bigComps {
		t.Fatalf("big01 components over its parts: %d", comps)
	}
	bs := big.BatchSubjects()
	if len(bs) != big.Parts || bs[0].Part != 1 || bs[len(bs)-1].LastPart != true || bs[0].LastPart {
		t.Fatalf("%+v", bs)
	}
	// The export is paced by the client window: one request per page.
	if e.count(inventoryPath) != len(pages) {
		t.Fatalf("%d requests for %d pages", e.count(inventoryPath), len(pages))
	}
}

func TestExportReportsASnapshotGoneMidway(t *testing.T) {
	e := newEnv(t)
	e.inv.set(bigSnapshot("inv-big"))
	c := e.client(t)
	_, err := c.Export(context.Background(), func(p Page) error {
		if p.Index == 0 {
			e.inv.set(baseSnapshot("inv-2", 10, t0))
		}
		return nil
	})
	if !errors.Is(err, ErrSnapshotGone) {
		t.Fatalf("%v", err)
	}
	// Starting again reads the new snapshot.
	snap, err := c.Export(context.Background(), func(Page) error { return nil })
	if err != nil || snap.ID != "inv-2" {
		t.Fatalf("%v %+v", err, snap)
	}
}

func TestExportStopsOnAVisitError(t *testing.T) {
	e := newEnv(t)
	stop := errors.New("stop")
	_, err := e.client(t).Export(context.Background(), func(Page) error { return stop })
	if !errors.Is(err, stop) || e.count(inventoryPath) != 1 {
		t.Fatalf("%v, %d requests", err, e.count(inventoryPath))
	}
}

// pageSrv serves the given pages in order by cursor "c<n>".
func pageSrv(t *testing.T, pages ...map[string]any) Config {
	t.Helper()
	return fakeServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			if _, err := fmt.Sscanf(c, "c%d", &n); err != nil {
				t.Errorf("cursor %q", c)
			}
		}
		b, err := json.Marshal(pages[n])
		if err != nil {
			t.Error(err)
		}
		fixed(http.StatusOK, string(b))(w, r)
	}))
}

func hostPart(id string, part int, last bool) map[string]any {
	return map[string]any{"subject_kind": "host", "subject_ref": map[string]any{"id": id}, "ecosystem": "debian:bookworm",
		"complete": true, "part": part, "last_part": last,
		"components": []any{map[string]any{"source_package": "bash", "source_version": "5.2.15-2"}}}
}

func page(snap string, n, pages int, subjects ...map[string]any) map[string]any {
	p := map[string]any{"format": InventoryFormat, "snapshot_id": snap, "generation": 3, "taken_at": "2026-11-09T11:00:00Z",
		"page": n, "pages": pages, "subjects": subjects}
	if n+1 < pages {
		p["next_cursor"] = fmt.Sprintf("c%d", n+1)
	}
	if subjects == nil {
		p["subjects"] = []any{}
	}
	return p
}

func TestExportRefusesPagesThatBreakTheContract(t *testing.T) {
	with := func(p map[string]any, k string, v any) map[string]any {
		q := map[string]any{}
		for kk, vv := range p {
			q[kk] = vv
		}
		if v == nil {
			delete(q, k)
		} else {
			q[k] = v
		}
		return q
	}
	tooMany := []map[string]any{}
	for i := 0; i <= MaxSubjectsPerPage; i++ {
		tooMany = append(tooMany, hostPart(fmt.Sprintf("h%04d", i), 1, true))
	}
	var cs []any
	for i := 0; i <= MaxImagePackages; i++ {
		cs = append(cs, map[string]any{"source_package": "musl", "source_version": "1"})
	}
	img := map[string]any{"subject_kind": "image", "subject_ref": map[string]any{"id": "web01", "image_digest": digestA},
		"complete": true, "part": 1, "last_part": true, "components": cs}
	headChange := hostPart("h", 2, true)
	headChange["complete"] = false
	cases := map[string][]map[string]any{
		"other snapshot on page 2":     {page("s1", 0, 2, hostPart("a", 1, true)), page("s2", 1, 2, hostPart("b", 1, true))},
		"other generation on page 2":   {page("s1", 0, 2), with(page("s1", 1, 2), "generation", 4)},
		"page count changes":           {page("s1", 0, 2), with(page("s1", 1, 3), "next_cursor", nil)},
		"wrong page number":            {with(page("s1", 0, 2), "page", 1)},
		"no cursor before last page":   {with(page("s1", 0, 2), "next_cursor", nil)},
		"cursor on last page":          {with(page("s1", 0, 1), "next_cursor", "c1")},
		"malformed cursor":             {with(page("s1", 0, 2), "next_cursor", "c1/../x")},
		"other format":                 {with(page("s1", 0, 1), "format", "vuln-inventory-v2")},
		"unknown field":                {with(page("s1", 0, 1), "labels", []any{"x"})},
		"malformed snapshot id":        {page("s 1", 0, 1)},
		"too many subjects":            {page("s1", 0, 1, tooMany...)},
		"part 2 without part 1":        {page("s1", 0, 1, hostPart("a", 2, true))},
		"parts out of order":           {page("s1", 0, 2, hostPart("a", 1, false)), page("s1", 1, 2, hostPart("a", 3, true))},
		"other subject before last":    {page("s1", 0, 2, hostPart("a", 1, false)), page("s1", 1, 2, hostPart("b", 1, true))},
		"subject again after last":     {page("s1", 0, 1, hostPart("a", 1, true), hostPart("a", 1, true))},
		"export ends before last part": {page("s1", 0, 1, hostPart("a", 1, false))},
		"header changes between parts": {page("s1", 0, 2, hostPart("h", 1, false)), page("s1", 1, 2, headChange)},
		"image over component limit":   {page("s1", 0, 1, img)},
		"host with digest":             {page("s1", 0, 1, with(hostPart("a", 1, true), "subject_ref", map[string]any{"id": "a", "image_digest": digestA}))},
		"address-like subject id":      {page("s1", 0, 1, hostPart("Host A", 1, true))},
		"unknown kind":                 {page("s1", 0, 1, with(hostPart("a", 1, true), "subject_kind", "device"))},
	}
	for name, pages := range cases {
		c, err := New(pageSrv(t, pages...))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Export(context.Background(), func(Page) error { return nil })
		if !errors.Is(err, ErrProtocol) && !errors.Is(err, ErrIncompleteExport) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestExportRefusesAnOversizedPage(t *testing.T) {
	big := `{"format":"` + InventoryFormat + `","pad":"` + strings.Repeat("x", MaxExportBytes) + `"}`
	c, err := New(fakeServer(t, fixed(http.StatusOK, big)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Export(context.Background(), func(Page) error { return nil }); !errors.Is(err, ErrProtocol) {
		t.Fatalf("%v", err)
	}
}

func TestExportAcceptsAValidHandWrittenExport(t *testing.T) {
	c, err := New(pageSrv(t, page("s1", 0, 2, hostPart("a", 1, true), hostPart("b", 1, false)), page("s1", 1, 2, hostPart("b", 2, true))))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := c.Export(context.Background(), func(Page) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := snap.Subject(vulnfinding.SubjectHost, vulnfinding.SubjectRef{ID: "b"}); b.Parts != 2 || len(snap.Subjects) != 2 {
		t.Fatalf("%+v", snap)
	}
}

// devicePart is one device subject part as the server exports it (ADR 0011
// D3): vendor, model, firmware version and the vendor ecosystem, no packages.
func devicePart(id string, complete bool) map[string]any {
	return map[string]any{"subject_kind": "device", "subject_ref": map[string]any{"id": id}, "ecosystem": "vendor:cisco:iosxe",
		"device": map[string]any{"vendor": "cisco", "model": "CBS350-24P-4G", "firmware_version": "3.1.1.7"},
		"complete": complete, "part": 1, "last_part": true, "components": []any{}}
}

func TestExportAcceptsADeviceSubjectAndKeepsItsCompleteness(t *testing.T) {
	c, err := New(pageSrv(t, page("s1", 0, 1, hostPart("a", 1, true), devicePart("sw01", true), devicePart("sw02", false))))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := c.Export(context.Background(), func(Page) error { return nil })
	if err != nil {
		t.Fatalf("export with a device subject: %v", err)
	}
	sw01, ok := snap.Subject(vulnfinding.SubjectDevice, vulnfinding.SubjectRef{ID: "sw01"})
	if !ok || sw01.Parts != 1 || !sw01.Complete {
		t.Fatalf("sw01: %+v", sw01)
	}
	sw02, ok := snap.Subject(vulnfinding.SubjectDevice, vulnfinding.SubjectRef{ID: "sw02"})
	if !ok || sw02.Complete {
		t.Fatalf("incomplete device is covered: %+v", sw02)
	}
}

func TestExportRefusesADeviceSubjectThatBreaksTheContract(t *testing.T) {
	noData := devicePart("sw03", true)
	delete(noData, "device")
	withComponents := devicePart("sw04", true)
	withComponents["components"] = []any{map[string]any{"source_package": "openssl", "source_version": "3.0.15-1"}}
	withKernel := devicePart("sw05", true)
	withKernel["running_kernel"] = map[string]any{"release": "6.1.0", "mapped": false}
	withDigest := devicePart("sw06", true)
	withDigest["subject_ref"] = map[string]any{"id": "sw06", "image_digest": "sha256:" + strings.Repeat("a", 64)}
	hostWithDevice := hostPart("h01", 1, true)
	hostWithDevice["device"] = map[string]any{"vendor": "cisco", "model": "CBS350", "firmware_version": "3.1.1.7"}
	hugeField := devicePart("sw07", true)
	hugeField["device"] = map[string]any{"vendor": "cisco", "model": strings.Repeat("A", MaxDeviceFieldBytes+1), "firmware_version": "3.1.1.7"}
	cases := map[string]map[string]any{
		"no device data": noData, "packages on a device": withComponents, "kernel on a device": withKernel,
		"digest on a device": withDigest, "device data on a host": hostWithDevice, "oversized device field": hugeField,
	}
	for name, part := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := New(pageSrv(t, page("s1", 0, 1, part)))
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Export(context.Background(), func(Page) error { return nil })
			if !errors.Is(err, ErrProtocol) {
				t.Fatalf("got %v, want ErrProtocol", err)
			}
		})
	}
}
