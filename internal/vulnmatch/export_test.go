// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/nosclient"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

func part(id string, n int, last bool, comps ...nosclient.Component) nosclient.SubjectPart {
	return nosclient.SubjectPart{Kind: vulnfinding.SubjectHost, Ref: vulnfinding.SubjectRef{ID: id}, Ecosystem: "debian:bookworm",
		Kernel:   &nosclient.Kernel{Release: "6.1.0-27-amd64", Mapped: true, SourcePackage: "linux", SourceVersion: "6.1.115-1"},
		Complete: true, Part: n, LastPart: last, Components: comps}
}

func exportComp(p, v string) nosclient.Component {
	return nosclient.Component{SourcePackage: p, SourceVersion: v, Binaries: []nosclient.Binary{{Name: p, Version: v + "+b1", Arch: "amd64"}}}
}

// exportThroughClient serves pages as a vuln-inventory-v1 export on a
// loopback TLS server and reads it back with nosclient's own Export, so
// every part the matcher sees has passed nosclient's numbering checks.
func exportThroughClient(t *testing.T, pages ...[]nosclient.SubjectPart) []nosclient.SubjectPart {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			i, _ = strconv.Atoi(c[1:])
		}
		page := map[string]any{"format": nosclient.InventoryFormat, "snapshot_id": "inv-1", "generation": 1,
			"taken_at": "2026-11-12T00:00:00Z", "page": i, "pages": len(pages), "subjects": pages[i]}
		if i+1 < len(pages) {
			page["next_cursor"] = "c" + strconv.Itoa(i+1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tok, ca := filepath.Join(dir, "token"), filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(tok, []byte("test-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := nosclient.New(nosclient.Config{BaseURL: srv.URL, TokenFile: tok, CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	var out []nosclient.SubjectPart
	if _, err := c.Export(context.Background(), func(p nosclient.Page) error {
		out = append(out, p.Subjects...)
		return nil
	}); err != nil {
		t.Fatalf("nosclient export: %v", err)
	}
	return out
}

// TestSubjectsFromExportMergesParts: parts numbered as nosclient accepts
// them (1-based, consecutive, a subject split across pages) merge into
// one subject each.
func TestSubjectsFromExportMergesParts(t *testing.T) {
	parts := exportThroughClient(t,
		[]nosclient.SubjectPart{part("h1", 1, false, exportComp("openssl", "3.0.14-1~deb12u2"))},
		[]nosclient.SubjectPart{part("h1", 2, true, exportComp("linux", "6.1.115-1")), part("h2", 1, true, exportComp("zlib", "1:1.2.13.dfsg-1"))},
	)
	subs, err := SubjectsFromExport(parts)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 || len(subs[0].Components) != 2 || subs[0].Kernel == nil || subs[0].Kernel.SourceVersion != "6.1.115-1" {
		t.Fatalf("subjects = %+v", subs)
	}
	if subs[0].Incomplete || subs[1].Incomplete {
		t.Fatalf("complete subjects marked incomplete: %+v", subs)
	}
	if b := subs[0].Components[0].Binaries[0]; b.SourceVersion != "" || b.Version != "3.0.14-1~deb12u2+b1" {
		t.Fatalf("binary = %+v", b)
	}
}

// TestSubjectsFromExportKeepsIncompleteness: a subject NOS reports as not
// complete stays marked, and the matcher reports it as a coverage gap.
func TestSubjectsFromExportKeepsIncompleteness(t *testing.T) {
	p := part("h1", 1, true, exportComp("openssl", "3.0.14-1~deb12u2"))
	p.Complete = false
	subs, err := SubjectsFromExport(exportThroughClient(t, []nosclient.SubjectPart{p}))
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || !subs[0].Incomplete {
		t.Fatalf("subjects = %+v", subs)
	}
	r := mustMatch(t, newDB(t), subs...)
	if !hasGap(r, "", GapInventoryIncomplete) {
		t.Fatalf("gaps = %+v", r.Gaps)
	}
}

// deviceExport is a device subject part as NOS exports it through the client.
func deviceExport(id string, complete bool, firmware string) nosclient.SubjectPart {
	return nosclient.SubjectPart{Kind: vulnfinding.SubjectDevice, Ref: vulnfinding.SubjectRef{ID: id}, Ecosystem: "vendor:cisco:iosxe",
		Device:   &nosclient.Device{Vendor: "cisco", Model: "CBS350-24P-4G", FirmwareVersion: firmware},
		Complete: complete, Part: 1, LastPart: true}
}

// TestSubjectsFromExportCarriesDeviceModelAndFirmware: a device's model and
// firmware reach the matcher; "unknown" reaches it as an empty value.
func TestSubjectsFromExportCarriesDeviceModelAndFirmware(t *testing.T) {
	subs, err := SubjectsFromExport(exportThroughClient(t,
		[]nosclient.SubjectPart{deviceExport("sw01", true, "3.1.1.7"), deviceExport("sw02", true, "unknown")}))
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 2 || subs[0].Device == nil || subs[0].Device.Model != "CBS350-24P-4G" || subs[0].Device.Firmware != "3.1.1.7" {
		t.Fatalf("subjects = %+v", subs)
	}
	if subs[0].Incomplete || subs[0].Ecosystem != "vendor:cisco:iosxe" {
		t.Fatalf("complete device: %+v", subs[0])
	}
	if subs[1].Device == nil || subs[1].Device.Firmware != "" {
		t.Fatalf("unknown firmware not empty: %+v", subs[1].Device)
	}
}

// TestDeviceWithoutKnownFirmwareIsNeverClean: a device whose firmware NOS
// does not know, or whose record is incomplete, is a coverage gap, never a
// clean result.
func TestDeviceWithoutKnownFirmwareIsNeverClean(t *testing.T) {
	subs, err := SubjectsFromExport(exportThroughClient(t,
		[]nosclient.SubjectPart{deviceExport("sw01", true, "unknown"), deviceExport("sw02", false, "3.1.1.7")}))
	if err != nil {
		t.Fatal(err)
	}
	r := mustMatch(t, newDB(t), subs...)
	if !hasGap(r, "", GapVersionUnknown) {
		t.Fatalf("unknown firmware is not a version gap: %+v", r.Gaps)
	}
	if !hasGap(r, "", GapInventoryIncomplete) {
		t.Fatalf("incomplete device is not an inventory gap: %+v", r.Gaps)
	}
}

func TestSubjectsFromExportRejectsIncompleteSubjects(t *testing.T) {
	tests := []struct {
		name  string
		parts []nosclient.SubjectPart
	}{
		{"missing last part", []nosclient.SubjectPart{part("h1", 1, false)}},
		{"0-based first part", []nosclient.SubjectPart{part("h1", 0, true)}},
		{"part out of order", []nosclient.SubjectPart{part("h1", 2, true)}},
		{"part after last part", []nosclient.SubjectPart{part("h1", 1, true), part("h1", 2, true)}},
		{"repeated part", []nosclient.SubjectPart{part("h1", 1, false), part("h1", 1, true)}},
		{"subject starts before previous last part", []nosclient.SubjectPart{part("h1", 1, false), part("h2", 1, true), part("h1", 2, true)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SubjectsFromExport(tc.parts); !errors.Is(err, ErrIncompleteSubject) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
