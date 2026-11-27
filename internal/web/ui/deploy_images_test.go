// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// PV-03h (ADR 0008 amendment 2, D4a/D4b): the Images page under /deploy and
// the wizard's image, SHA-256 and template choices, all taken from the
// executor's ListPVEImages.

const (
	dpImageID      = "debian-13"
	dpCatalogURL   = "https://cloud.example/debian-13.qcow2"
	dpRecordExec   = "exec-img-1"
	dpPlainVMID    = 9001
	dpRecordGen    = 2
	dpInventoryGen = 1
)

// dpImagesDefault is the executor's catalog with one prepared template on
// the test node: VMID 9000 from debian-13 at dpImageSHA, generation 1.
func dpImagesDefault() *pb.ListPVEImagesResponse {
	return &pb.ListPVEImagesResponse{
		CatalogSequence: 3,
		CatalogDigest:   strings.Repeat("d1", 32),
		Images: []*pb.PVEImage{{
			Image: &pb.PVECatalogImage{Id: dpImageID, Os: "debian", Release: "13", Arch: "amd64", Url: dpCatalogURL,
				Sha256: dpImageSHA, DiskFormat: "qcow2"},
			Trust: "signed", CatalogSequence: 3, CatalogDigest: strings.Repeat("d1", 32),
		}},
		Templates: []*pb.PVETemplateRecord{{
			RemoteId: dpRemote, Node: dpNode, Storage: "local-lvm", ImageId: dpImageID, Trust: "signed",
			Vmid: dpTemplate, Generation: 1, SourceSha256: dpImageSHA, ConfigDigest: strings.Repeat("7c", 32),
			TrustGeneration: 1, ExecutionId: dpRecordExec, PreparedAtUnix: 1798000000,
		}},
	}
}

// ListPVEImages is the executor's read RPC (server role) of the fake.
func (f *fakeProvision) ListPVEImages(_ context.Context, _ *pb.ListPVEImagesRequest, _ ...grpc.CallOption) (*pb.ListPVEImagesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.imagesErr != nil {
		return nil, f.imagesErr
	}
	if f.images == nil {
		return &pb.ListPVEImagesResponse{}, nil
	}
	return f.images, nil
}

// withRecord returns the default records with one record replaced by edit.
func withRecord(edit func(*pb.PVETemplateRecord)) *pb.ListPVEImagesResponse {
	r := dpImagesDefault()
	edit(r.Templates[0])
	return r
}

// TestImagesPageListsCatalogAndRecords: the page shows the catalog entries
// (ID, release, architecture, URL, SHA-256, trust) and the template records.
func TestImagesPageListsCatalogAndRecords(t *testing.T) {
	e := newDPEnv(t)
	code, body, _ := e.do(t, http.MethodGet, "/deploy/images", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /deploy/images = %d", code)
	}
	for _, want := range []string{
		`href="/deploy/images"`, dpImageID, "13", "amd64", dpCatalogURL, dpImageSHA, "signed",
		"local-lvm", ">9000<", "exec-img-1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("images page lacks %q", want)
		}
	}
}

// TestImagesPageRendersCatalogAsTextOnly: catalog strings are escaped, a
// javascript: URL is not linked, and the response carries a CSP.
func TestImagesPageRendersCatalogAsTextOnly(t *testing.T) {
	e := newDPEnv(t)
	e.prov.images = &pb.ListPVEImagesResponse{Images: []*pb.PVEImage{{
		Image: &pb.PVECatalogImage{Id: dpImageID, Os: `<script>alert(1)</script>`, Release: "13", Arch: "amd64",
			Url: "javascript:alert(2)", Sha256: dpImageSHA},
		Trust: "local",
	}, {
		Image: &pb.PVECatalogImage{Id: "evil", Os: "x", Release: "1", Arch: "amd64",
			Url: "https://u:p@cloud.example/x.qcow2#<script>", Sha256: dpImageSHA},
		Trust: "signed",
	}}}
	code, body, _ := e.do(t, http.MethodGet, "/deploy/images", "", "")
	if code != http.StatusOK {
		t.Fatalf("GET /deploy/images = %d", code)
	}
	if strings.Contains(body, "<script>alert(1)</script>") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the catalog's OS text is not escaped")
	}
	if strings.Contains(body, `href="javascript:`) {
		t.Error("a javascript: URL is linked")
	}
	if strings.Contains(body, `href="https://u:p@`) || strings.Contains(body, "<script>#") {
		t.Error("a URL with user info or raw script is linked")
	}
	req := httptest.NewRequest(http.MethodGet, "/deploy/images", nil)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %s", csp, want)
		}
	}
}

// TestImagesPageSaysNotAvailableWhenExecutorFails: an unreachable executor
// is shown as not available, not as an empty catalog.
func TestImagesPageSaysNotAvailableWhenExecutorFails(t *testing.T) {
	e := newDPEnv(t)
	e.prov.imagesErr = context.DeadlineExceeded
	_, body, _ := e.do(t, http.MethodGet, "/deploy/images", "", "")
	if !strings.Contains(body, "Not available") || strings.Contains(body, "No image catalog entries") {
		t.Errorf("an unreachable executor is not shown as not available: %s", body)
	}
}

// TestWizardOffersOnlyPreparedRecordsOfTheNode: a stopped guest without a
// template record is not offered; the record's VMID is.
func TestWizardOffersOnlyPreparedRecordsOfTheNode(t *testing.T) {
	e := newDPEnv(t)
	e.observe(t, dpGuest(dpPlainVMID, "stopped-plain", pvecontract.GuestStopped))
	_, body, _ := e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
	if !strings.Contains(body, `<option value="9000">`) {
		t.Error("the wizard does not offer the prepared template's VMID")
	}
	if strings.Contains(body, `value="9001"`) || strings.Contains(body, "stopped-plain") {
		t.Error("the wizard offers a stopped guest without a template record")
	}
	if !strings.Contains(body, `<select name="image"`) || !strings.Contains(body, `<option value="debian-13"`) ||
		!strings.Contains(body, `<select name="template_sha256"`) || !strings.Contains(body, `<option value="`+dpImageSHA+`"`) {
		t.Error("the wizard's image and SHA-256 are not selection lists from the catalog")
	}
}

// TestWizardWithoutExecutorOffersNoTemplate: when the executor's catalog
// cannot be read, the wizard says so and offers no template.
func TestWizardWithoutExecutorOffersNoTemplate(t *testing.T) {
	e := newDPEnv(t)
	e.prov.imagesErr = context.DeadlineExceeded
	_, body, _ := e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
	if strings.Contains(body, `<option value="9000">`) || !strings.Contains(body, "image catalog is not available") {
		t.Error("the wizard offers templates without the executor's catalog")
	}
}

// TestWizardRefusesValuesThatAreNotARecord: image, SHA-256, storage and
// VMID must match one template record; anything else is refused before the
// executor sees a proposal.
func TestWizardRefusesValuesThatAreNotARecord(t *testing.T) {
	cases := map[string]func(url.Values){
		"vmid without record":    func(f url.Values) { f.Set("template_vmid", "9001") },
		"image not in catalog":   func(f url.Values) { f.Set("image", "fedora-41") },
		"sha not the record's":   func(f url.Values) { f.Set("template_sha256", strings.Repeat("cd", 32)) },
		"storage not the record": func(f url.Values) { f.Set("storage", "other-pool") },
		"vmid of other node":     func(f url.Values) { f.Set("template_vmid", "9000"); f.Set("node", "p2") },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDPEnv(t)
			e.observe(t, dpGuest(dpPlainVMID, "stopped-plain", pvecontract.GuestStopped))
			f := dpForm()
			mod(f)
			if code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode()); code != http.StatusBadRequest {
				t.Fatalf("propose = %d %q, want 400", code, body)
			}
			if len(e.prov.proposed) != 0 {
				t.Error("a value that is no template record reached the executor")
			}
		})
	}
}

// TestWizardSendsTheRecordGeneration: PVETemplateRef.Generation is the
// executor record's generation, not the inventory generation of the guest.
func TestWizardSendsTheRecordGeneration(t *testing.T) {
	e := newDPEnv(t)
	e.prov.images = withRecord(func(r *pb.PVETemplateRecord) { r.Generation = dpRecordGen })
	e.observe(t) // template 9000 has inventory generation dpInventoryGen
	if dpInventoryGen == dpRecordGen {
		t.Fatal("the test needs different generations")
	}
	e.propose(t, dpForm())
	ref := e.prov.proposed[0].GetTemplate()
	if ref.GetGeneration() != dpRecordGen || ref.GetVmid() != dpTemplate || ref.GetSourceSha256() != dpImageSHA ||
		ref.GetImageId() != dpImageID || ref.GetStorage() != "local-lvm" || ref.GetRemoteId() != dpRemote || ref.GetNode() != dpNode {
		t.Errorf("template reference %v", ref)
	}
}

// TestWizardProvisioningAfterPrepareEndsLikePi07: after a successful
// preparation (a record with generation 2) the wizard's provisioning runs to
// the booting state: no error, one commit, no ErrPveTemplateChanged.
func TestWizardProvisioningAfterPrepareEndsLikePi07(t *testing.T) {
	e := newDPEnv(t)
	e.prov.images = withRecord(func(r *pb.PVETemplateRecord) { r.Generation = dpRecordGen })
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	body := e.waitState(t, run, "booting")
	if strings.Contains(body, "ErrPveTemplateChanged") || strings.Contains(body, "template changed") {
		t.Error("the provisioning reports a changed template")
	}
	if e.prov.commitCount() != 1 || e.prov.commits[0].GetSpec().GetTemplate().GetGeneration() != dpRecordGen {
		t.Errorf("commits = %d, want one with generation %d", e.prov.commitCount(), dpRecordGen)
	}
}
