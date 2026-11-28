// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
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

// ProposePVEImagePrepare binds pve.image.prepare on the node under dpPin.
func (f *fakeProvision) ProposePVEImagePrepare(_ context.Context, in *pb.ProposePVEImagePrepareRequest, _ ...grpc.CallOption) (*pb.ProposePVEImagePrepareResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepProposed = append(f.prepProposed, in.GetSpec())
	target, err := permit.ProviderMutationTarget{RemoteID: in.GetSpec().GetRemoteId(), TrustPin: dpPin, Kind: "node", Node: in.GetSpec().GetNode()}.RiskTarget()
	if err != nil {
		return nil, err
	}
	rq := canonical.Request{RequestVersion: 1, ExecutionID: "exec-prep-1", ActionID: "pve.image.prepare", ModuleVersion: "1.0.0",
		ArtifactSHA256: strings.Repeat("a2", 32), ParametersHash: strings.Repeat("0e", 32), CredentialRefs: []string{"pve-lab-action"},
		RiskClass: canonical.RiskHigh, StagePlanHash: strings.Repeat("5f", 32), ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		ResolvedTargets: []canonical.Target{target}}
	if f.prepMutate != nil {
		f.prepMutate(&rq)
	}
	c, err := canonical.Encode(rq)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	sha := dpImageSHA
	if f.prepSHA != "" {
		sha = f.prepSHA
	}
	return &pb.ProposePVEImagePrepareResponse{
		Image: &pb.PVEImage{Image: &pb.PVECatalogImage{Id: in.GetSpec().GetImageId(), Sha256: sha}, Trust: "signed"},
		Permit: &pb.ProposeExecutionResponse{ExecutionDigest: hex.EncodeToString(sum[:]), CanonicalRequest: c,
			ApprovalRequirement: f.requirement, RiskClass: pb.RiskClass_RISK_CLASS_HIGH,
			ChallengeExpiryUnix: time.Now().Add(5 * time.Minute).Unix(), RequestOptionsJson: []byte(`{"challenge":"cHJlcA"}`)}}, nil
}

// CommitPVEImagePrepare answers the record the preparation wrote.
func (f *fakeProvision) CommitPVEImagePrepare(_ context.Context, in *pb.CommitPVEImagePrepareRequest, _ ...grpc.CallOption) (*pb.CommitPVEImagePrepareResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepCommits = append(f.prepCommits, in)
	s := in.GetSpec()
	return &pb.CommitPVEImagePrepareResponse{ExecutionId: "exec-prep-1", Template: &pb.PVETemplateRecord{RemoteId: s.GetRemoteId(),
		Node: s.GetNode(), Storage: s.GetStorage(), ImageId: s.GetImageId(), Trust: "signed", Vmid: s.GetVmid(), Generation: 3,
		SourceSha256: dpImageSHA, ExecutionId: "exec-prep-1", PreparedAtUnix: time.Now().Unix()}}, nil
}

// prepCounts returns the number of prepare proposals, assertions and commits.
func (f *fakeProvision) prepCounts() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.prepProposed), len(f.assertions), len(f.prepCommits)
}

// dpPrepareForm is a preparation of the catalog image on the test node.
func dpPrepareForm() url.Values {
	return url.Values{"remote": {dpRemote}, "node": {dpNode}, "storage": {"local-lvm"}, "import_storage": {"local"},
		"image": {dpImageID}, "vmid": {"9100"}}
}

// prepareIDRe finds the approval button's preparation ID on the page.
var prepareIDRe = regexp.MustCompile(`data-id="([0-9a-f]{32})" data-options="[^"]*" data-commit="/deploy/images/approve"`)

// TestImagesPrepareIsApprovedWithTheUsersAssertion: a preparation is
// proposed over ProposePVEImagePrepare, shown with an approval button, and
// committed only after the user's security key assertion was accepted; the
// commit carries the proposed spec and digest.
func TestImagesPrepareIsApprovedWithTheUsersAssertion(t *testing.T) {
	e := newDPEnv(t)
	code, body, loc := e.do(t, http.MethodPost, "/deploy/images/prepare", gpFormCT, dpPrepareForm().Encode())
	if code != http.StatusSeeOther || loc != "/deploy/images" {
		t.Fatalf("prepare = %d %q %q", code, loc, body)
	}
	if p, a, c := e.prov.prepCounts(); p != 1 || a != 0 || c != 0 {
		t.Fatalf("after propose: proposals %d assertions %d commits %d", p, a, c)
	}
	_, page, _ := e.do(t, http.MethodGet, "/deploy/images", "", "")
	m := prepareIDRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no approval button on the page: %s", page)
	}
	for _, want := range []string{"pve.image.prepare", dpImageSHA, "9100", "schedules.js", "webauthn.js"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if code, body, _ := e.do(t, http.MethodPost, "/deploy/images/approve", "application/json", approveJSON(m[1])); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, page, _ = e.do(t, http.MethodGet, "/deploy/images", "", "")
		if strings.Contains(page, `class="prepare-state">prepared<`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the preparation never finished: %s", page)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, a, c := e.prov.prepCounts(); a != 1 || c != 1 {
		t.Fatalf("assertions %d commits %d, want 1 and 1", a, c)
	}
	e.prov.mu.Lock()
	defer e.prov.mu.Unlock()
	cm := e.prov.prepCommits[0]
	if cm.GetSpec().GetVmid() != 9100 || cm.GetSpec().GetImageId() != dpImageID || cm.GetSpec().GetImportStorage() != "local" ||
		len(cm.GetExecutionDigest()) != 64 {
		t.Errorf("commit %v", cm)
	}
	// A second approval of the same preparation is refused.
	if code, _, _ := e.do(t, http.MethodPost, "/deploy/images/approve", "application/json", approveJSON(m[1])); code != http.StatusNotFound {
		t.Errorf("second approve = %d, want 404", code)
	}
}

// TestImagesPrepareRefusesWhatIsNotListed: only a listed catalog image can be
// proposed, with valid fields; an unreachable catalog proposes nothing.
func TestImagesPrepareRefusesWhatIsNotListed(t *testing.T) {
	cases := map[string]struct {
		mod  func(url.Values)
		down bool
		want int
	}{
		"image not in catalog": {mod: func(f url.Values) { f.Set("image", "fedora-41") }, want: http.StatusBadRequest},
		"script image":         {mod: func(f url.Values) { f.Set("image", "<script>") }, want: http.StatusBadRequest},
		"vmid too small":       {mod: func(f url.Values) { f.Set("vmid", "99") }, want: http.StatusBadRequest},
		"vmid not a number":    {mod: func(f url.Values) { f.Set("vmid", "9100x") }, want: http.StatusBadRequest},
		"no import storage":    {mod: func(f url.Values) { f.Del("import_storage") }, want: http.StatusBadRequest},
		"unknown remote":       {mod: func(f url.Values) { f.Set("remote", "other") }, want: http.StatusConflict},
		"catalog unavailable":  {mod: func(url.Values) {}, down: true, want: http.StatusConflict},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDPEnv(t)
			if c.down {
				e.prov.imagesErr = context.DeadlineExceeded
			}
			f := dpPrepareForm()
			c.mod(f)
			if code, body, _ := e.do(t, http.MethodPost, "/deploy/images/prepare", gpFormCT, f.Encode()); code != c.want {
				t.Fatalf("prepare = %d %q, want %d", code, body, c.want)
			}
			if p, _, _ := e.prov.prepCounts(); p != 0 {
				t.Error("a refused preparation reached the executor")
			}
		})
	}
}

// TestImagesPrepareWithADifferentBindingCannotBeApproved: when the executor
// binds another action, target or image SHA-256 than requested, the page
// shows the difference and no assertion is relayed.
func TestImagesPrepareWithADifferentBindingCannotBeApproved(t *testing.T) {
	cases := map[string]func(*fakeProvision){
		"other action": func(f *fakeProvision) {
			f.prepMutate = func(r *canonical.Request) { r.ActionID = "pve.guest.provision" }
		},
		"other node": func(f *fakeProvision) {
			f.prepMutate = func(r *canonical.Request) {
				tg, _ := permit.ProviderMutationTarget{RemoteID: dpRemote, TrustPin: dpPin, Kind: "node", Node: "p2"}.RiskTarget()
				r.ResolvedTargets = []canonical.Target{tg}
			}
		},
		"other image sha": func(f *fakeProvision) { f.prepSHA = strings.Repeat("cd", 32) },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDPEnv(t)
			mod(e.prov)
			if code, body, _ := e.do(t, http.MethodPost, "/deploy/images/prepare", gpFormCT, dpPrepareForm().Encode()); code != http.StatusSeeOther {
				t.Fatalf("prepare = %d %q", code, body)
			}
			_, page, _ := e.do(t, http.MethodGet, "/deploy/images", "", "")
			if prepareIDRe.MatchString(page) || !strings.Contains(page, "differs from the request") {
				t.Fatalf("a differing binding is approvable: %s", page)
			}
			id := regexp.MustCompile(`data-prepare="([0-9a-f]{32})"`).FindStringSubmatch(page)
			if id == nil {
				t.Fatal("the preparation is not listed")
			}
			if code, _, _ := e.do(t, http.MethodPost, "/deploy/images/approve", "application/json", approveJSON(id[1])); code != http.StatusNotFound {
				t.Errorf("approve = %d, want 404", code)
			}
			if _, a, c := e.prov.prepCounts(); a != 0 || c != 0 {
				t.Errorf("assertions %d commits %d after a differing binding", a, c)
			}
		})
	}
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

// TestWizardOffersNoRecordWithASupersededCatalogSHA: the catalog lists a
// new SHA-256 for the image, the record was prepared from the old one. The
// executor refuses such a record (BindTemplate compares it with the catalog),
// so the wizard offers neither its VMID nor a SHA-256 and says it must be
// prepared again; a form with the old or new values is refused before the
// executor.
func TestWizardOffersNoRecordWithASupersededCatalogSHA(t *testing.T) {
	e := newDPEnv(t)
	newSHA := strings.Repeat("ef", 32)
	e.prov.images = dpImagesDefault()
	e.prov.images.Images[0].Image.Sha256 = newSHA
	_, body, _ := e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
	if strings.Contains(body, `<option value="9000"`) {
		t.Error("the wizard offers a record whose SHA-256 the catalog no longer lists")
	}
	if strings.Contains(body, `<option value="`+dpImageSHA+`"`) || strings.Contains(body, `<option value="`+newSHA+`"`) {
		t.Error("the wizard offers a SHA-256 that no offered record was prepared from")
	}
	if strings.Contains(body, `<option value="debian-13"`) {
		t.Error("the wizard offers an image without a bindable record")
	}
	if !strings.Contains(body, "prepare it again") {
		t.Error("the wizard does not say that the template must be prepared again")
	}
	// One environment per attempt: the propose rate limit counts attempts.
	for _, sha := range []string{dpImageSHA, newSHA} {
		e := newDPEnv(t)
		e.prov.images = dpImagesDefault()
		e.prov.images.Images[0].Image.Sha256 = newSHA
		f := dpForm()
		f.Set("template_sha256", sha)
		if code, b, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode()); code != http.StatusBadRequest {
			t.Errorf("propose with sha %s = %d %q, want 400", sha[:4], code, b)
		}
		if len(e.prov.proposed) != 0 {
			t.Error("a record with a superseded SHA-256 reached the executor")
		}
	}
}

// TestWizardLeavesOutRecordsOfOtherTargets: records of another node, another
// remote, another storage than the profile's, or an image the catalog does
// not list are not offered; only the record of the target is.
func TestWizardLeavesOutRecordsOfOtherTargets(t *testing.T) {
	e := newDPEnv(t)
	r := dpImagesDefault()
	base := r.Templates[0]
	add := func(vmid uint64, edit func(*pb.PVETemplateRecord)) {
		c := &pb.PVETemplateRecord{RemoteId: base.RemoteId, Node: base.Node, Storage: base.Storage, ImageId: base.ImageId,
			Trust: base.Trust, Vmid: vmid, Generation: 1, SourceSha256: base.SourceSha256}
		edit(c)
		r.Templates = append(r.Templates, c)
	}
	add(9101, func(c *pb.PVETemplateRecord) { c.Node = "p2" })
	add(9102, func(c *pb.PVETemplateRecord) { c.RemoteId = "pve-other" })
	add(9103, func(c *pb.PVETemplateRecord) { c.Storage = "other-pool" })
	add(9104, func(c *pb.PVETemplateRecord) { c.ImageId = "fedora-41" })
	e.prov.images = r
	_, body, _ := e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
	if !strings.Contains(body, `<option value="9000">`) {
		t.Error("the wizard does not offer the target's record")
	}
	for _, v := range []string{"9101", "9102", "9103", "9104"} {
		if strings.Contains(body, `value="`+v+`"`) {
			t.Errorf("the wizard offers record %s of another target", v)
		}
	}
	if strings.Contains(body, `value="fedora-41"`) {
		t.Error("the wizard offers an image that is not in the catalog")
	}
}

// TestWizardTemplateLabelShowsTheRecord: the template choice is labelled
// with the record's VMID, image, storage, trust, SHA-256 and generation.
func TestWizardTemplateLabelShowsTheRecord(t *testing.T) {
	e := newDPEnv(t)
	e.prov.images = withRecord(func(r *pb.PVETemplateRecord) { r.Generation = dpRecordGen })
	_, body, _ := e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
	want := `<option value="9000">9000 · debian-13 · local-lvm · signed · sha256 ` + dpImageSHA + ` · generation 2</option>`
	if !strings.Contains(body, want) {
		t.Errorf("wizard lacks %s", want)
	}
}

// TestImagesAnswerOverLimitsIsNotAvailable: an executor answer with too many
// entries or records, or with an overlong or non-UTF-8 string, is not shown
// and the wizard offers no template from it.
func TestImagesAnswerOverLimitsIsNotAvailable(t *testing.T) {
	cases := map[string]func(*pb.ListPVEImagesResponse){
		"too many images": func(r *pb.ListPVEImagesResponse) {
			for range 256 {
				r.Images = append(r.Images, r.Images[0])
			}
		},
		"too many records": func(r *pb.ListPVEImagesResponse) {
			for range 1024 {
				r.Templates = append(r.Templates, r.Templates[0])
			}
		},
		"overlong url":   func(r *pb.ListPVEImagesResponse) { r.Images[0].Image.Url = dpCatalogURL + strings.Repeat("a", 2048) },
		"overlong node":  func(r *pb.ListPVEImagesResponse) { r.Templates[0].Node = strings.Repeat("n", 2049) },
		"non-utf8 os":    func(r *pb.ListPVEImagesResponse) { r.Images[0].Image.Os = "deb\xffian" },
		"non-utf8 trust": func(r *pb.ListPVEImagesResponse) { r.Templates[0].Trust = "\xc3" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDPEnv(t)
			r := dpImagesDefault()
			edit(r)
			e.prov.images = r
			_, body, _ := e.do(t, http.MethodGet, "/deploy/images", "", "")
			if !strings.Contains(body, "Not available") || strings.Contains(body, dpRecordExec) {
				t.Error("an answer over the limits is shown")
			}
			_, body, _ = e.do(t, http.MethodGet, "/deployments/new?remote=pve-lab&node=p1&profile=web_s", "", "")
			if strings.Contains(body, `<option value="9000"`) {
				t.Error("the wizard offers a template from an answer over the limits")
			}
		})
	}
}

// TestImagesPreparationsAreBoundedPerUser: one user's open preparations do
// not block another user's, and a preparation over the user's limit is
// refused before the executor is asked for a proposal.
func TestImagesPreparationsAreBoundedPerUser(t *testing.T) {
	e := newDPEnv(t)
	sessions := auth.NewStore(e.db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: sessions, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: gpOrigin}, a.Wrap(e.h)))
	t.Cleanup(srv.Close)
	login := func(user string) *http.Cookie {
		token, _, err := sessions.Create(context.Background(), "cred-"+user, user)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Cookie{Name: auth.CookieName, Value: token}
	}
	prepare := func(c *http.Cookie) int {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/deploy/images/prepare", strings.NewReader(dpPrepareForm().Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(c)
		req.Header.Set("Origin", gpOrigin)
		req.Header.Set("Content-Type", gpFormCT)
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	alice, bob := login("alice"), login("bob")
	const perUser = 4
	for i := range perUser {
		if code := prepare(alice); code != http.StatusSeeOther {
			t.Fatalf("alice prepare %d = %d", i, code)
		}
	}
	if code := prepare(alice); code != http.StatusServiceUnavailable {
		t.Errorf("alice prepare over her limit = %d, want 503", code)
	}
	if p, _, _ := e.prov.prepCounts(); p != perUser {
		t.Errorf("executor proposals = %d, want %d: a refused preparation reached the executor", p, perUser)
	}
	if code := prepare(bob); code != http.StatusSeeOther {
		t.Errorf("bob prepare = %d: alice's preparations block other users", code)
	}
}
