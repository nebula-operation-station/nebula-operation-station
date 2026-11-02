// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	"golang.org/x/crypto/ssh"
)

const (
	imgUbuntuID  = "ubuntu-24.04-amd64"
	imgUbuntuURL = "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
	imgLocalID   = "local-rocky-9-amd64"
	imgLocalURL  = "https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2"
)

var (
	imgUbuntuSHA = strings.Repeat("5a", 32)
	imgLocalSHA  = strings.Repeat("7c", 32)
)

var imgArtifact = []byte("pve.image.prepare 1.0.0\nPrepare a PVE template from a catalog image.\n")

// releaseSK is a software stand-in for a FIDO release root, test-only. It
// writes sk-ssh-ed25519 SSHSIG signatures in the release namespace so the
// production verifier runs end to end.
type releaseSK struct {
	priv ed25519.PrivateKey
	pub  ssh.PublicKey
}

func newReleaseSK(t *testing.T) *releaseSK {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{ssh.KeyAlgoSKED25519, pub, release.Application}))
	if err != nil {
		t.Fatal(err)
	}
	return &releaseSK{priv: priv, pub: k}
}

func (k *releaseSK) root() release.Root { return release.Root{ID: "root-1", Key: k.pub} }

func (k *releaseSK) sign(t *testing.T, msg []byte) []byte {
	t.Helper()
	h := sha512.Sum512(msg)
	var m [6]byte
	copy(m[:], "SSHSIG")
	signed := ssh.Marshal(struct {
		Magic     [6]byte
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}{m, release.Namespace, "", "sha512", h[:]})
	app := sha256.Sum256([]byte(release.Application))
	data := sha256.Sum256(signed)
	fido := ssh.Marshal(struct {
		App     []byte `ssh:"rest"`
		Flags   byte
		Counter uint32
		Data    []byte `ssh:"rest"`
	}{app[:], 0x01, 1, data[:]})
	sig := ssh.Signature{Format: ssh.KeyAlgoSKED25519, Blob: ed25519.Sign(k.priv, fido),
		Rest: ssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{0x01, 1})}
	raw := ssh.Marshal(struct {
		Magic     [6]byte
		Version   uint32
		PublicKey []byte
		Namespace string
		Reserved  string
		HashAlg   string
		Signature []byte
	}{m, 1, k.pub.Marshal(), release.Namespace, "", "sha512", ssh.Marshal(sig)})
	return []byte("-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(raw) + "\n-----END SSH SIGNATURE-----\n")
}

// catalogDoc returns a canonical signed-catalog document.
func catalogDoc(t *testing.T, seq int, images ...map[string]any) []byte {
	t.Helper()
	list := make([]any, 0, len(images))
	for _, im := range images {
		list = append(list, im)
	}
	b, err := json.Marshal(map[string]any{"format": release.CatalogFormat, "sequence": seq, "images": list})
	if err != nil {
		t.Fatal(err)
	}
	c, err := jcs.Transform(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ubuntuEntry(sha string) map[string]any {
	return map[string]any{"id": imgUbuntuID, "os": "ubuntu", "release": "24.04", "arch": "amd64",
		"url": imgUbuntuURL, "sha256": sha, "disk_format": "qcow2"}
}

// imageClient is the fake PVE client with the image step allowlist; it
// reports the node and the template configuration separately.
type imageClient struct {
	*fakeMutClient
	mu             sync.Mutex
	steps          []PveMutationStep
	templateDigest string
}

func (c *imageClient) TaskType(method string) (string, bool) { return ImageStepTaskType(method) }

func (c *imageClient) Dispatch(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, tok pveapi.TokenSupplier) (string, error) {
	_, _ = c.fakeMutClient.Dispatch(ctx, rm, node, step, tok)
	c.mu.Lock()
	c.steps = append(c.steps, step)
	n := len(c.steps)
	c.mu.Unlock()
	tt, _ := ImageStepTaskType(step.Method)
	return testTaskUPID(node, time.Now(), tt, "9000", mutActionUser, 100+n), nil
}

func (c *imageClient) TargetState(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, tok pveapi.TokenSupplier) (string, string, error) {
	live, digest, err := c.fakeMutClient.TargetState(ctx, rm, kind, node, vmid, tok)
	if kind == permit.ProviderKindQemu {
		c.mu.Lock()
		digest = c.templateDigest
		c.mu.Unlock()
	}
	return live, digest, err
}

func (c *imageClient) setTemplateDigest(d string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.templateDigest = d
}

func (c *imageClient) dispatched() []PveMutationStep {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PveMutationStep(nil), c.steps...)
}

type imagesEnv struct {
	*pveMutEnv
	sk     *releaseSK
	client *imageClient
	imgs   *PveImages
	store  *FilePveTemplateStore
}

func newImagesEnv(t *testing.T) *imagesEnv {
	t.Helper()
	me := newPveMutEnv(t, true)
	ic := &imageClient{fakeMutClient: me.client, templateDigest: strings.Repeat("e1", 32)}
	me.m.Client = ic
	sk := newReleaseSK(t)
	cat := newCatalogAt(filepath.Join(t.TempDir(), "pve-catalog.json"))
	raw := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	if err := cat.LoadSigned([]release.Root{sk.root()}, raw, sk.sign(t, raw)); err != nil {
		t.Fatal(err)
	}
	if err := cat.AddLocal(release.Image{ID: imgLocalID, OS: "rocky", Release: "9", Arch: "amd64", URL: imgLocalURL, SHA256: imgLocalSHA, DiskFormat: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	store := &FilePveTemplateStore{Path: filepath.Join(t.TempDir(), "pve-templates.json")}
	return &imagesEnv{pveMutEnv: me, sk: sk, client: ic, store: store,
		imgs: &PveImages{Mutations: me.m, Catalog: cat, Templates: store, Artifact: imgArtifact, ModuleVersion: "1.0.0"}}
}

func prepareReq(image string, vmid uint64) PveImagePrepareRequest {
	return PveImagePrepareRequest{
		PveTemplateKey: PveTemplateKey{RemoteID: mutRemote, Node: "pve1", Storage: "local-lvm", ImageID: image},
		ImportStorage:  "local", VMID: vmid,
	}
}

// propose builds and registers the proposal of req at risk; it returns the
// pending permit.
func (e *imagesEnv) propose(req PveImagePrepareRequest, risk canonical.Risk) permit.Permit {
	e.t.Helper()
	mutExecSeq++
	id := fmt.Sprintf("00000000-0000-4000-b000-%012d", mutExecSeq)
	rq, params, err := e.imgs.ProposalRequest(context.Background(), req, id, risk, strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if err != nil {
		e.t.Fatal(err)
	}
	res, err := e.auth.ProposeAtLeastMinimum(rq, params)
	if err != nil {
		e.t.Fatal(err)
	}
	return res.Permit
}

func (e *imagesEnv) approveImage(req PveImagePrepareRequest) PveImagePrepareRequest {
	e.t.Helper()
	p := e.propose(req, canonical.RiskLow)
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = p.Digest
	return req
}

func (e *imagesEnv) prepare(req PveImagePrepareRequest) PveTemplateRecord {
	e.t.Helper()
	rec, err := e.imgs.Prepare(context.Background(), e.approveImage(req))
	if err != nil {
		e.t.Fatal(err)
	}
	return rec
}

func bindingOf(r PveTemplateRecord) PveTemplateBinding {
	return PveTemplateBinding{PveTemplateKey: r.PveTemplateKey, VMID: r.VMID, Generation: r.Generation, SourceSHA256: r.SourceSHA256}
}

func TestImagePrepareDownloadsWithCatalogChecksumAndBuildsCloudInitTemplate(t *testing.T) {
	e := newImagesEnv(t)
	rec := e.prepare(prepareReq(imgUbuntuID, 9000))

	steps := e.client.dispatched()
	if len(steps) != 3 || steps[0].Method != pveStepImageDownload || steps[1].Method != pveStepImageCreateVM || steps[2].Method != pveStepImageTemplate {
		t.Fatalf("steps = %+v", steps)
	}
	for _, d := range e.client.fakeMutClient.dispatches {
		if d.header != "PVEAPIToken="+mutActionToken || d.node != "pve1" {
			t.Fatalf("dispatch used %q on %s", d.header, d.node)
		}
	}
	// The steps translate into the typed pveapi calls with the catalog URL
	// and checksum and the imported file.
	w := &recordingImageWriter{}
	for _, s := range steps {
		if _, err := DispatchImageStep(context.Background(), w, "pve1", s); err != nil {
			t.Fatal(err)
		}
	}
	dl := w.download
	if dl.Content != pveapi.ContentImport || dl.SourceURL != imgUbuntuURL || dl.SHA256 != imgUbuntuSHA || dl.Storage != "local" || dl.Node != "pve1" {
		t.Fatalf("download = %+v", dl)
	}
	cr := w.create
	if cr.VMID != 9000 || cr.Storage != "local-lvm" || cr.ImportStorage != "local" || cr.ImportFilename != dl.Filename || cr.Name != "tpl-ubuntu-24-04-amd64" {
		t.Fatalf("create = %+v", cr)
	}
	if w.templateVMID != 9000 || w.templateNode != "pve1" {
		t.Fatalf("template = %d on %s", w.templateVMID, w.templateNode)
	}

	if rec.VMID != 9000 || rec.Generation != 1 || rec.SourceSHA256 != imgUbuntuSHA || rec.ConfigDigest != strings.Repeat("e1", 32) ||
		rec.Trust != ImageTrustSigned || rec.TrustGeneration < 1 || rec.ExecutionID == "" {
		t.Fatalf("record = %+v", rec)
	}
	stored, ok, err := e.store.PveTemplate(rec.PveTemplateKey)
	if err != nil || !ok || stored.ConfigDigest != rec.ConfigDigest || stored.Generation != 1 {
		t.Fatalf("stored = %+v %v %v", stored, ok, err)
	}
	e.noSecrets(nil, rec.ExecutionID)
}

func TestImagePrepareIsHighForSignedAndLocalEntries(t *testing.T) {
	e := newImagesEnv(t)
	for _, id := range []string{imgUbuntuID, imgLocalID} {
		p := e.propose(prepareReq(id, 9000), canonical.RiskLow)
		if p.Request.RiskClass != canonical.RiskHigh {
			t.Fatalf("%s: risk %s, want HIGH", id, p.Request.RiskClass)
		}
	}
	local, _ := e.imgs.Catalog.Lookup(imgLocalID)
	if local.Trust != ImageTrustLocal || ImagePrepareRisk(local) != canonical.RiskHigh {
		t.Fatalf("local entry %+v risk %s", local, ImagePrepareRisk(local))
	}
	// A higher requested risk is kept.
	if p := e.propose(prepareReq(imgLocalID, 9001), canonical.RiskCritical); p.Request.RiskClass != canonical.RiskCritical {
		t.Fatalf("critical lowered to %s", p.Request.RiskClass)
	}
}

func TestImagePrepareParametersBindProvenance(t *testing.T) {
	e := newImagesEnv(t)
	p := e.propose(prepareReq(imgLocalID, 9000), canonical.RiskLow)
	s := string(p.Parameters)
	for _, want := range []string{`"trust":"local"`, imgLocalSHA, imgLocalURL} {
		if !strings.Contains(s, want) {
			t.Fatalf("parameters lack %s: %s", want, s)
		}
	}
	p = e.propose(prepareReq(imgUbuntuID, 9000), canonical.RiskLow)
	if !strings.Contains(string(p.Parameters), `"trust":"signed"`) || !strings.Contains(string(p.Parameters), `"catalog_sequence":1`) {
		t.Fatalf("signed provenance missing: %s", p.Parameters)
	}
}

func TestImagePrepareRiskFloorRaisesAnyPrepareRequest(t *testing.T) {
	floor := ImagePrepareRiskFloor{Next: fixedRisk{}}
	r, why, err := floor.MinimumRisk(canonical.Request{ActionID: PveImagePrepareAction}, nil)
	if err != nil || r != canonical.RiskHigh || !strings.Contains(why, "ADR 0008") {
		t.Fatalf("prepare floor = %s %q %v", r, why, err)
	}
	if r, _, _ := floor.MinimumRisk(canonical.Request{ActionID: "pve.test.mutation"}, nil); r != canonical.RiskMedium {
		t.Fatalf("other action floor = %s", r)
	}
	if r, _, _ := (ImagePrepareRiskFloor{}).MinimumRisk(canonical.Request{ActionID: PveImagePrepareAction}, nil); r != canonical.RiskHigh {
		t.Fatalf("no next policy: %s", r)
	}
}

func TestImageCatalogRefusesUntrustedSigner(t *testing.T) {
	c := newCatalogAt(filepath.Join(t.TempDir(), "pve-catalog.json"))
	trusted, other := newReleaseSK(t), newReleaseSK(t)
	raw := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	if err := c.LoadSigned([]release.Root{trusted.root()}, raw, other.sign(t, raw)); !errors.Is(err, release.ErrUntrusted) {
		t.Fatalf("foreign signer: %v", err)
	}
	if err := c.LoadSigned(nil, raw, trusted.sign(t, raw)); !errors.Is(err, release.ErrUntrusted) {
		t.Fatalf("no roots: %v", err)
	}
	if _, ok := c.Lookup(imgUbuntuID); ok {
		t.Fatal("unverified catalog entry is visible")
	}
}

func TestImageCatalogRefusesRollback(t *testing.T) {
	c := newCatalogAt(filepath.Join(t.TempDir(), "pve-catalog.json"))
	sk := newReleaseSK(t)
	roots := []release.Root{sk.root()}
	v2 := catalogDoc(t, 2, ubuntuEntry(imgUbuntuSHA))
	if err := c.LoadSigned(roots, v2, sk.sign(t, v2)); err != nil {
		t.Fatal(err)
	}
	v1 := catalogDoc(t, 1, ubuntuEntry(imgLocalSHA))
	if err := c.LoadSigned(roots, v1, sk.sign(t, v1)); !errors.Is(err, ErrPveCatalogRollback) {
		t.Fatalf("older catalog: %v", err)
	}
	v2b := catalogDoc(t, 2, ubuntuEntry(imgLocalSHA))
	if err := c.LoadSigned(roots, v2b, sk.sign(t, v2b)); !errors.Is(err, ErrPveCatalogRollback) {
		t.Fatalf("conflicting catalog with the same sequence: %v", err)
	}
	if err := c.LoadSigned(roots, v2, sk.sign(t, v2)); err != nil {
		t.Fatalf("same catalog again: %v", err)
	}
	if img, _ := c.Lookup(imgUbuntuID); img.SHA256 != imgUbuntuSHA {
		t.Fatalf("catalog rolled back: %+v", img)
	}
}

func TestImageCatalogLocalEntryCannotShadowSigned(t *testing.T) {
	e := newImagesEnv(t)
	err := e.imgs.Catalog.AddLocal(release.Image{ID: imgUbuntuID, OS: "ubuntu", Release: "24.04", Arch: "amd64", URL: imgLocalURL, SHA256: imgLocalSHA, DiskFormat: "qcow2"})
	if !errors.Is(err, release.ErrFormat) {
		t.Fatalf("local entry with a signed id: %v", err)
	}
	if img, _ := e.imgs.Catalog.Lookup(imgUbuntuID); img.SHA256 != imgUbuntuSHA || img.Trust != ImageTrustSigned {
		t.Fatalf("signed entry shadowed: %+v", img)
	}
	if err := e.imgs.Catalog.AddLocal(release.Image{ID: "local-x", OS: "x", Release: "1", Arch: "amd64", URL: "http://insecure.example/x.qcow2", SHA256: imgLocalSHA, DiskFormat: "qcow2"}); !errors.Is(err, release.ErrFormat) {
		t.Fatalf("local http entry: %v", err)
	}
	if !e.imgs.Catalog.RemoveLocal(imgLocalID) {
		t.Fatal("remove local")
	}
	if _, _, err := e.imgs.ProposalRequest(context.Background(), prepareReq(imgLocalID, 9000), "00000000-0000-4000-b000-999999999999", canonical.RiskHigh,
		strings.Repeat("c", 64), time.Now().Add(time.Hour)); !errors.Is(err, ErrPveImageUnknown) {
		t.Fatalf("removed local entry: %v", err)
	}
}

func TestImagePrepareCatalogChangeAfterApprovalIsDenied(t *testing.T) {
	e := newImagesEnv(t)
	req := e.approveImage(prepareReq(imgUbuntuID, 9000))
	raw := catalogDoc(t, 2, ubuntuEntry(strings.Repeat("99", 32)))
	if err := e.imgs.Catalog.LoadSigned([]release.Root{e.sk.root()}, raw, e.sk.sign(t, raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.imgs.Prepare(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("prepare after catalog change: %v", err)
	}
	if len(e.client.dispatched()) != 0 {
		t.Fatal("dispatched after the catalog changed")
	}
	if _, ok, _ := e.store.PveTemplate(req.PveTemplateKey); ok {
		t.Fatal("template recorded without a preparation")
	}
}

func TestImagePrepareFailedStepRecordsNoTemplate(t *testing.T) {
	e := newImagesEnv(t)
	e.client.fakeMutClient.status = func(string) (PveTaskStatus, error) { return PveTaskStatus{ExitStatus: "checksum mismatch"}, nil }
	req := e.approveImage(prepareReq(imgUbuntuID, 9000))
	if _, err := e.imgs.Prepare(context.Background(), req); !errors.Is(err, ErrPveStepFailed) {
		t.Fatalf("failed download: %v", err)
	}
	if n := len(e.client.dispatched()); n != 1 {
		t.Fatalf("steps after a failed download: %d", n)
	}
	if _, ok, _ := e.store.PveTemplate(req.PveTemplateKey); ok {
		t.Fatal("template recorded after a failed step")
	}
}

func TestTemplateBindingIsExactAndDetectsOutsideChange(t *testing.T) {
	e := newImagesEnv(t)
	rec := e.prepare(prepareReq(imgUbuntuID, 9000))
	ctx := context.Background()
	if got, err := e.imgs.BindTemplate(ctx, bindingOf(rec)); err != nil || got.VMID != 9000 {
		t.Fatalf("bind = %+v %v", got, err)
	}
	for name, mut := range map[string]func(*PveTemplateBinding){
		"vmid":       func(b *PveTemplateBinding) { b.VMID = 9001 },
		"generation": func(b *PveTemplateBinding) { b.Generation = 2 },
		"source":     func(b *PveTemplateBinding) { b.SourceSHA256 = imgLocalSHA },
	} {
		b := bindingOf(rec)
		mut(&b)
		if _, err := e.imgs.BindTemplate(ctx, b); !errors.Is(err, ErrPveTemplateChanged) {
			t.Fatalf("%s mismatch: %v", name, err)
		}
	}
	other := bindingOf(rec)
	other.Storage = "ceph"
	if _, err := e.imgs.BindTemplate(ctx, other); !errors.Is(err, ErrPveTemplateNotPrepared) {
		t.Fatalf("unprepared key: %v", err)
	}
	// Someone edits the template in PVE: its configuration digest changes.
	e.client.setTemplateDigest(strings.Repeat("f0", 32))
	if _, err := e.imgs.BindTemplate(ctx, bindingOf(rec)); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("changed template: %v", err)
	}
	if !strings.Contains(e.logs.String(), "pve_template_changed") {
		t.Fatal("outside change not audited")
	}
}

func TestTemplateBindingFailsWhenCatalogWithdrawsImage(t *testing.T) {
	e := newImagesEnv(t)
	rec := e.prepare(prepareReq(imgUbuntuID, 9000))
	raw := catalogDoc(t, 2, ubuntuEntry(strings.Repeat("99", 32)))
	if err := e.imgs.Catalog.LoadSigned([]release.Root{e.sk.root()}, raw, e.sk.sign(t, raw)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(rec)); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("withdrawn digest: %v", err)
	}
}

func TestImagePrepareIsOneTimeUntilTemplateChanges(t *testing.T) {
	e := newImagesEnv(t)
	first := e.prepare(prepareReq(imgUbuntuID, 9000))
	_, _, err := e.imgs.ProposalRequest(context.Background(), prepareReq(imgUbuntuID, 9001), "00000000-0000-4000-b000-999999999998", canonical.RiskHigh,
		strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if !errors.Is(err, ErrPveImagePrepared) {
		t.Fatalf("second preparation of a valid template: %v", err)
	}
	// The template changed outside NOS: preparing again is allowed and
	// replaces the record with the next generation.
	e.client.setTemplateDigest(strings.Repeat("f0", 32))
	second := e.prepare(prepareReq(imgUbuntuID, 9001))
	if second.Generation != first.Generation+1 || second.VMID != 9001 || second.ConfigDigest != strings.Repeat("f0", 32) {
		t.Fatalf("re-preparation record = %+v", second)
	}
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(first)); !errors.Is(err, ErrPveTemplateChanged) {
		t.Fatalf("binding of the replaced generation: %v", err)
	}
	if _, err := e.imgs.BindTemplate(context.Background(), bindingOf(second)); err != nil {
		t.Fatalf("binding of the new generation: %v", err)
	}
}

// recordingImageWriter records the typed pveapi calls of image steps.
type recordingImageWriter struct {
	download     pveapi.DownloadRequest
	create       pveapi.ImageVMRequest
	templateNode string
	templateVMID int64
	calls        int
	err          error
}

func (w *recordingImageWriter) DownloadURL(_ context.Context, r pveapi.DownloadRequest) (string, error) {
	w.calls++
	w.download = r
	return "upid-download", w.err
}

func (w *recordingImageWriter) CreateImageVM(_ context.Context, r pveapi.ImageVMRequest) (string, error) {
	w.calls++
	w.create = r
	return "upid-create", w.err
}

func (w *recordingImageWriter) ConvertToTemplate(_ context.Context, node string, vmid int64) (string, error) {
	w.calls++
	w.templateNode, w.templateVMID = node, vmid
	return "upid-template", w.err
}

func TestDispatchImageStepRefusesMalformedSteps(t *testing.T) {
	cases := map[string]PveMutationStep{
		"unknown method": {Method: "pve.guest.start", Args: json.RawMessage(`{"vmid":9000}`)},
		"unknown field":  {Method: pveStepImageTemplate, Args: json.RawMessage(`{"vmid":9000,"force":1}`)},
		"trailing data":  {Method: pveStepImageTemplate, Args: json.RawMessage(`{"vmid":9000}{"vmid":1}`)},
		"wrong type":     {Method: pveStepImageTemplate, Args: json.RawMessage(`{"vmid":"9000"}`)},
		"empty":          {Method: pveStepImageDownload},
		"oversize":       {Method: pveStepImageDownload, Args: json.RawMessage(`{"url":"` + strings.Repeat("a", maxPveImageStepArgs) + `"}`)},
	}
	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			w := &recordingImageWriter{}
			if _, err := DispatchImageStep(context.Background(), w, "pve1", step); !errors.Is(err, ErrPveRejected) {
				t.Fatalf("err = %v, want ErrPveRejected", err)
			}
			if w.calls != 0 {
				t.Fatal("malformed step reached the writer")
			}
		})
	}
}

func TestDispatchImageStepClassifiesWriterErrors(t *testing.T) {
	step := PveMutationStep{Method: pveStepImageTemplate, Args: json.RawMessage(`{"vmid":9000}`)}
	for name, tc := range map[string]struct {
		err      error
		rejected bool
	}{
		"invalid argument": {fmt.Errorf("x: %w", pveapi.ErrInvalidArgument), true},
		"http 400":         {&pveapi.WriteError{Op: "template", Reason: pveapi.ReasonHTTPError, Status: 400}, true},
		"http 502":         {&pveapi.WriteError{Op: "template", Reason: pveapi.ReasonHTTPError, Status: 502}, false},
		"transport":        {&pveapi.WriteError{Op: "template", Reason: pveapi.ReasonTransport}, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DispatchImageStep(context.Background(), &recordingImageWriter{err: tc.err}, "pve1", step)
			if err == nil || errors.Is(err, ErrPveRejected) != tc.rejected {
				t.Fatalf("err = %v, rejected want %v", err, tc.rejected)
			}
		})
	}
}

func TestImageStepTaskTypes(t *testing.T) {
	for m, want := range map[string]string{pveStepImageDownload: "download", pveStepImageCreateVM: "qmcreate", pveStepImageTemplate: "qmtemplate"} {
		if got, ok := ImageStepTaskType(m); !ok || got != want {
			t.Fatalf("%s: %q %v", m, got, ok)
		}
	}
	if _, ok := ImageStepTaskType("guest.start"); ok {
		t.Fatal("non-image method allowed")
	}
}

func TestFilePveTemplateStoreIsDurableAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pve-templates.json")
	s := &FilePveTemplateStore{Path: path}
	key := PveTemplateKey{RemoteID: mutRemote, Node: "pve1", Storage: "local-lvm", ImageID: imgUbuntuID}
	if _, ok, err := s.PveTemplate(key); ok || err != nil {
		t.Fatalf("empty store: %v %v", ok, err)
	}
	rec := PveTemplateRecord{PveTemplateKey: key, Trust: ImageTrustSigned, VMID: 9000, Generation: 1, SourceSHA256: imgUbuntuSHA,
		ConfigDigest: strings.Repeat("e1", 32), TrustGeneration: 1, ExecutionID: "x", PreparedAt: time.Unix(1700000000, 0).UTC()}
	if err := s.PutPveTemplate(rec); err != nil {
		t.Fatal(err)
	}
	rec.Generation = 2
	if err := s.PutPveTemplate(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := (&FilePveTemplateStore{Path: path}).PveTemplate(key)
	if err != nil || !ok || got != rec {
		t.Fatalf("reloaded = %+v %v %v", got, ok, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v %v", fi.Mode(), err)
	}
	for name, content := range map[string][]byte{
		"garbage":       []byte("{not json"),
		"unknown field": []byte(`[{"remote_id":"x","evil":1}]`),
		"oversize":      make([]byte, maxPveTemplateStore+1),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.PveTemplate(key); err == nil {
			t.Fatalf("%s: corrupt store accepted", name)
		}
	}
}

// A broken record store fails preparation proposals and bindings closed.
func TestImageTemplateStoreErrorsFailClosed(t *testing.T) {
	e := newImagesEnv(t)
	if err := os.WriteFile(e.store.Path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := e.imgs.ProposalRequest(context.Background(), prepareReq(imgUbuntuID, 9000), "00000000-0000-4000-b000-999999999997", canonical.RiskHigh,
		strings.Repeat("c", 64), time.Now().Add(time.Hour))
	if !errors.Is(err, ErrPveTemplateStore) {
		t.Fatalf("proposal with a broken store: %v", err)
	}
	b := PveTemplateBinding{PveTemplateKey: prepareReq(imgUbuntuID, 9000).PveTemplateKey, VMID: 9000, Generation: 1, SourceSHA256: imgUbuntuSHA}
	if _, err := e.imgs.BindTemplate(context.Background(), b); !errors.Is(err, ErrPveTemplateStore) {
		t.Fatalf("binding with a broken store: %v", err)
	}
}
