// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// This file tests the image preparation RPCs (ProposePVEImagePrepare,
// CommitPVEImagePrepare; ADR 0008 PV-03b part 3, D1 (a)) and the catalog
// load function (LoadPVEImageCatalog, D2 (a)).

// imagePrepareRPCEnv is the provisioning RPC environment (the Service's
// own engine, provisioner, VMID store and authority with the virtual
// authenticator) with no template prepared yet and template reads served
// by a pinned TLS PVE fake on loopback through the production client.
type imagePrepareRPCEnv struct {
	*provisionRPCEnv
	images *PveImages
	pve    *fakeTemplatePVE
	cfg    string
	base   int
}

func newImagePrepareRPCEnv(t *testing.T) *imagePrepareRPCEnv {
	t.Helper()
	e := newProvisionRPCEnv(t)
	p := e.svc.pveProvisioner()
	if p == nil || p.Images == nil {
		t.Fatal("no provisioner")
	}
	// No template record: the preparation below is the first of the key.
	p.Images.Templates = &FilePveTemplateStore{Path: filepath.Join(t.TempDir(), pveTemplatesFile)}
	chain := makeTestChain(t)
	f := newFakeTemplatePVE(t, chain.tls)
	e.client.setTemplateReader(loopbackTemplateReader{c: testMutClient(chain), ep: f.ep})
	cfg := templateConfigJSON("tpl-ubuntu-24-04-amd64")
	f.set(replyStatus(http.StatusOK, cfg))
	return &imagePrepareRPCEnv{provisionRPCEnv: e, images: p.Images, pve: f, cfg: cfg, base: len(e.client.dispatched())}
}

// sent returns the image steps dispatched since the environment was built
// (its setup prepares a template of its own on the shared fake).
func (e *imagePrepareRPCEnv) sent() []PveMutationStep {
	return e.client.dispatched()[e.base:]
}

func imageSpec(id string, vmid uint64) *pb.PVEImagePrepareSpec {
	return &pb.PVEImagePrepareSpec{RemoteId: mutRemote, Node: "pve1", Storage: "local-lvm", ImageId: id, ImportStorage: "local", Vmid: vmid}
}

func (e *imagePrepareRPCEnv) propose(uid uint32, spec *pb.PVEImagePrepareSpec) (*pb.ProposePVEImagePrepareResponse, error) {
	out, reached, err := call(uid, pb.ExecutorService_ProposePVEImagePrepare_FullMethodName, nil, e.svc.ProposePVEImagePrepare,
		&pb.ProposePVEImagePrepareRequest{Spec: spec})
	if !reached && err == nil {
		e.t.Fatal("propose not reached")
	}
	return out, err
}

func (e *imagePrepareRPCEnv) commit(uid uint32, spec *pb.PVEImagePrepareSpec, digest string) (*pb.CommitPVEImagePrepareResponse, error) {
	out, _, err := call(uid, pb.ExecutorService_CommitPVEImagePrepare_FullMethodName, nil, e.svc.CommitPVEImagePrepare,
		&pb.CommitPVEImagePrepareRequest{Spec: spec, ExecutionDigest: digest})
	return out, err
}

func (e *imagePrepareRPCEnv) assert(digest string, challenge []byte, verified bool) (*pb.SubmitAssertionResponse, error) {
	return e.svc.SubmitAssertion(context.Background(), &pb.SubmitAssertionRequest{ExecutionDigest: digest, AssertionJson: e.sign(challenge, verified)})
}

// TestImagePrepareRPCThenGuestProvisionSucceeds is the mandatory test of
// PV-03b: the server proposes pve.image.prepare over the RPC and gets a
// HIGH permit that needs the user's verified assertion; a commit before
// the approval, a presence-only assertion, a commit with another spec and
// a replay are refused and send nothing. After the verified approval the
// commit downloads, creates and converts the template and writes the
// record, which BindTemplate accepts. ProposePVEGuestProvision for exactly
// this template then succeeds: no error, a provisioning permit in the
// response and the VMID reserved for that execution. Any other outcome
// (ErrPveTemplateChanged, ErrPveRemoteChanged, ErrPveVMIDTaken, ...) fails.
func TestImagePrepareRPCThenGuestProvisionSucceeds(t *testing.T) {
	e := newImagePrepareRPCEnv(t)
	ctx := context.Background()
	spec := imageSpec(imgUbuntuID, 9000)

	prop, err := e.propose(localTestServerUID, spec)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	pm := prop.GetPermit()
	if pm.GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH || pm.GetState() != pb.PermitState_PERMIT_STATE_PENDING ||
		pm.GetApprovalRequirement() != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED || len(pm.GetChallenge()) == 0 {
		t.Fatalf("permit risk %v state %v requirement %v challenge %d, want pending HIGH with user verification",
			pm.GetRiskClass(), pm.GetState(), pm.GetApprovalRequirement(), len(pm.GetChallenge()))
	}
	if img := prop.GetImage(); img.GetImage().GetId() != imgUbuntuID || img.GetImage().GetSha256() != imgUbuntuSHA ||
		img.GetTrust() != string(ImageTrustSigned) || img.GetCatalogSequence() != 1 {
		t.Fatalf("proposed image %+v", img)
	}
	digest := pm.GetExecutionDigest()

	// The permit is the gate: not approved, nothing is sent.
	if _, err := e.commit(localTestServerUID, spec, digest); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("commit before approval: %v, want PermissionDenied", err)
	}
	e.openSession(t)
	if _, err := e.assert(digest, pm.GetChallenge(), false); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("presence-only approval of a HIGH preparation: %v, want PermissionDenied", err)
	}
	if _, err := e.commit(localTestServerUID, spec, digest); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("commit after a refused approval: %v, want PermissionDenied", err)
	}
	if n := len(e.sent()); n != 0 {
		t.Fatalf("%d steps sent without an approved permit", n)
	}

	approved, err := e.assert(digest, pm.GetChallenge(), true)
	if err != nil || approved.GetState() != pb.PermitState_PERMIT_STATE_APPROVED {
		t.Fatalf("verified approval: %+v %v", approved, err)
	}
	other := imageSpec(imgUbuntuID, 9001)
	if _, err := e.commit(localTestServerUID, other, digest); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("commit with another vmid: %v, want PermissionDenied", err)
	}
	if n := len(e.sent()); n != 0 {
		t.Fatalf("%d steps sent for a changed spec", n)
	}

	res, err := e.commit(localTestServerUID, spec, digest)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	var methods []string
	for _, st := range e.sent() {
		methods = append(methods, st.Method)
	}
	if strings.Join(methods, ",") != strings.Join([]string{pveStepImageDownload, pveStepImageCreateVM, pveStepImageTemplate}, ",") {
		t.Fatalf("steps %v", methods)
	}
	tpl := res.GetTemplate()
	if tpl.GetVmid() != 9000 || tpl.GetGeneration() != 1 || tpl.GetSourceSha256() != imgUbuntuSHA || tpl.GetTrust() != string(ImageTrustSigned) ||
		tpl.GetConfigDigest() != configDigestOf(t, e.cfg) || tpl.GetExecutionId() == "" || res.GetExecutionId() != tpl.GetExecutionId() ||
		tpl.GetRemoteId() != mutRemote || tpl.GetNode() != "pve1" || tpl.GetStorage() != "local-lvm" || tpl.GetImageId() != imgUbuntuID {
		t.Fatalf("template record %+v", tpl)
	}
	if _, err := e.commit(localTestServerUID, spec, digest); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("replayed commit: %v, want PermissionDenied", err)
	}
	if n := len(e.sent()); n != 3 {
		t.Fatalf("%d steps after the replay, want 3", n)
	}

	binding := PveTemplateBinding{
		PveTemplateKey: PveTemplateKey{RemoteID: tpl.GetRemoteId(), Node: tpl.GetNode(), Storage: tpl.GetStorage(), ImageID: tpl.GetImageId()},
		VMID:           tpl.GetVmid(), Generation: tpl.GetGeneration(), SourceSHA256: tpl.GetSourceSha256(),
	}
	if _, err := e.images.BindTemplate(ctx, binding); err != nil {
		t.Fatalf("bind of the prepared template: %v", err)
	}
	// The record and the binding came from template reads over the pinned
	// loopback PVE fake, which saw GETs only.
	if len(e.pve.requests()) == 0 || e.pve.writeCount() != 0 {
		t.Fatalf("PVE fake requests %v, writes %d", e.pve.requests(), e.pve.writeCount())
	}

	gp, reached, err := call(localTestServerUID, pb.ExecutorService_ProposePVEGuestProvision_FullMethodName, nil, e.svc.ProposePVEGuestProvision,
		&pb.ProposePVEGuestProvisionRequest{Spec: testProvisionSpec(binding, PveAutomationCredentialRef)})
	if !reached || err != nil {
		t.Fatalf("provision proposal for the prepared template: reached %v err %v", reached, err)
	}
	gpm := gp.GetPermit()
	if gpm == nil || gpm.GetState() != pb.PermitState_PERMIT_STATE_PENDING || gp.GetExecutionId() == "" {
		t.Fatalf("provision proposal %+v", gp)
	}
	d, err := canonical.ParseDigest(gpm.GetExecutionDigest())
	if err != nil {
		t.Fatalf("provision permit digest: %v", err)
	}
	if st, ok := e.auth.PermitState(d); !ok || st != permit.StatePending {
		t.Fatalf("provision permit %v %v, want registered and pending", st, ok)
	}
	if gp.GetVmid() < pvecontract.MinVMID || gp.GetVmid() == binding.VMID {
		t.Fatalf("provision vmid %d", gp.GetVmid())
	}
	holder, ok, err := e.svc.pveProvisioner().VMIDs.VMIDHolder(mutRemote, gp.GetVmid(), e.svc.clock())
	if err != nil || !ok || holder.ExecutionID != gp.GetExecutionId() {
		t.Fatalf("vmid %d holder %+v %v %v, want reserved for %s", gp.GetVmid(), holder, ok, err, gp.GetExecutionId())
	}
}

// TestImagePrepareRPCsRefuseCollector: the pve-collector reaches neither
// RPC through the role table, and the handlers refuse it (and a caller
// without a role) even past a wide role table. Nothing is proposed or sent.
func TestImagePrepareRPCsRefuseCollector(t *testing.T) {
	e := newImagePrepareRPCEnv(t)
	spec := imageSpec(imgUbuntuID, 9000)
	digest := canonical.Digest{}.String()
	propM, commitM := pb.ExecutorService_ProposePVEImagePrepare_FullMethodName, pb.ExecutorService_CommitPVEImagePrepare_FullMethodName

	if _, reached, err := call(localTestCollUID, propM, nil, e.svc.ProposePVEImagePrepare, &pb.ProposePVEImagePrepareRequest{Spec: spec}); reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector propose: reached %v err %v", reached, err)
	}
	if _, reached, err := call(localTestCollUID, commitM, nil, e.svc.CommitPVEImagePrepare, &pb.CommitPVEImagePrepareRequest{Spec: spec, ExecutionDigest: digest}); reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector commit: reached %v err %v", reached, err)
	}
	wide := MethodRoles()
	wide[propM] = []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector}
	wide[commitM] = wide[propM]
	if _, reached, err := call(localTestCollUID, propM, wide, e.svc.ProposePVEImagePrepare, &pb.ProposePVEImagePrepareRequest{Spec: spec}); !reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector propose past a wide role table: reached %v err %v", reached, err)
	}
	if _, reached, err := call(localTestCollUID, commitM, wide, e.svc.CommitPVEImagePrepare, &pb.CommitPVEImagePrepareRequest{Spec: spec, ExecutionDigest: digest}); !reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector commit past a wide role table: reached %v err %v", reached, err)
	}
	if _, err := e.svc.ProposePVEImagePrepare(context.Background(), &pb.ProposePVEImagePrepareRequest{Spec: spec}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("propose without a caller: %v", err)
	}
	if _, err := e.svc.CommitPVEImagePrepare(context.Background(), &pb.CommitPVEImagePrepareRequest{Spec: spec, ExecutionDigest: digest}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("commit without a caller: %v", err)
	}
	if n := len(e.sent()); n != 0 {
		t.Fatalf("%d steps sent for refused callers", n)
	}
	if strings.Contains(e.logs.String(), "pve_image_prepare_proposed") {
		t.Fatal("a refused caller's proposal was registered")
	}
}

// TestImagePrepareRPCRejectsMalformedSpecs: a missing, empty, oversize or
// non-UTF-8 field, an invalid node name, a VMID out of range or a
// malformed digest is InvalidArgument; nothing is proposed or sent.
func TestImagePrepareRPCRejectsMalformedSpecs(t *testing.T) {
	e := newImagePrepareRPCEnv(t)
	for name, mod := range map[string]func(*pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec{
		"nil":           func(*pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec { return nil },
		"empty storage": func(s *pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec { s.Storage = ""; return s },
		"oversize image": func(s *pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec {
			s.ImageId = strings.Repeat("a", 256)
			return s
		},
		"non-utf8":  func(s *pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec { s.ImportStorage = "loc\xffal"; return s },
		"bad node":  func(s *pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec { s.Node = "pve1/../x"; return s },
		"vmid zero": func(s *pb.PVEImagePrepareSpec) *pb.PVEImagePrepareSpec { s.Vmid = 0; return s },
	} {
		t.Run(name, func(t *testing.T) {
			spec := mod(imageSpec(imgUbuntuID, 9000))
			if _, err := e.propose(localTestAdminUID, spec); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("propose: %v, want InvalidArgument", err)
			}
			if _, err := e.commit(localTestAdminUID, spec, canonical.Digest{}.String()); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("commit: %v, want InvalidArgument", err)
			}
		})
	}
	if _, err := e.commit(localTestAdminUID, imageSpec(imgUbuntuID, 9000), "not-a-digest"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed digest: %v, want InvalidArgument", err)
	}
	if n := len(e.sent()); n != 0 {
		t.Fatalf("%d steps sent for malformed specs", n)
	}
}

// TestImagePrepareRPCRefusesPreparedAndUnknownImages: an image whose
// template is still valid is AlreadyExists and an image in no catalog is
// NotFound; neither registers a permit.
func TestImagePrepareRPCRefusesPreparedAndUnknownImages(t *testing.T) {
	e := newImagePrepareRPCEnv(t)
	if _, err := e.propose(localTestAdminUID, imageSpec("debian-12-amd64", 9000)); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown image: %v, want NotFound", err)
	}
	approved := e.approveImage(prepareReq(imgUbuntuID, 9000))
	if _, err := e.images.Prepare(context.Background(), approved); err != nil {
		t.Fatal(err)
	}
	if _, err := e.propose(localTestAdminUID, imageSpec(imgUbuntuID, 9001)); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("prepared image: %v, want AlreadyExists", err)
	}
	// An unreadable template refuses the re-preparation (D5).
	e.pve.set(replyStatus(http.StatusInternalServerError, `{"data":null}`))
	if _, err := e.propose(localTestAdminUID, imageSpec(imgUbuntuID, 9001)); status.Code(err) != codes.Unavailable {
		t.Fatalf("unreadable template: %v, want Unavailable", err)
	}
}

// catalogLoadEnv is the RPC environment with a fresh, empty production
// style catalog (durable rollback state in its own file, in-memory local
// entries), so LoadPVEImageCatalog is the only way a signed catalog gets
// in.
type catalogLoadEnv struct {
	*imagePrepareRPCEnv
	cat   *PveImageCatalog
	state string
}

func newCatalogLoadEnv(t *testing.T) *catalogLoadEnv {
	t.Helper()
	e := newImagePrepareRPCEnv(t)
	state := filepath.Join(t.TempDir(), pveCatalogStateFile)
	cat := newCatalogAt(state)
	if err := cat.AddLocal(localRocky()); err != nil {
		t.Fatal(err)
	}
	e.images.Catalog = cat
	return &catalogLoadEnv{imagePrepareRPCEnv: e, cat: cat, state: state}
}

func (e *catalogLoadEnv) load(raw, sig []byte) error {
	return e.svc.LoadPVEImageCatalog([]release.Root{e.sk.root()}, bytes.NewReader(raw), bytes.NewReader(sig))
}

func (e *catalogLoadEnv) stateBytes() []byte {
	e.t.Helper()
	b, err := os.ReadFile(e.state)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// TestLoadPVEImageCatalogLoadsSignedCatalog: a catalog signed by an
// active release root loads, its sequence is persisted, and its images
// can be proposed.
func TestLoadPVEImageCatalogLoadsSignedCatalog(t *testing.T) {
	e := newCatalogLoadEnv(t)
	if _, err := e.propose(localTestAdminUID, imageSpec(imgUbuntuID, 9000)); status.Code(err) != codes.NotFound {
		t.Fatalf("signed image before the catalog is loaded: %v, want NotFound", err)
	}
	raw := catalogDoc(t, 3, ubuntuEntry(imgUbuntuSHA))
	if err := e.load(raw, e.sk.sign(t, raw)); err != nil {
		t.Fatalf("load: %v", err)
	}
	if st, ok, err := e.cat.State.PveCatalogState(); err != nil || !ok || st.Sequence != 3 {
		t.Fatalf("persisted state %+v %v %v", st, ok, err)
	}
	prop, err := e.propose(localTestAdminUID, imageSpec(imgUbuntuID, 9000))
	if err != nil || prop.GetImage().GetCatalogSequence() != 3 {
		t.Fatalf("propose after load: %+v %v", prop, err)
	}
}

// TestLoadPVEImageCatalogRefusals: an unsigned catalog (no signature, or
// one by a key that is not a release root), an oversize catalog or
// signature and a rolled-back catalog are refused with their sentinel;
// nothing is persisted, the loaded catalog (if any) stays, every signed
// image of a refused catalog is NotFound (ErrPveImageUnknown), and the
// local entry stays preparable.
func TestLoadPVEImageCatalogRefusals(t *testing.T) {
	stranger := newReleaseSK(t)
	for _, tc := range []struct {
		name string
		// prior is loaded first (sequence; 0: none).
		prior int
		in    func(t *testing.T, e *catalogLoadEnv) (raw, sig []byte)
		want  []error
	}{
		{"no signature", 0, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			return catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA)), nil
		}, []error{release.ErrFormat}},
		{"untrusted key", 0, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			raw := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
			return raw, stranger.sign(t, raw)
		}, []error{release.ErrUntrusted, release.ErrSignature}},
		{"signature of other bytes", 0, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			raw := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
			return raw, e.sk.sign(t, catalogDoc(t, 2, ubuntuEntry(imgUbuntuSHA)))
		}, []error{release.ErrSignature, release.ErrUntrusted}},
		{"oversize catalog", 0, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			raw := bytes.Repeat([]byte(" "), release.MaxCatalog+1)
			return raw, e.sk.sign(t, raw)
		}, []error{release.ErrFormat}},
		{"oversize signature", 0, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			return catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA)), bytes.Repeat([]byte("A"), release.MaxSignature+1)
		}, []error{release.ErrFormat}},
		{"rollback", 5, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			raw := catalogDoc(t, 4, ubuntuEntry(strings.Repeat("6b", 32)))
			return raw, e.sk.sign(t, raw)
		}, []error{ErrPveCatalogRollback}},
		{"same sequence other bytes", 5, func(t *testing.T, e *catalogLoadEnv) ([]byte, []byte) {
			raw := catalogDoc(t, 5, ubuntuEntry(strings.Repeat("6b", 32)))
			return raw, e.sk.sign(t, raw)
		}, []error{ErrPveCatalogRollback}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newCatalogLoadEnv(t)
			if tc.prior != 0 {
				raw := catalogDoc(t, tc.prior, ubuntuEntry(imgUbuntuSHA))
				if err := e.load(raw, e.sk.sign(t, raw)); err != nil {
					t.Fatal(err)
				}
			}
			before := e.stateBytes()
			raw, sig := tc.in(t, e)
			err := e.load(raw, sig)
			matched := false
			for _, w := range tc.want {
				matched = matched || errors.Is(err, w)
			}
			if !matched {
				t.Fatalf("load: %v, want one of %v", err, tc.want)
			}
			if after := e.stateBytes(); !bytes.Equal(before, after) {
				t.Fatalf("refused catalog changed the state: %q -> %q", before, after)
			}
			if !strings.Contains(e.logs.String(), "pve_image_catalog_refused") {
				t.Fatal("no audit line for the refused catalog")
			}
			l, err := e.cat.CatalogListing()
			if err != nil {
				t.Fatal(err)
			}
			if int(l.Sequence) != tc.prior {
				t.Fatalf("loaded sequence %d after a refused catalog, want %d", l.Sequence, tc.prior)
			}
			if tc.prior == 0 {
				if _, err := e.propose(localTestAdminUID, imageSpec(imgUbuntuID, 9000)); status.Code(err) != codes.NotFound {
					t.Fatalf("signed image without a signed catalog: %v, want NotFound", err)
				}
				if _, _, err := e.images.ProposalRequest(context.Background(), prepareReq(imgUbuntuID, 9000), "00000000-0000-4000-b000-999999999990",
					canonical.RiskHigh, pveImagePrepareStagePlan, e.svc.clock().Add(pveImagePrepareLifetime)); !errors.Is(err, ErrPveImageUnknown) {
					t.Fatalf("signed image without a signed catalog: %v, want ErrPveImageUnknown", err)
				}
			} else if img, ok := e.cat.Lookup(imgUbuntuID); !ok || img.SHA256 != imgUbuntuSHA {
				t.Fatalf("loaded catalog replaced by a refused one: %+v %v", img, ok)
			}
			// The local entry carries its own trust and stays preparable.
			prop, err := e.propose(localTestAdminUID, imageSpec(imgLocalID, 9000))
			if err != nil || prop.GetImage().GetTrust() != string(ImageTrustLocal) || prop.GetPermit().GetRiskClass() != pb.RiskClass_RISK_CLASS_HIGH {
				t.Fatalf("local entry after a refused catalog: %+v %v", prop, err)
			}
		})
	}
}

// TestLoadPVEImageCatalogWithoutStateDirectory: an executor without a
// state directory loads no catalog and says so with ErrPveCatalogState.
func TestLoadPVEImageCatalogWithoutStateDirectory(t *testing.T) {
	logs := &syncBuffer{}
	svc := &Service{log: slog.New(slog.NewJSONHandler(logs, nil))}
	sk := newReleaseSK(t)
	raw := catalogDoc(t, 1, ubuntuEntry(imgUbuntuSHA))
	if err := svc.LoadPVEImageCatalog([]release.Root{sk.root()}, bytes.NewReader(raw), bytes.NewReader(sk.sign(t, raw))); !errors.Is(err, ErrPveCatalogState) {
		t.Fatalf("load without a state directory: %v, want ErrPveCatalogState", err)
	}
}
