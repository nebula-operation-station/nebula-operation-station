// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// PV-03h (ADR 0008 amendment 2, D4a and D4b): the Images page under /deploy
// and the wizard's image, SHA-256 and template choices come from the
// executor's ListPVEImages. The executor is the only authority: the page
// shows what it answers, and the wizard accepts only a template record it
// lists. Every string from the executor is untrusted and rendered as text;
// only an https URL without user info becomes a link.

// DeployImages reads the image catalog and the prepared template records
// (ListPVEImages, server role, read-only). executorclient.Client satisfies
// it. A DeployProvisioner value that lacks it shows the page as not
// available.
type DeployImages interface {
	ListPVEImages(ctx context.Context, in *pb.ListPVEImagesRequest, opts ...grpc.CallOption) (*pb.ListPVEImagesResponse, error)
}

// deployImagesCSP is the Content-Security-Policy of the Images page, in the
// style of the other pages (middleware.valueCSP): no inline script or style,
// no framing, no plugins.
const deployImagesCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

// pveImageRow is one catalog entry as the page shows it.
type pveImageRow struct {
	ID, OS, Release, Arch, URL, SHA256, DiskFormat, Trust string
	// Link is the URL when it is an https link, otherwise empty.
	Link string
	// CatalogSequence is the signed catalog the entry came from (0 local).
	CatalogSequence int64
}

// pveTemplateRow is one prepared template record as the page shows it.
type pveTemplateRow struct {
	Remote, Node, Storage, Image, Trust, SourceSHA256, ConfigDigest string
	VMID, Generation, TrustGeneration                               uint64
	ExecutionID                                                     string
	PreparedAt                                                      time.Time
}

// pveImagesView is what the page and the wizard need from the executor.
type pveImagesView struct {
	// Available is false when the executor did not answer; the lists are
	// then empty and must not be read as "nothing prepared".
	Available       bool
	CatalogSequence int64
	CatalogDigest   string
	Images          []pveImageRow
	Templates       []pveTemplateRow
}

// deployImagesData is the data of the Images page.
type deployImagesData struct {
	View pveImagesView
	// CanPrepare is true when the executor can propose a preparation.
	CanPrepare bool
	// Prepares are the user's proposed preparations.
	Prepares []imagePrepare
}

// safeHTTPSLink returns raw when it is an absolute https URL without user
// info or fragment (the catalog allows neither, so a link must not carry
// them); otherwise it returns "" and the URL is shown as text only.
func safeHTTPSLink(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return ""
	}
	return raw
}

const (
	// maxPVECatalogEntries bounds the catalog entries taken from the
	// executor's ListPVEImages answer.
	maxPVECatalogEntries = 256
	// maxPVETemplateRecords bounds the template records taken from it.
	maxPVETemplateRecords = 1024
	// maxPVEImageText bounds every string of the answer (the longest is a
	// catalog URL).
	maxPVEImageText = 2048
)

// errPVEImagesAnswer marks an executor answer over the limits; the page and
// the wizard then treat the catalog as not available.
var errPVEImagesAnswer = errors.New("executor image answer over the limits")

// checkPVEImagesAnswer refuses an answer with too many entries or records,
// or with a string that is too long or not UTF-8.
func checkPVEImagesAnswer(resp *pb.ListPVEImagesResponse) error {
	if n := len(resp.GetImages()); n > maxPVECatalogEntries {
		return fmt.Errorf("%w: %d catalog entries", errPVEImagesAnswer, n)
	}
	if n := len(resp.GetTemplates()); n > maxPVETemplateRecords {
		return fmt.Errorf("%w: %d template records", errPVEImagesAnswer, n)
	}
	strs := []string{resp.GetCatalogDigest()}
	for _, img := range resp.GetImages() {
		c := img.GetImage()
		strs = append(strs, c.GetId(), c.GetOs(), c.GetRelease(), c.GetArch(), c.GetUrl(), c.GetSha256(), c.GetDiskFormat(), img.GetTrust())
	}
	for _, t := range resp.GetTemplates() {
		strs = append(strs, t.GetRemoteId(), t.GetNode(), t.GetStorage(), t.GetImageId(), t.GetTrust(), t.GetSourceSha256(),
			t.GetConfigDigest(), t.GetExecutionId())
	}
	for _, s := range strs {
		if len(s) > maxPVEImageText || !utf8.ValidString(s) {
			return fmt.Errorf("%w: a string is too long or not UTF-8", errPVEImagesAnswer)
		}
	}
	return nil
}

// loadPVEImages asks the executor for the catalog and the records. An
// error, an answer over the limits or a missing capability leaves Available
// false.
func (h *Handler) loadPVEImages(ctx context.Context) pveImagesView {
	images, ok := h.deploy.(DeployImages)
	if !ok || images == nil {
		return pveImagesView{}
	}
	resp, err := images.ListPVEImages(ctx, &pb.ListPVEImagesRequest{})
	if err != nil {
		h.log.Error("deploy images: list", "error", err)
		return pveImagesView{}
	}
	if err := checkPVEImagesAnswer(resp); err != nil {
		h.log.Error("deploy images: executor answer refused", "error", err)
		return pveImagesView{}
	}
	v := pveImagesView{Available: true, CatalogSequence: resp.GetCatalogSequence(), CatalogDigest: resp.GetCatalogDigest()}
	for _, img := range resp.GetImages() {
		c := img.GetImage()
		v.Images = append(v.Images, pveImageRow{ID: c.GetId(), OS: c.GetOs(), Release: c.GetRelease(), Arch: c.GetArch(),
			URL: c.GetUrl(), Link: safeHTTPSLink(c.GetUrl()), SHA256: c.GetSha256(), DiskFormat: c.GetDiskFormat(),
			Trust: img.GetTrust(), CatalogSequence: img.GetCatalogSequence()})
	}
	for _, t := range resp.GetTemplates() {
		v.Templates = append(v.Templates, pveTemplateRow{Remote: t.GetRemoteId(), Node: t.GetNode(), Storage: t.GetStorage(),
			Image: t.GetImageId(), Trust: t.GetTrust(), VMID: t.GetVmid(), Generation: t.GetGeneration(),
			SourceSHA256: t.GetSourceSha256(), ConfigDigest: t.GetConfigDigest(), TrustGeneration: t.GetTrustGeneration(),
			ExecutionID: t.GetExecutionId(), PreparedAt: time.Unix(t.GetPreparedAtUnix(), 0).UTC()})
	}
	return v
}

// handleDeployImages renders the read-only Images page (PV-03h, D4a).
func (h *Handler) handleDeployImages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	hd := w.Header()
	hd.Set("Content-Security-Policy", deployImagesCSP)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")
	d := &deployImagesData{View: h.loadPVEImages(ctx)}
	if prep, ok := h.deploy.(DeployImagePreparer); ok && prep != nil && h.pve != nil && h.pveRemotes != nil {
		d.CanPrepare = d.View.Available
		d.Prepares = h.imagePrepares.list(webUser(r), h.clockNow())
	}
	h.render(w, r, pageData{Title: "Deploy Images", Active: "deploy", Content: "deploy_images",
		Scripts: []string{"webauthn.js", "schedules.js", "formpost.js"}, DeployImages: d})
}

// templateRecord returns the generation of the executor's template record
// for the chosen remote, node, storage, image, SHA-256 and VMID. The record
// is the only source of the template reference (PVETemplateRef.Generation);
// anything that is not a listed record is refused.
func (h *Handler) templateRecord(ctx context.Context, d deployForm) (uint64, error) {
	v := h.loadPVEImages(ctx)
	if !v.Available {
		return 0, formError("the executor's image catalog is not available: no template can be chosen")
	}
	for _, t := range v.Templates {
		if t.Remote == d.Remote && t.Node == d.Node && t.Storage == d.Storage && t.Image == d.Image &&
			t.SourceSHA256 == d.TemplateSHA256 && t.VMID == d.TemplateVMID {
			if _, ok := v.catalogEntry(t); !ok {
				return 0, formError("the template was prepared from an image SHA-256 the catalog no longer lists: prepare it again on the Images page")
			}
			return t.Generation, nil
		}
	}
	return 0, formError("the template is not a prepared record for this node, storage, image and SHA-256: prepare it on the Images page first")
}

// catalogEntry returns the catalog entry the record t was prepared from:
// same image ID and the SHA-256 the catalog lists today. The executor binds
// only such a record (BindTemplate compares the record's SHA-256 with the
// catalog), so a record without one cannot be provisioned from.
func (v pveImagesView) catalogEntry(t pveTemplateRow) (pveImageRow, bool) {
	for _, img := range v.Images {
		if img.ID == t.Image && img.SHA256 == t.SourceSHA256 {
			return img, true
		}
	}
	return pveImageRow{}, false
}

// wizardImages fills the wizard's choices from the executor (PV-03h, D4b).
// Every choice comes from a template record that can be bound: a record of
// the chosen remote and node, on the profile's storage when one is set,
// whose image and SHA-256 the catalog lists today. The image and SHA-256
// lists are those of the offered records, so every option belongs to one.
// A record prepared from a SHA-256 the catalog has since replaced is not
// offered; a note asks to prepare it again. Without the executor's answer
// the wizard offers no template.
func (h *Handler) wizardImages(ctx context.Context, d *deployWizardData) {
	v := h.loadPVEImages(ctx)
	if !v.Available {
		d.Notes = append(d.Notes, "The executor's image catalog is not available: no prepared template can be chosen.")
		return
	}
	seenImage, seenSHA := map[string]bool{}, map[string]bool{}
	stale := 0
	for _, t := range v.Templates {
		if t.Remote != d.Remote || t.Node != d.Node || (d.Storage != "" && t.Storage != d.Storage) {
			continue
		}
		img, ok := v.catalogEntry(t)
		if !ok {
			stale++
			continue
		}
		d.Templates = append(d.Templates, deployOption{Value: strconv.FormatUint(t.VMID, 10), Label: templateOptionLabel(t)})
		if !seenImage[img.ID] {
			seenImage[img.ID] = true
			d.Images = append(d.Images, deployOption{Value: img.ID,
				Label:    img.ID + " (" + img.OS + " " + img.Release + ", " + img.Arch + ")",
				Selected: img.ID == d.Image})
		}
		if !seenSHA[img.SHA256] {
			seenSHA[img.SHA256] = true
			d.Digests = append(d.Digests, deployOption{Value: img.SHA256, Label: img.SHA256 + " (" + img.ID + ")"})
		}
	}
	if stale > 0 {
		d.Notes = append(d.Notes, strconv.Itoa(stale)+" template record(s) on this node were prepared from an image SHA-256 the catalog no longer lists and cannot be used: prepare it again on the Images page.")
	}
	if len(d.Templates) == 0 {
		d.Notes = append(d.Notes, "No usable prepared template on this node and storage: prepare one on the Images page.")
	}
}

// ---- Preparation (pve.image.prepare, D1a) ---------------------------------

// DeployImagePreparer proposes and runs an image preparation (server role,
// HIGH; the user's security key assertion approves it). executorclient.Client
// satisfies it. A DeployProvisioner value that lacks it offers no
// preparation.
type DeployImagePreparer interface {
	ProposePVEImagePrepare(ctx context.Context, in *pb.ProposePVEImagePrepareRequest, opts ...grpc.CallOption) (*pb.ProposePVEImagePrepareResponse, error)
	CommitPVEImagePrepare(ctx context.Context, in *pb.CommitPVEImagePrepareRequest, opts ...grpc.CallOption) (*pb.CommitPVEImagePrepareResponse, error)
}

const (
	// maxImagePrepares bounds the preparations the page keeps in memory.
	maxImagePrepares = 32
	// maxImagePreparesPerUser bounds one user's share, so that one user's
	// open proposals do not block everyone else's.
	maxImagePreparesPerUser = 4
	// imagePrepareTTL is how long a preparation stays on the page.
	imagePrepareTTL = 2 * time.Hour
	// maxImagePrepareForm bounds the preparation form's body.
	maxImagePrepareForm = 8 << 10
	// minTemplateVMID and maxTemplateVMID are PVE's VMID range.
	minTemplateVMID = 100
	maxTemplateVMID = 999999999
)

// Preparation states as the page shows them.
const (
	prepareProposed  = "proposed"
	prepareRunning   = "preparing"
	prepareDone      = "prepared"
	prepareFailed    = "failed"
	prepareActionID  = "pve.image.prepare"
	prepareCLIDetail = "approve it on the executor host with nebula approve, then run it here"
)

// imagePrepare is one proposed preparation of the user.
type imagePrepare struct {
	ID, User    string
	Spec        *pb.PVEImagePrepareSpec
	ImageSHA256 string
	Digest      string
	Risk        string
	Requirement string
	Options     string
	Bound       guestPowerBinding
	Mismatch    []string
	State       string
	Message     string
	Record      *pveTemplateRow
	Expires     time.Time
}

// Approvable reports whether the security key may approve it now.
func (p imagePrepare) Approvable() bool {
	return p.State == prepareProposed && p.Requirement == "key" && p.Options != "" && len(p.Mismatch) == 0
}

// Runnable reports whether it waits for a CLI approval and a run.
func (p imagePrepare) Runnable() bool {
	return p.State == prepareProposed && p.Requirement != "key" && len(p.Mismatch) == 0
}

// imagePrepares keeps the proposed preparations in memory.
type imagePrepares struct {
	mu sync.Mutex
	m  map[string]*imagePrepare
}

func newImagePrepares() *imagePrepares { return &imagePrepares{m: map[string]*imagePrepare{}} }

// roomLocked drops expired entries and refuses when the store or the user's
// share of it is full. The caller holds s.mu.
func (s *imagePrepares) roomLocked(user string, now time.Time) error {
	mine := 0
	for id, x := range s.m {
		if now.After(x.Expires) {
			delete(s.m, id)
			continue
		}
		if x.User == user {
			mine++
		}
	}
	if mine >= maxImagePreparesPerUser {
		return errors.New("you have too many open image preparations: run them or wait until they expire")
	}
	if len(s.m) >= maxImagePrepares {
		return errors.New("too many open image preparations: wait until earlier ones expire")
	}
	return nil
}

// room reports whether user may store one more preparation now; it is
// checked before the executor is asked for a proposal, so a full store
// leaves no proposal behind there.
func (s *imagePrepares) room(user string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roomLocked(user, now)
}

// put stores p after dropping expired entries; it refuses when the store or
// the user's share is full.
func (s *imagePrepares) put(p *imagePrepare, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.roomLocked(p.User, now); err != nil {
		return err
	}
	s.m[p.ID] = p
	return nil
}

// take moves the user's preparation id to state when ok accepts it and
// returns a copy; ok and the change happen under one lock.
func (s *imagePrepares) take(user, id string, now time.Time, ok func(imagePrepare) bool, state string) (imagePrepare, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, found := s.m[id]
	if !found || p.User != user || now.After(p.Expires) || !ok(*p) {
		return imagePrepare{}, false
	}
	p.State = state
	return *p, true
}

// set changes a stored preparation.
func (s *imagePrepares) set(id string, f func(*imagePrepare)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.m[id]; ok {
		f(p)
	}
}

// list returns copies of the user's live preparations, newest last.
func (s *imagePrepares) list(user string, now time.Time) []imagePrepare {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []imagePrepare
	for _, p := range s.m {
		if p.User == user && !now.After(p.Expires) {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Expires.Before(out[j].Expires) })
	return out
}

// prepareMismatch lists every difference between what the executor bound
// and what was requested: the action, the node target under the remote's
// current trust pin, the risk, the expiry and the catalog SHA-256.
func prepareMismatch(b guestPowerBinding, spec *pb.PVEImagePrepareSpec, bound *pb.PVEImage, catalogSHA, risk, trustPin string, now time.Time) []string {
	var out []string
	if b.ActionID != prepareActionID {
		out = append(out, "the executor bound a different action ("+cleanText(b.ActionID)+")")
	}
	if bound.GetImage().GetId() != spec.GetImageId() || bound.GetImage().GetSha256() != catalogSHA {
		out = append(out, "the executor bound a different image or SHA-256 than the catalog lists")
	}
	return append(out, guestTargetMismatch(b, guestRef{remote: spec.GetRemoteId(), kind: "node", node: spec.GetNode()}, risk, trustPin, now)...)
}

// parseImagePrepareForm reads the preparation form; the image must be a
// catalog entry the executor lists (returned with its SHA-256).
func parseImagePrepareForm(f url.Values, v pveImagesView) (*pb.PVEImagePrepareSpec, string, error) {
	get := func(k string) string { return strings.TrimSpace(f.Get(k)) }
	s := &pb.PVEImagePrepareSpec{RemoteId: get("remote"), Node: get("node"), Storage: get("storage"),
		ImageId: get("image"), ImportStorage: get("import_storage")}
	switch {
	case !deployRemoteRe.MatchString(s.RemoteId):
		return nil, "", formError("choose a PVE remote")
	case !deployRemoteRe.MatchString(s.Node):
		return nil, "", formError("choose a node")
	case !deployFieldRe.MatchString(s.Storage):
		return nil, "", formError("name the storage for the template's disk")
	case !deployFieldRe.MatchString(s.ImportStorage):
		return nil, "", formError("name the storage that receives the downloaded image")
	}
	vmid, err := strconv.ParseUint(get("vmid"), 10, 64)
	if err != nil || vmid < minTemplateVMID || vmid > maxTemplateVMID {
		return nil, "", formError("the template VMID must be a number from 100 to 999999999")
	}
	s.Vmid = vmid
	for _, img := range v.Images {
		if img.ID == s.ImageId {
			return s, img.SHA256, nil
		}
	}
	return nil, "", formError("the image is not in the executor's catalog")
}

// handleImagePrepare proposes a preparation (ProposePVEImagePrepare) and
// keeps the executor's bound request for the user's approval.
func (h *Handler) handleImagePrepare(w http.ResponseWriter, r *http.Request) {
	prep, ok := h.deploy.(DeployImagePreparer)
	if !h.deployEnabled(w, r) {
		return
	}
	if !ok || prep == nil {
		http.Error(w, "image preparation is not available", http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImagePrepareForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v := h.loadPVEImages(ctx)
	if !v.Available {
		http.Error(w, "the executor's image catalog is not available: nothing can be prepared", http.StatusConflict)
		return
	}
	spec, catalogSHA, err := parseImagePrepareForm(r.PostForm, v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	meta := h.pveMeta(ctx)
	if !remoteAllowsMutations(meta, spec.GetRemoteId()) {
		http.Error(w, "the PVE remote is not active: no preparation", http.StatusConflict)
		return
	}
	id, err := newDeployRunID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	user := webUser(r)
	if err := h.imagePrepares.room(user, h.clockNow()); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	resp, err := prep.ProposePVEImagePrepare(ctx, &pb.ProposePVEImagePrepareRequest{Spec: spec})
	if err != nil {
		h.guestPowerRefusal(w, "propose image prepare", err)
		return
	}
	now := h.clockNow()
	perm := resp.GetPermit()
	digest := perm.GetExecutionDigest()
	risk := riskWord(perm.GetRiskClass())
	if !guestPowerDigestRe.MatchString(digest) || perm.GetRiskClass() == pb.RiskClass_RISK_CLASS_UNSPECIFIED || strings.HasPrefix(risk, "RISK") {
		http.Error(w, "the executor returned no usable proposal", http.StatusBadGateway)
		return
	}
	bound, err := parseGuestPowerCanonical(perm.GetCanonicalRequest(), digest)
	if err != nil {
		h.log.Error("image prepare: unusable canonical request", "remote", spec.GetRemoteId(), "error", err)
		http.Error(w, err.Error()+": the proposal is refused, nothing can be approved here", http.StatusBadGateway)
		return
	}
	p := &imagePrepare{ID: id, User: user, Spec: spec, ImageSHA256: catalogSHA, Digest: digest, Risk: risk, Bound: bound,
		Requirement: requirementText(perm.GetApprovalRequirement()), State: prepareProposed, Expires: now.Add(imagePrepareTTL),
		Mismatch: prepareMismatch(bound, spec, resp.GetImage(), catalogSHA, risk, meta[spec.GetRemoteId()].TrustPin, now)}
	if opts := perm.GetRequestOptionsJson(); len(opts) > 0 && json.Valid(opts) {
		p.Options = string(opts)
	}
	if p.Requirement == "key" && p.Options == "" && len(p.Mismatch) == 0 {
		http.Error(w, "the executor returned no approval challenge", http.StatusBadGateway)
		return
	}
	if p.Requirement != "key" {
		p.Message = prepareCLIDetail
	}
	if err := h.imagePrepares.put(p, now); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if len(p.Mismatch) > 0 {
		h.log.Error("image prepare: executor binding differs from the request", "remote", spec.GetRemoteId(), "mismatch", strings.Join(p.Mismatch, "; "))
	}
	h.log.Info("audit", "kind", "image_prepare_proposed", "prepare", id, "remote", spec.GetRemoteId(), "node", spec.GetNode(),
		"image", spec.GetImageId(), "vmid", spec.GetVmid(), "risk", risk, "user", user)
	http.Redirect(w, r, "/deploy/images", http.StatusSeeOther)
}

// handleImagePrepareApprove relays the security key assertion (schedules.js
// posts {id, assertion}) and starts the preparation.
func (h *Handler) handleImagePrepareApprove(w http.ResponseWriter, r *http.Request) {
	prep, ok := h.deploy.(DeployImagePreparer)
	if !h.deployEnabled(w, r) {
		return
	}
	if !ok || prep == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		ID        string          `json:"id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	user := webUser(r)
	if !deployRunIDRe.MatchString(in.ID) || len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusNotFound, "preparation not found")
		return
	}
	p, ok := h.imagePrepares.take(user, in.ID, h.clockNow(), imagePrepare.Approvable, prepareRunning)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "preparation not found or not waiting for approval")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if _, err := h.deploy.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: p.Digest, AssertionJson: in.Assertion}); err != nil {
		h.imagePrepares.set(p.ID, func(x *imagePrepare) { x.State = prepareProposed })
		h.assertionRefusal(w, "approve image prepare", err)
		return
	}
	h.log.Info("audit", "kind", "image_prepare_approved", "prepare", p.ID, "user", user)
	h.startImagePrepare(r, prep, p)
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// handleImagePrepareRun runs a preparation approved with `nebula approve`;
// the executor refuses an unapproved permit.
func (h *Handler) handleImagePrepareRun(w http.ResponseWriter, r *http.Request) {
	prep, ok := h.deploy.(DeployImagePreparer)
	if !h.deployEnabled(w, r) {
		return
	}
	if !ok || prep == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxImagePrepareForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	id := r.PostForm.Get("id")
	if !deployRunIDRe.MatchString(id) {
		http.Error(w, "preparation not found", http.StatusNotFound)
		return
	}
	p, ok := h.imagePrepares.take(webUser(r), id, h.clockNow(), imagePrepare.Runnable, prepareRunning)
	if !ok {
		http.Error(w, "preparation not found or not waiting for a run", http.StatusNotFound)
		return
	}
	h.startImagePrepare(r, prep, p)
	http.Redirect(w, r, "/deploy/images", http.StatusSeeOther)
}

// startImagePrepare runs the approved preparation in the background: the
// executor downloads the image and creates the template.
func (h *Handler) startImagePrepare(r *http.Request, prep DeployImagePreparer, p imagePrepare) {
	ctx := context.WithoutCancel(r.Context())
	go func() {
		ctx, cancel := context.WithTimeout(ctx, deployCommitTimeout)
		defer cancel()
		resp, err := prep.CommitPVEImagePrepare(ctx, &pb.CommitPVEImagePrepareRequest{Spec: p.Spec, ExecutionDigest: p.Digest})
		if err != nil {
			st, _ := status.FromError(err)
			msg := "the preparation could not be confirmed (executor unavailable); check the executor's job list before preparing again"
			switch st.Code() {
			case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.NotFound, codes.Aborted, codes.AlreadyExists:
				msg = "the executor refused: " + cleanText(st.Message())
			default:
				h.log.Error("commit image prepare", "prepare", p.ID, "error", err)
			}
			h.imagePrepares.set(p.ID, func(x *imagePrepare) {
				x.Message = msg
				if p.Requirement != "key" && (st.Code() == codes.PermissionDenied || st.Code() == codes.FailedPrecondition) {
					// Not approved yet: approve with the CLI, then run again.
					x.State = prepareProposed
					return
				}
				x.State = prepareFailed
			})
			return
		}
		t := resp.GetTemplate()
		row := &pveTemplateRow{Remote: t.GetRemoteId(), Node: t.GetNode(), Storage: t.GetStorage(), Image: t.GetImageId(),
			Trust: t.GetTrust(), VMID: t.GetVmid(), Generation: t.GetGeneration(), SourceSHA256: t.GetSourceSha256(),
			ExecutionID: t.GetExecutionId(), PreparedAt: time.Unix(t.GetPreparedAtUnix(), 0).UTC()}
		h.imagePrepares.set(p.ID, func(x *imagePrepare) { x.State, x.Record, x.Message = prepareDone, row, "" })
		h.log.Info("audit", "kind", "image_prepared", "prepare", p.ID, "vmid", row.VMID, "generation", row.Generation)
	}()
}

// templateOptionLabel is the wizard's label of a template record.
func templateOptionLabel(t pveTemplateRow) string {
	return fmt.Sprintf("%d · %s · %s · %s · sha256 %s · generation %d", t.VMID, t.Image, t.Storage, t.Trust, t.SourceSHA256, t.Generation)
}
