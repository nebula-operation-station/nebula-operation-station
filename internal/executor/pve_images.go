// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
)

// This file is the image catalog and template preparation (ADR 0008
// section 2, PV-03). The catalog is signed release data verified through
// the release roots (E15); an operator may add local entries, which carry
// trust "Local". pve.image.prepare is a HIGH mutation of a node that
// downloads the image with its catalog checksum (PVE verifies it), creates
// a VM from the imported disk with a cloud-init drive and agent=1, and
// converts it to a template. The executor then records the template's
// VMID, generation, source digest and configuration digest; provisioning
// binds that record and fails when the template changed outside NOS.

// PveImagePrepareAction is the action ID of template preparation.
const PveImagePrepareAction = "pve.image.prepare"

// Typed step methods of pve.image.prepare and the PVE task types they
// create.
const (
	pveStepImageDownload = "pve.image.download"
	pveStepImageCreateVM = "pve.image.create_vm"
	pveStepImageTemplate = "pve.image.template"
)

var pveImageTaskTypes = map[string]string{
	pveStepImageDownload: "download",
	pveStepImageCreateVM: "qmcreate",
	pveStepImageTemplate: "qmtemplate",
}

// Image preparation limits.
const (
	// maxPveImageStepArgs bounds the arguments of one image step.
	maxPveImageStepArgs = 8 << 10
	// maxPveTemplateName bounds the template's guest name (one DNS label).
	maxPveTemplateName = 63
	// pveImageFileDigestPrefix is how many digest hex digits the
	// downloaded file name carries, so another image version never reuses
	// an existing file.
	pveImageFileDigestPrefix = 16
)

// ImageTrust is the provenance of a catalog entry.
type ImageTrust string

// Image trust values.
const (
	// ImageTrustSigned is an entry of the signed release catalog.
	ImageTrustSigned ImageTrust = "signed"
	// ImageTrustLocal is an entry an operator added ("Local" in the UI).
	ImageTrustLocal ImageTrust = "local"
)

var (
	// ErrPveImageUnknown is returned for an image ID that is in neither
	// the signed catalog nor the local entries.
	ErrPveImageUnknown = errors.New("executor: image is not in the catalog")
	// ErrPveCatalogRollback is returned for a signed catalog that is older
	// than, or conflicts with, the loaded one.
	ErrPveCatalogRollback = errors.New("executor: image catalog is older than the loaded one")
	// ErrPveImagePrepared is returned when the image already has a valid
	// template for the remote, node and storage.
	ErrPveImagePrepared = errors.New("executor: image is already prepared on this storage")
	// ErrPveTemplateNotPrepared is returned when no template record exists.
	ErrPveTemplateNotPrepared = errors.New("executor: no prepared template for this image")
	// ErrPveTemplateChanged is returned when the template no longer matches
	// its record (changed outside NOS, re-prepared or withdrawn from the
	// catalog).
	ErrPveTemplateChanged = errors.New("executor: prepared template changed; binding refused")
	// ErrPveTemplateStore is returned when the template record could not
	// be read or written.
	ErrPveTemplateStore = errors.New("executor: template record unavailable")
)

// PveImage is one resolved catalog entry and its provenance.
type PveImage struct {
	release.Image
	// Trust is ImageTrustSigned or ImageTrustLocal.
	Trust ImageTrust
	// CatalogSequence and CatalogDigest identify the signed catalog the
	// entry came from; zero and empty for a local entry.
	CatalogSequence int64
	CatalogDigest   string
}

// PveImageCatalog holds the verified signed catalog and the local
// entries. It is safe for concurrent use.
type PveImageCatalog struct {
	mu     sync.Mutex
	signed *release.Catalog
	local  map[string]release.Image
}

// LoadSigned verifies a signed catalog with the active release roots of
// the executor's durable root state and makes it current. A catalog with a
// lower sequence, or the same sequence and other bytes, is refused.
func (c *PveImageCatalog) LoadSigned(roots []release.Root, raw, sig []byte) error {
	cat, err := release.VerifyCatalog(roots, raw, sig)
	if err != nil {
		return fmt.Errorf("load image catalog: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur := c.signed; cur != nil &&
		(cat.Sequence < cur.Sequence || (cat.Sequence == cur.Sequence && cat.Digest != cur.Digest)) {
		return fmt.Errorf("load image catalog sequence %d over %d: %w", cat.Sequence, cur.Sequence, ErrPveCatalogRollback)
	}
	c.signed = &cat
	return nil
}

// AddLocal adds or replaces an operator-defined entry. Its ID must start
// with release.LocalImagePrefix; it carries trust "Local".
func (c *PveImageCatalog) AddLocal(img release.Image) error {
	if err := release.ValidateImage(img, true); err != nil {
		return fmt.Errorf("add local image: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.local == nil {
		c.local = make(map[string]release.Image)
	}
	c.local[img.ID] = img
	return nil
}

// RemoveLocal removes a local entry and reports whether it existed.
func (c *PveImageCatalog) RemoveLocal(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.local[id]
	delete(c.local, id)
	return ok
}

// Lookup resolves an image ID. Signed and local IDs never overlap.
func (c *PveImageCatalog) Lookup(id string) (PveImage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.HasPrefix(id, release.LocalImagePrefix) {
		img, ok := c.local[id]
		return PveImage{Image: img, Trust: ImageTrustLocal}, ok
	}
	if c.signed == nil {
		return PveImage{}, false
	}
	img, ok := c.signed.Image(id)
	return PveImage{Image: img, Trust: ImageTrustSigned, CatalogSequence: c.signed.Sequence, CatalogDigest: c.signed.Digest}, ok
}

// pveImagePrepareRisk is the base risk of pve.image.prepare: a one-time
// HIGH action per (remote, node, storage, image) (ADR 0008 section 2).
const pveImagePrepareRisk = canonical.RiskHigh

// ImagePrepareRisk is the risk floor of preparing img. An entry that is not
// from the signed catalog (trust "Local") has no release signature behind
// its URL and digest and raises the action to HIGH, whatever the base
// risk is.
func ImagePrepareRisk(img PveImage) canonical.Risk {
	risk := pveImagePrepareRisk
	if img.Trust != ImageTrustSigned {
		risk = canonical.MaxRisk(risk, canonical.RiskHigh)
	}
	return risk
}

// ImagePrepareRiskFloor wraps the executor's risk policy so that every
// pve.image.prepare request has a floor of at least HIGH, whoever builds
// it. The authority enforces the floor when proposing and authorizing.
type ImagePrepareRiskFloor struct {
	Next permit.RiskPolicy
}

// MinimumRisk implements permit.RiskPolicy.
func (p ImagePrepareRiskFloor) MinimumRisk(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	risk, why := canonical.RiskLow, ""
	if p.Next != nil {
		var err error
		if risk, why, err = p.Next.MinimumRisk(r, targets); err != nil {
			return "", "", err
		}
	}
	if r.ActionID == PveImagePrepareAction && risk.Rank() < canonical.RiskHigh.Rank() {
		risk, why = canonical.RiskHigh, strings.TrimPrefix(why+"; ", "; ")+"pve.image.prepare is HIGH (ADR 0008)"
	}
	return risk, why, nil
}

// PveTemplateKey names one preparation: an image on a remote, node and
// storage.
type PveTemplateKey struct {
	RemoteID string `json:"remote_id"`
	Node     string `json:"node"`
	Storage  string `json:"storage"`
	ImageID  string `json:"image_id"`
}

// PveTemplateRecord is the executor's record of a prepared template.
type PveTemplateRecord struct {
	PveTemplateKey
	// Trust is the provenance of the image at preparation.
	Trust ImageTrust `json:"trust"`
	// VMID is the template's VMID.
	VMID uint64 `json:"vmid"`
	// Generation counts the preparations of the key; each one replaces the
	// record and invalidates bindings to the previous one.
	Generation uint64 `json:"generation"`
	// SourceSHA256 is the catalog digest of the image the template was
	// made from.
	SourceSHA256 string `json:"source_sha256"`
	// ConfigDigest is the hex SHA-256 of the template's complete PVE
	// configuration right after preparation.
	ConfigDigest string `json:"config_digest"`
	// TrustGeneration is the remote's trust generation at preparation.
	TrustGeneration uint64 `json:"trust_generation"`
	// ExecutionID is the preparation's execution.
	ExecutionID string `json:"execution_id"`
	// PreparedAt is when the record was written.
	PreparedAt time.Time `json:"prepared_at"`
}

// PveTemplateStore persists template records.
type PveTemplateStore interface {
	// PveTemplate returns the record of key, if any.
	PveTemplate(key PveTemplateKey) (PveTemplateRecord, bool, error)
	// PutPveTemplate durably writes rec, replacing the record of its key.
	PutPveTemplate(rec PveTemplateRecord) error
}

// PveTemplateBinding is what provisioning binds: the template record of a
// key at an exact VMID, generation and source digest.
type PveTemplateBinding struct {
	PveTemplateKey
	VMID         uint64
	Generation   uint64
	SourceSHA256 string
}

// PveImagePrepareRequest selects one preparation.
type PveImagePrepareRequest struct {
	// Digest is the approved permit (Prepare only).
	Digest canonical.Digest
	PveTemplateKey
	// ImportStorage receives the downloaded image (content "import").
	ImportStorage string
	// VMID is the VMID of the new template.
	VMID uint64
}

// PveImages proposes and runs pve.image.prepare and binds its records.
type PveImages struct {
	Mutations *PveMutations
	Catalog   *PveImageCatalog
	Templates PveTemplateStore
	// Artifact and ModuleVersion identify the action the permit binds.
	Artifact      []byte
	ModuleVersion string
}

func (p *PveImages) checkDeps() error {
	if p.Mutations == nil || p.Catalog == nil || p.Templates == nil || len(p.Artifact) == 0 || p.ModuleVersion == "" {
		return errors.New("executor: pve images: Mutations, Catalog, Templates, Artifact and ModuleVersion are required")
	}
	return nil
}

// pveImageDownloadArgs, pveImageCreateArgs and pveImageTemplateArgs are
// the typed arguments of the image steps.
type pveImageDownloadArgs struct {
	Storage  string `json:"storage"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
}

type pveImageCreateArgs struct {
	VMID           int64  `json:"vmid"`
	Name           string `json:"name"`
	Storage        string `json:"storage"`
	ImportStorage  string `json:"import_storage"`
	ImportFilename string `json:"import_filename"`
}

type pveImageTemplateArgs struct {
	VMID int64 `json:"vmid"`
}

// pveImagePlan is the approved parameters of pve.image.prepare: the image
// with its provenance, the key and the step plan.
type pveImagePlan struct {
	Image struct {
		ID              string     `json:"id"`
		OS              string     `json:"os"`
		Release         string     `json:"release"`
		Arch            string     `json:"arch"`
		URL             string     `json:"url"`
		SHA256          string     `json:"sha256"`
		DiskFormat      string     `json:"disk_format"`
		Trust           ImageTrust `json:"trust"`
		CatalogSequence int64      `json:"catalog_sequence"`
		CatalogDigest   string     `json:"catalog_digest"`
	} `json:"image"`
	Storage       string            `json:"storage"`
	ImportStorage string            `json:"import_storage"`
	VMID          uint64            `json:"vmid"`
	Steps         []PveMutationStep `json:"steps"`
}

// templateName is the template's guest name: one DNS label from the image
// ID.
func templateName(id string) string {
	n := "tpl-" + strings.ReplaceAll(id, ".", "-")
	if len(n) > maxPveTemplateName {
		n = n[:maxPveTemplateName]
	}
	return strings.TrimRight(n, "-")
}

func stepOf(method string, args any) (PveMutationStep, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return PveMutationStep{}, ErrPveMutationPlan
	}
	return PveMutationStep{Method: method, Args: b}, nil
}

// mutation builds the exact mutation request of req from the current
// catalog. Prepare rebuilds it, so a catalog change since the approval
// changes the parameters and the permit no longer covers them.
func (p *PveImages) mutation(req PveImagePrepareRequest) (PveMutationRequest, PveImage, error) {
	img, ok := p.Catalog.Lookup(req.ImageID)
	if !ok {
		return PveMutationRequest{}, PveImage{}, ErrPveImageUnknown
	}
	if req.VMID < pvecontract.MinVMID || req.VMID > pvecontract.MaxVMID {
		return PveMutationRequest{}, PveImage{}, ErrPveMutationPlan
	}
	var plan pveImagePlan
	plan.Image.ID, plan.Image.OS, plan.Image.Release, plan.Image.Arch = img.ID, img.OS, img.Release, img.Arch
	plan.Image.URL, plan.Image.SHA256, plan.Image.DiskFormat = img.URL, img.SHA256, img.DiskFormat
	plan.Image.Trust, plan.Image.CatalogSequence, plan.Image.CatalogDigest = img.Trust, img.CatalogSequence, img.CatalogDigest
	plan.Storage, plan.ImportStorage, plan.VMID = req.Storage, req.ImportStorage, req.VMID

	file := "nos-" + img.ID + "-" + img.SHA256[:pveImageFileDigestPrefix] + "." + img.DiskFormat
	vmid := int64(req.VMID)
	for _, s := range []struct {
		method string
		args   any
	}{
		{pveStepImageDownload, pveImageDownloadArgs{Storage: req.ImportStorage, Filename: file, URL: img.URL, SHA256: img.SHA256}},
		{pveStepImageCreateVM, pveImageCreateArgs{VMID: vmid, Name: templateName(img.ID), Storage: req.Storage, ImportStorage: req.ImportStorage, ImportFilename: file}},
		{pveStepImageTemplate, pveImageTemplateArgs{VMID: vmid}},
	} {
		st, err := stepOf(s.method, s.args)
		if err != nil {
			return PveMutationRequest{}, PveImage{}, err
		}
		plan.Steps = append(plan.Steps, st)
	}
	params, err := json.Marshal(plan)
	if err != nil {
		return PveMutationRequest{}, PveImage{}, ErrPveMutationPlan
	}
	return PveMutationRequest{
		Digest: req.Digest, RemoteID: req.RemoteID, Kind: permit.ProviderKindNode, Node: req.Node,
		ActionID: PveImagePrepareAction, ModuleVersion: p.ModuleVersion, Artifact: p.Artifact, Parameters: params,
	}, img, nil
}

// ProposalRequest builds the canonical request and parameters of a new
// pve.image.prepare proposal. The risk is raised to ImagePrepareRisk. An
// image whose template for the key is still valid is refused.
func (p *PveImages) ProposalRequest(ctx context.Context, req PveImagePrepareRequest, executionID string, risk canonical.Risk, stagePlanHash string, expiry time.Time) (canonical.Request, []byte, error) {
	if err := p.checkDeps(); err != nil {
		return canonical.Request{}, nil, err
	}
	mr, img, err := p.mutation(req)
	if err != nil {
		return canonical.Request{}, nil, err
	}
	rec, ok, err := p.Templates.PveTemplate(req.PveTemplateKey)
	if err != nil {
		return canonical.Request{}, nil, ErrPveTemplateStore
	}
	if ok {
		_, err := p.BindTemplate(ctx, PveTemplateBinding{PveTemplateKey: rec.PveTemplateKey, VMID: rec.VMID, Generation: rec.Generation, SourceSHA256: rec.SourceSHA256})
		if err == nil {
			return canonical.Request{}, nil, ErrPveImagePrepared
		}
		if errors.Is(err, ErrPveTemplateStore) || errors.Is(err, ErrPveJobStore) {
			return canonical.Request{}, nil, err
		}
	}
	return p.Mutations.ProposalRequest(ctx, mr, executionID, canonical.MaxRisk(risk, ImagePrepareRisk(img)), stagePlanHash, expiry)
}

// Prepare runs an approved pve.image.prepare and records the template.
// The record's generation is one above the key's previous record.
func (p *PveImages) Prepare(ctx context.Context, req PveImagePrepareRequest) (PveTemplateRecord, error) {
	if err := p.checkDeps(); err != nil {
		return PveTemplateRecord{}, err
	}
	mr, img, err := p.mutation(req)
	if err != nil {
		return PveTemplateRecord{}, err
	}
	prev, had, err := p.Templates.PveTemplate(req.PveTemplateKey)
	if err != nil {
		return PveTemplateRecord{}, ErrPveTemplateStore
	}
	res, err := p.Mutations.Run(ctx, mr)
	if err != nil {
		return PveTemplateRecord{}, err
	}
	rm, err := p.Mutations.activeRemote(req.RemoteID)
	if err != nil {
		return PveTemplateRecord{}, err
	}
	digest, err := p.liveTemplate(ctx, rm, req.Node, req.VMID)
	if err != nil {
		return PveTemplateRecord{}, err
	}
	rec := PveTemplateRecord{
		PveTemplateKey: req.PveTemplateKey, Trust: img.Trust, VMID: req.VMID, Generation: 1,
		SourceSHA256: img.SHA256, ConfigDigest: digest, TrustGeneration: rm.TrustGeneration,
		ExecutionID: res.ExecutionID, PreparedAt: p.Mutations.now().UTC(),
	}
	if had {
		rec.Generation = prev.Generation + 1
	}
	if err := p.Templates.PutPveTemplate(rec); err != nil {
		p.Mutations.log().Error("pve template record not written", "execution", res.ExecutionID)
		return PveTemplateRecord{}, ErrPveTemplateStore
	}
	p.Mutations.log().Info("audit", "kind", "pve_template_prepared", "remote", rec.RemoteID, "node", rec.Node, "storage", rec.Storage,
		"image", rec.ImageID, "trust", string(rec.Trust), "vmid", rec.VMID, "generation", rec.Generation, "source_sha256", rec.SourceSHA256,
		"execution", rec.ExecutionID)
	return rec, nil
}

// liveTemplate reads the template's live configuration digest with the
// read token and checks that it is on node.
func (p *PveImages) liveTemplate(ctx context.Context, rm executordb.PveRemote, node string, vmid uint64) (string, error) {
	read, err := p.Mutations.readToken(rm)
	if err != nil {
		return "", err
	}
	liveNode, digest, err := p.Mutations.Client.TargetState(ctx, rm, permit.ProviderKindQemu, node, vmid, read)
	if err != nil || liveNode != node || !validHexDigest(digest) {
		return "", ErrPveTemplateChanged
	}
	return digest, nil
}

func validHexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}

// BindTemplate checks that the template record of b's key still has b's
// VMID, generation and source digest, that the catalog still lists the
// image with that digest, that the remote keeps the trust generation of
// the preparation and that the live template configuration equals the
// recorded one. Any difference (a template changed, moved or removed
// outside NOS, a re-preparation, a withdrawn catalog entry, a re-pinned
// remote) fails the binding.
func (p *PveImages) BindTemplate(ctx context.Context, b PveTemplateBinding) (PveTemplateRecord, error) {
	if err := p.checkDeps(); err != nil {
		return PveTemplateRecord{}, err
	}
	rec, ok, err := p.Templates.PveTemplate(b.PveTemplateKey)
	if err != nil {
		return PveTemplateRecord{}, ErrPveTemplateStore
	}
	if !ok {
		return PveTemplateRecord{}, ErrPveTemplateNotPrepared
	}
	if rec.VMID != b.VMID || rec.Generation != b.Generation || rec.SourceSHA256 != b.SourceSHA256 {
		return PveTemplateRecord{}, ErrPveTemplateChanged
	}
	img, ok := p.Catalog.Lookup(rec.ImageID)
	if !ok || img.SHA256 != rec.SourceSHA256 {
		return PveTemplateRecord{}, ErrPveTemplateChanged
	}
	rm, ok, err := p.Mutations.DB.GetRemote(rec.RemoteID)
	if err != nil {
		return PveTemplateRecord{}, ErrPveJobStore
	}
	if !ok || rm.State != executordb.StateActive || rm.TrustGeneration != rec.TrustGeneration {
		return PveTemplateRecord{}, ErrPveRemoteChanged
	}
	digest, err := p.liveTemplate(ctx, rm, rec.Node, rec.VMID)
	if err != nil {
		return PveTemplateRecord{}, err
	}
	if digest != rec.ConfigDigest {
		p.Mutations.log().Warn("audit", "kind", "pve_template_changed", "remote", rec.RemoteID, "node", rec.Node, "image", rec.ImageID, "vmid", rec.VMID)
		return PveTemplateRecord{}, ErrPveTemplateChanged
	}
	return rec, nil
}

// ImageStepTaskType returns the PVE task type of an image step method, for
// a PveMutationClient's TaskType.
func ImageStepTaskType(method string) (string, bool) {
	tt, ok := pveImageTaskTypes[method]
	return tt, ok
}

// PveImageWriter is the part of pveapi.Writer the image steps use.
type PveImageWriter interface {
	DownloadURL(ctx context.Context, r pveapi.DownloadRequest) (string, error)
	CreateImageVM(ctx context.Context, r pveapi.ImageVMRequest) (string, error)
	ConvertToTemplate(ctx context.Context, node string, vmid int64) (string, error)
}

// DispatchImageStep decodes one image step strictly and sends it with w,
// for a PveMutationClient's Dispatch. A step the writer refused before
// anything reached PVE, or that PVE refused, wraps ErrPveRejected; any
// other error means the request may have been received.
func DispatchImageStep(ctx context.Context, w PveImageWriter, node string, step PveMutationStep) (string, error) {
	var upid string
	var err error
	switch step.Method {
	case pveStepImageDownload:
		var a pveImageDownloadArgs
		if err := decodeStepArgs(step.Args, &a); err != nil {
			return "", err
		}
		upid, err = w.DownloadURL(ctx, pveapi.DownloadRequest{Node: node, Storage: a.Storage, Content: pveapi.ContentImport,
			Filename: a.Filename, SourceURL: a.URL, SHA256: a.SHA256})
	case pveStepImageCreateVM:
		var a pveImageCreateArgs
		if err := decodeStepArgs(step.Args, &a); err != nil {
			return "", err
		}
		upid, err = w.CreateImageVM(ctx, pveapi.ImageVMRequest{Node: node, VMID: a.VMID, Name: a.Name, Storage: a.Storage,
			ImportStorage: a.ImportStorage, ImportFilename: a.ImportFilename})
	case pveStepImageTemplate:
		var a pveImageTemplateArgs
		if err := decodeStepArgs(step.Args, &a); err != nil {
			return "", err
		}
		upid, err = w.ConvertToTemplate(ctx, node, a.VMID)
	default:
		return "", fmt.Errorf("dispatch image step: %w", ErrPveRejected)
	}
	if err == nil {
		return upid, nil
	}
	var we *pveapi.WriteError
	if errors.Is(err, pveapi.ErrInvalidArgument) || (errors.As(err, &we) && !we.OutcomeUnknown()) {
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, err)
	}
	return "", fmt.Errorf("dispatch %s: %w", step.Method, err)
}

// decodeStepArgs decodes args into dst with a size limit, no unknown
// fields and no trailing data; a malformed step is refused unsent.
func decodeStepArgs(args json.RawMessage, dst any) error {
	if len(args) == 0 || len(args) > maxPveImageStepArgs {
		return fmt.Errorf("decode image step: %w", ErrPveRejected)
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || dec.More() {
		return fmt.Errorf("decode image step: %w", ErrPveRejected)
	}
	return nil
}
