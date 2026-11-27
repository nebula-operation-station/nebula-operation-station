// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"google.golang.org/grpc"

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

// loadPVEImages asks the executor for the catalog and the records. An
// error or a missing capability leaves Available false.
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
	h.render(w, r, pageData{Title: "Deploy Images", Active: "deploy", Content: "deploy_images",
		DeployImages: &deployImagesData{View: h.loadPVEImages(ctx)}})
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
			return t.Generation, nil
		}
	}
	return 0, formError("the template is not a prepared record for this node, storage, image and SHA-256: prepare it on the Images page first")
}

// wizardImages fills the wizard's choices from the executor (PV-03h, D4b):
// the catalog IDs, the catalog SHA-256s, and the VMIDs of the prepared
// template records of the chosen node. Without the executor's answer the
// wizard offers no template.
func (h *Handler) wizardImages(ctx context.Context, d *deployWizardData) {
	v := h.loadPVEImages(ctx)
	if !v.Available {
		d.Notes = append(d.Notes, "The executor's image catalog is not available: no prepared template can be chosen.")
		return
	}
	for _, img := range v.Images {
		d.Images = append(d.Images, deployOption{Value: img.ID,
			Label:    img.ID + " (" + img.OS + " " + img.Release + ", " + img.Arch + ")",
			Selected: img.ID == d.Image})
		d.Digests = append(d.Digests, deployOption{Value: img.SHA256, Label: img.SHA256 + " (" + img.ID + ")"})
	}
	for _, t := range v.Templates {
		if t.Remote == d.Remote && t.Node == d.Node {
			d.Templates = append(d.Templates, deployOption{Value: strconv.FormatUint(t.VMID, 10), Label: templateOptionLabel(t)})
		}
	}
}

// templateOptionLabel is the wizard's label of a template record.
func templateOptionLabel(t pveTemplateRow) string {
	return fmt.Sprintf("%d · %s · %s · sha256 %s · generation %d", t.VMID, t.Image, t.Trust, t.SourceSHA256, t.Generation)
}
