// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
)

// Deploy profiles (ADR 0008 section 1, PV-04): versioned, secret-free
// presets for guest provisioning. Saving creates a new immutable version;
// the profile references runbooks and vault entries, never secret values.

// DeployProfiles stores deploy profiles (internal/deployprofile.Store).
type DeployProfiles interface {
	Save(ctx context.Context, user string, p deployprofile.Profile) (deployprofile.Version, error)
	Latest(ctx context.Context) ([]deployprofile.Version, error)
	Versions(ctx context.Context, slug string) ([]deployprofile.Version, error)
	Get(ctx context.Context, slug string, version int) (deployprofile.Version, error)
}

type deployProfileRow struct {
	Slug, Title, Image, SizeLabel string
	Created                       time.Time
	Version                       int
}

type deployProfileVersionRow struct {
	Version              int
	DocSHA256, CreatedBy string
	Created              time.Time
}

type deployProfileDetail struct {
	Slug, Title, Description, Image, StorageClass string
	SizeLabel, Bridge, IPAMPool, DHCP, DNS        string
	Bootstrap, Runbooks, VaultRefs                string
	Version                                       int
	DocSHA256                                     string
	Versions                                      []deployProfileVersionRow
}

type deployProfileEdit struct {
	Existing bool
	// Draft is the JSON of the draft to start from (rendered into a data
	// attribute and parsed by deployprofiles.js).
	Draft string
	// Modules and Presets are the JSON catalogs the form renders.
	Modules string
	Presets string
}

type deployProfilesData struct {
	Rows   []deployProfileRow
	Detail *deployProfileDetail
	Edit   *deployProfileEdit
}

func sizeLabel(s deployprofile.Size) string {
	if s.Preset != "" {
		return s.Preset
	}
	return strconv.Itoa(s.VCPU) + " vCPU / " + strconv.Itoa(s.RAMGiB) + " GiB RAM / " + strconv.Itoa(s.DiskGiB) + " GiB disk"
}

func (h *Handler) handleDeployProfiles(w http.ResponseWriter, r *http.Request) {
	if h.deployProfiles == nil {
		h.render(w, r, pageData{Title: "Deploy Profiles", Active: "deploy", Content: "empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	data := pageData{Title: "Deploy Profiles", Active: "deploy", Content: "deploy_profiles", DeployProfiles: &deployProfilesData{}}
	list, err := h.deployProfiles.Latest(ctx)
	if err != nil {
		h.log.Error("list deploy profiles", "error", err)
	}
	for _, v := range list {
		data.DeployProfiles.Rows = append(data.DeployProfiles.Rows, deployProfileRow{
			Slug: v.Profile.Slug, Title: v.Profile.Title, Image: v.Profile.Image,
			SizeLabel: sizeLabel(v.Profile.Size), Created: v.CreatedAt.UTC(), Version: v.Version,
		})
	}
	h.render(w, r, data)
}

func (h *Handler) handleDeployProfile(w http.ResponseWriter, r *http.Request) {
	if h.deployProfiles == nil {
		http.NotFound(w, r)
		return
	}
	slug := r.PathValue("slug")
	version := 0
	if s := r.URL.Query().Get("version"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			http.NotFound(w, r)
			return
		}
		version = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.deployProfiles.Get(ctx, slug, version)
	if errors.Is(err, deployprofile.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get deploy profile", "error", err)
		http.Error(w, "deploy profiles unavailable", http.StatusInternalServerError)
		return
	}
	all, err := h.deployProfiles.Versions(ctx, slug)
	if err != nil {
		h.log.Error("list deploy profile versions", "error", err)
		http.Error(w, "deploy profiles unavailable", http.StatusInternalServerError)
		return
	}
	d := &deployProfileDetail{
		Slug: v.Profile.Slug, Title: v.Profile.Title, Description: v.Profile.Description,
		Image: v.Profile.Image, StorageClass: v.Profile.StorageClass,
		SizeLabel: sizeLabel(v.Profile.Size), Bridge: v.Profile.Network.Bridge,
		IPAMPool: v.Profile.Network.IPAMPool, DNS: strings.Join(v.Profile.DNS.Nameservers, ", "),
		Version: v.Version, DocSHA256: v.DocSHA256,
	}
	if v.Profile.Network.VLAN != 0 {
		d.Bridge += " VLAN " + strconv.Itoa(v.Profile.Network.VLAN)
	}
	if v.Profile.Network.DHCP {
		d.DHCP = "DHCP"
	}
	if v.Profile.DNS.SearchDomain != "" {
		if d.DNS != "" {
			d.DNS += "; "
		}
		d.DNS += "search " + v.Profile.DNS.SearchDomain
	}
	for _, m := range v.Profile.Bootstrap {
		if d.Bootstrap != "" {
			d.Bootstrap += ", "
		}
		d.Bootstrap += m.Name
	}
	for _, rb := range v.Profile.Runbooks {
		if d.Runbooks != "" {
			d.Runbooks += ", "
		}
		d.Runbooks += rb.Slug + " v" + strconv.Itoa(rb.Version)
	}
	for _, vr := range v.Profile.VaultRefs {
		if d.VaultRefs != "" {
			d.VaultRefs += ", "
		}
		d.VaultRefs += vr.Slot + " = vault:" + vr.VaultID
	}
	for _, vv := range all {
		d.Versions = append(d.Versions, deployProfileVersionRow{
			Version: vv.Version, DocSHA256: vv.DocSHA256, CreatedBy: vv.CreatedBy, Created: vv.CreatedAt.UTC(),
		})
	}
	h.render(w, r, pageData{Title: "Profile " + v.Profile.Slug, Active: "deploy", Content: "deploy_profile",
		DeployProfiles: &deployProfilesData{Detail: d}})
}

func (h *Handler) handleDeployProfileEdit(w http.ResponseWriter, r *http.Request) {
	if h.deployProfiles == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	edit := &deployProfileEdit{
		Modules: `["user","ssh-hardening","timezone","packages","qemu-guest-agent","docker","netbird","firewall","telegraf","pkg-report"]`,
		Presets: `["S","M","L","XL"]`,
	}
	slug := r.PathValue("slug")
	if slug != "" {
		v, err := h.deployProfiles.Get(ctx, slug, 0)
		if errors.Is(err, deployprofile.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			h.log.Error("get deploy profile", "error", err)
			http.Error(w, "deploy profiles unavailable", http.StatusInternalServerError)
			return
		}
		js, err := marshalDraft(v.Profile)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		edit.Draft = js
		edit.Existing = true
	}
	title := "New deploy profile"
	if edit.Existing {
		title = "Edit profile " + slug
	}
	h.render(w, r, pageData{Title: title, Active: "deploy", Content: "deploy_profile_edit",
		Scripts: []string{"webauthn.js", "deployprofiles.js"}, DeployProfiles: &deployProfilesData{Edit: edit}})
}

// marshalDraft renders the profile for the edit form's data attribute.
func marshalDraft(p deployprofile.Profile) (string, error) {
	doc, err := p.Doc()
	if err != nil {
		return "", err
	}
	return string(doc), nil
}

// maxDeployProfileRequest bounds a save request (the document is at most
// 16 KiB; JSON escaping can grow it).
const maxDeployProfileRequest = 64 << 10

func (h *Handler) handleDeployProfileSave(w http.ResponseWriter, r *http.Request) {
	if h.deployProfiles == nil {
		http.NotFound(w, r)
		return
	}
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDeployProfileRequest)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var p deployprofile.Profile
	if err := dec.Decode(&p); err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "the profile is too large")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	v, err := h.deployProfiles.Save(ctx, webUser(r), p)
	var ie *deployprofile.InvalidError
	switch {
	case errors.As(err, &ie):
		writeJSONError(w, http.StatusBadRequest, ie.Error())
		return
	case err != nil:
		h.log.Error("save deploy profile", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "the profile could not be saved")
		return
	}
	h.log.Info("audit", "kind", "deploy_profile_saved", "profile", v.Profile.Slug, "version", v.Version,
		"doc_sha256", v.DocSHA256, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]any{"slug": v.Profile.Slug, "version": v.Version})
}
