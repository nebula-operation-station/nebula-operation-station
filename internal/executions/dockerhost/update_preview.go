// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// docker-update-preview-v1 is the result of docker.update_preview 1.0.0
// (container update plan cu02): per unit (one Compose project or one
// standalone container) the identity and image facts a container update
// binding needs, the keyed configuration and source digests, and the
// reasons that make the unit, a service or an image unavailable. The host
// is hostile, so every value is checked against the script's own rules
// and limits; a result that breaks one is refused as a whole.

// Limits of the preview, enforced by the script and again here (container
// update plan cu02). TestPreviewLimitsMatchScript keeps both in agreement.
const (
	// MaxPreviewContainers bounds the containers with facts in one result;
	// units past it are truncated.
	MaxPreviewContainers = 200
	// MaxPreviewProjects bounds the Compose projects with facts; later
	// projects are truncated.
	MaxPreviewProjects = 50
	// MaxPreviewTargetTags bounds the target_tags parameter; a proposal
	// with more is refused.
	MaxPreviewTargetTags = 20
	// MaxPreviewConfigFiles bounds a project's operator Compose files; a
	// project with more is unsupported_files.
	MaxPreviewConfigFiles = 16
	// MaxPreviewConfigFileBytes bounds each operator Compose file.
	MaxPreviewConfigFileBytes = 1 << 20
	// MaxPreviewComposeConfigBytes bounds `docker compose config` output.
	MaxPreviewComposeConfigBytes = 4 << 20
	// MaxPreviewIndexBytes bounds one manifest or index GET; a larger one
	// is tag_unresolved.
	MaxPreviewIndexBytes = 256 << 10
	// MaxPreviewResultBytes bounds the result, below hostrun.MaxResult.
	MaxPreviewResultBytes = 768 << 10
	// MaxPreviewOldDigests bounds an image's local repository digests (the
	// binding's old_digests).
	MaxPreviewOldDigests = 8
	// MaxRunRegistryRequests bounds the registry requests of one run;
	// tags past it are tag_unresolved.
	MaxRunRegistryRequests = 120
	// MaxPreviewWallClock bounds the preview's work on the host; units not
	// finished by then are truncated, which leaves a minute of the
	// 5-minute job for the result.
	MaxPreviewWallClock = 4 * time.Minute
)

// ErrPreviewFormat: the bytes are not a docker-update-preview-v1 result
// within its limits and rules.
var ErrPreviewFormat = errors.New("dockerhost: not a docker-update-preview-v1 result")

// Preview statuses: ok carries units; every other status carries none.
const (
	PreviewOK = "ok"
	// PreviewPrepareRequired: the host has no salt yet; run
	// docker.update_prepare. No digests, so every unit is unavailable.
	PreviewPrepareRequired = "prepare_required"
)

var previewStatuses = map[string]bool{
	PreviewOK: true, PreviewPrepareRequired: true, "salt_unsafe": true, "tooling_missing": true, "not_root": true,
	"params_invalid": true, "host_unreadable": true, "result_too_large": true, "internal_error": true,
}

// Unit reasons. Units with reason "" or override_drift carry complete
// facts (an observed reason of a complete unit, kept for Resolve); every
// other reason carries none.
const (
	PreviewTruncated     = "truncated"
	PreviewOverrideDrift = "override_drift"
)

var (
	previewComposeReasons = map[string]bool{
		"": true, PreviewTruncated: true, PreviewOverrideDrift: true, "project_mismatch": true, "unsupported_files": true,
		"dependency_unsupported": true, "host_unreadable": true,
	}
	previewStandaloneReasons = map[string]bool{"": true, PreviewTruncated: true, "host_unreadable": true}
	// Service reasons: each makes an update of that service unavailable.
	previewServiceReasons = map[string]bool{
		"build_unsupported": true, "config_not_applied": true, "digest_pinned": true, "ephemeral_port": true,
		"mixed_images": true, "scale_mismatch": true, "target_not_running": true,
	}
	previewImageReasons = map[string]bool{"": true, "reference_unsupported": true, "old_digest_unknown": true, "platform_unknown": true}

	previewProjectRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	previewServiceRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	previewCNameRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	previewHex64Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	previewDigestRe   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	previewPlatformRe = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9_]{1,16}(/[a-z0-9]{1,16})?$`)
	previewTagRe      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

// UpdatePreview is a parsed docker-update-preview-v1 result.
type UpdatePreview struct {
	Status string
	// Units: Compose projects by name, then standalone containers by ID.
	Units []PreviewUnit
}

// PreviewUnit is one atomic recreate unit as the preview saw it.
type PreviewUnit struct {
	// Form is "compose" or "standalone".
	Form string
	// Project is the Compose project; "" for a standalone unit.
	Project string
	// ContainerID is the standalone container; "" for a Compose unit.
	ContainerID string
	// Reason is "" for an available unit, else why it is unavailable.
	Reason string
	// Compose only: the unkeyed path hashes and the keyed source digest.
	WorkingDirHash  string
	ConfigFilesHash string
	SourceDigest    string
	// Services: every service the project's files render, sorted.
	Services []PreviewService
	// Targets: every container of the unit, by service and ID.
	Targets []PreviewTarget
	// Images: one entry per distinct (image ID, running reference).
	Images []PreviewImage
}

// HasFacts reports whether the unit carries its identity facts.
func (u PreviewUnit) HasFacts() bool { return u.Reason == "" || u.Reason == PreviewOverrideDrift }

// PreviewService is one rendered service of a Compose unit.
type PreviewService struct {
	Service string
	// Replicas is the number of the service's containers on the host;
	// Scale is what the files say (-1 when not a number).
	Replicas int
	Scale    int
	// Depends are the direct dependencies (depends_on, links,
	// volumes_from) with depends_on's restart flag; Shares are the
	// services it shares a namespace with.
	Depends []PreviewDependency
	Shares  []string
	// Reasons make an update of this service unavailable.
	Reasons []string
}

// PreviewDependency is one direct dependency of a service.
type PreviewDependency struct {
	Service string
	Restart bool
}

// PreviewTarget is one container with its full identity.
type PreviewTarget struct {
	Service             string
	ContainerID         string
	ContainerName       string
	State               string
	ImageID             string
	RunningReference    string
	ConfigurationDigest string
}

// PreviewImage is the image facts of one (image ID, running reference).
type PreviewImage struct {
	ImageID          string
	RunningReference string
	Repository       string
	Tag              string
	Platform         string
	OldDigests       []string
	// Resolved: the current tag first, then each target tag.
	Resolved []PreviewResolution
	Reason   string
}

// PreviewResolution is one tag resolved anonymously on the host.
type PreviewResolution struct {
	Tag            string
	IndexDigest    string
	PlatformDigest string
	// Reason is "" or tag_unresolved (then both digests are "").
	Reason string
}

type previewDoc struct {
	Format string             `json:"format"`
	Status string             `json:"status"`
	Units  *[]json.RawMessage `json:"units"`
}

type previewUnitDoc struct {
	Form            *string            `json:"form"`
	Project         *string            `json:"project"`
	ContainerID     *string            `json:"container_id"`
	Reason          *string            `json:"reason"`
	WorkingDirHash  *string            `json:"working_dir_hash"`
	ConfigFilesHash *string            `json:"config_files_hash"`
	SourceDigest    *string            `json:"source_digest"`
	Services        *[]previewSvcDoc   `json:"services"`
	Targets         *[]previewTarget   `json:"targets"`
	Images          *[]previewImageDoc `json:"images"`
}

type previewSvcDoc struct {
	Service  *string          `json:"service"`
	Replicas *int             `json:"replicas"`
	Scale    *int             `json:"scale"`
	Depends  *[]previewDepDoc `json:"depends"`
	Shares   *[]string        `json:"shares"`
	Reasons  *[]string        `json:"reasons"`
}

type previewDepDoc struct {
	Service *string `json:"service"`
	Restart *bool   `json:"restart"`
}

type previewTarget struct {
	Service             *string `json:"service"`
	ContainerID         *string `json:"container_id"`
	ContainerName       *string `json:"container_name"`
	State               *string `json:"state"`
	ImageID             *string `json:"image_id"`
	RunningReference    *string `json:"running_reference"`
	ConfigurationDigest *string `json:"configuration_digest"`
}

type previewImageDoc struct {
	ImageID          *string          `json:"image_id"`
	RunningReference *string          `json:"running_reference"`
	Repository       *string          `json:"repository"`
	Tag              *string          `json:"tag"`
	Platform         *string          `json:"platform"`
	OldDigests       *[]string        `json:"old_digests"`
	Resolved         *[]previewResDoc `json:"resolved"`
	Reason           *string          `json:"reason"`
}

type previewResDoc struct {
	Tag            *string `json:"tag"`
	IndexDigest    *string `json:"index_digest"`
	PlatformDigest *string `json:"platform_digest"`
	Reason         *string `json:"reason"`
}

// strictDecode decodes exactly one JSON value with no unknown members.
func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func previewErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrPreviewFormat}, args...)...)
}

// ParseUpdatePreview reads a docker-update-preview-v1 result strictly:
// every member present with its type, no unknown member, every value
// within its pattern and limit, every list in its order without
// duplicates, and the facts present exactly where the reason allows.
func ParseUpdatePreview(result []byte) (UpdatePreview, error) {
	if len(result) > MaxPreviewResultBytes || !utf8.Valid(result) {
		return UpdatePreview{}, previewErr("size or encoding")
	}
	var doc previewDoc
	if err := strictDecode(result, &doc); err != nil {
		return UpdatePreview{}, previewErr("%v", err)
	}
	if doc.Format != "docker-update-preview-v1" || !previewStatuses[doc.Status] || doc.Units == nil {
		return UpdatePreview{}, previewErr("format, status or units")
	}
	out := UpdatePreview{Status: doc.Status}
	if doc.Status != PreviewOK {
		if len(*doc.Units) != 0 {
			return UpdatePreview{}, previewErr("units with status %s", doc.Status)
		}
		return out, nil
	}
	var facts, projects int
	var prev PreviewUnit
	seenIDs := map[string]bool{}
	for i, raw := range *doc.Units {
		u, err := parsePreviewUnit(raw)
		if err != nil {
			return UpdatePreview{}, fmt.Errorf("unit %d: %w", i, err)
		}
		if i > 0 && !previewUnitLess(prev, u) {
			return UpdatePreview{}, previewErr("unit %d out of order", i)
		}
		prev = u
		if u.Form == "compose" {
			projects++
		}
		if u.HasFacts() {
			if u.Form == "compose" && projects > MaxPreviewProjects {
				return UpdatePreview{}, previewErr("more than %d projects with facts", MaxPreviewProjects)
			}
			facts += len(u.Targets)
			for _, t := range u.Targets {
				if seenIDs[t.ContainerID] {
					return UpdatePreview{}, previewErr("container %s in two units", t.ContainerID)
				}
				seenIDs[t.ContainerID] = true
			}
		}
		out.Units = append(out.Units, u)
	}
	if facts > MaxPreviewContainers {
		return UpdatePreview{}, previewErr("more than %d containers", MaxPreviewContainers)
	}
	return out, nil
}

// previewUnitLess: Compose units by project, then standalone units by ID.
func previewUnitLess(a, b PreviewUnit) bool {
	if a.Form != b.Form {
		return a.Form == "compose"
	}
	if a.Form == "compose" {
		return a.Project < b.Project
	}
	return a.ContainerID < b.ContainerID
}

func str(p *string) (string, bool) {
	if p == nil {
		return "", false
	}
	return *p, true
}

func parsePreviewUnit(raw json.RawMessage) (PreviewUnit, error) {
	var d previewUnitDoc
	if err := strictDecode(raw, &d); err != nil {
		return PreviewUnit{}, previewErr("%v", err)
	}
	var u PreviewUnit
	var ok1, ok2, ok3, ok4 bool
	u.Form, ok1 = str(d.Form)
	u.Project, ok2 = str(d.Project)
	u.ContainerID, ok3 = str(d.ContainerID)
	u.Reason, ok4 = str(d.Reason)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return PreviewUnit{}, previewErr("unit head")
	}
	switch u.Form {
	case "compose":
		if !previewProjectRe.MatchString(u.Project) || u.ContainerID != "" || !previewComposeReasons[u.Reason] {
			return PreviewUnit{}, previewErr("compose unit head")
		}
	case "standalone":
		if u.Project != "" || !previewHex64Re.MatchString(u.ContainerID) || !previewStandaloneReasons[u.Reason] {
			return PreviewUnit{}, previewErr("standalone unit head")
		}
	default:
		return PreviewUnit{}, previewErr("form")
	}
	compose := u.Form == "compose"
	factsPresent := d.Targets != nil || d.Images != nil || d.Services != nil || d.SourceDigest != nil ||
		d.WorkingDirHash != nil || d.ConfigFilesHash != nil
	if !u.HasFacts() {
		if factsPresent {
			return PreviewUnit{}, previewErr("facts with reason %s", u.Reason)
		}
		return u, nil
	}
	if d.Targets == nil || d.Images == nil || (compose != (d.Services != nil && d.SourceDigest != nil &&
		d.WorkingDirHash != nil && d.ConfigFilesHash != nil)) || (!compose && (d.Services != nil || d.SourceDigest != nil ||
		d.WorkingDirHash != nil || d.ConfigFilesHash != nil)) {
		return PreviewUnit{}, previewErr("incomplete facts")
	}
	services := map[string]*PreviewService{}
	if compose {
		u.WorkingDirHash, u.ConfigFilesHash, u.SourceDigest = *d.WorkingDirHash, *d.ConfigFilesHash, *d.SourceDigest
		for _, h := range []string{u.WorkingDirHash, u.ConfigFilesHash, u.SourceDigest} {
			if !previewHex64Re.MatchString(h) {
				return PreviewUnit{}, previewErr("hash")
			}
		}
		var err error
		if u.Services, err = parsePreviewServices(*d.Services, u.Reason); err != nil {
			return PreviewUnit{}, err
		}
		for i := range u.Services {
			services[u.Services[i].Service] = &u.Services[i]
		}
	}
	targets, err := parsePreviewTargets(*d.Targets, compose, services)
	if err != nil {
		return PreviewUnit{}, err
	}
	u.Targets = targets
	if !compose && (len(targets) != 1 || targets[0].ContainerID != u.ContainerID) {
		return PreviewUnit{}, previewErr("standalone target")
	}
	if u.Images, err = parsePreviewImages(*d.Images, targets); err != nil {
		return PreviewUnit{}, err
	}
	return u, nil
}

func sortedUnique(xs []string, valid func(string) bool) bool {
	for i, x := range xs {
		if !valid(x) || (i > 0 && xs[i-1] >= x) {
			return false
		}
	}
	return true
}

func parsePreviewServices(docs []previewSvcDoc, unitReason string) ([]PreviewService, error) {
	if len(docs) == 0 || len(docs) > MaxPreviewContainers {
		return nil, previewErr("service count")
	}
	out := make([]PreviewService, 0, len(docs))
	names := map[string]bool{}
	for i, d := range docs {
		if d.Service == nil || d.Replicas == nil || d.Scale == nil || d.Depends == nil || d.Shares == nil || d.Reasons == nil {
			return nil, previewErr("service %d incomplete", i)
		}
		s := PreviewService{Service: *d.Service, Replicas: *d.Replicas, Scale: *d.Scale, Shares: *d.Shares, Reasons: *d.Reasons}
		if !previewServiceRe.MatchString(s.Service) || (i > 0 && out[i-1].Service >= s.Service) {
			return nil, previewErr("service %d name or order", i)
		}
		if s.Replicas < 0 || s.Replicas > MaxPreviewContainers || s.Scale < -1 {
			return nil, previewErr("service %s counts", s.Service)
		}
		if !sortedUnique(s.Reasons, func(r string) bool { return previewServiceReasons[r] }) {
			return nil, previewErr("service %s reasons", s.Service)
		}
		// override_drift takes precedence over config_not_applied (Q27).
		if unitReason == PreviewOverrideDrift && slices.Contains(s.Reasons, "config_not_applied") {
			return nil, previewErr("config_not_applied beside override_drift")
		}
		if s.Replicas == 0 && len(s.Reasons) != 0 {
			return nil, previewErr("service %s without containers has reasons", s.Service)
		}
		if !sortedUnique(s.Shares, previewServiceRe.MatchString) {
			return nil, previewErr("service %s shares", s.Service)
		}
		for j, dep := range *d.Depends {
			if dep.Service == nil || dep.Restart == nil || !previewServiceRe.MatchString(*dep.Service) ||
				(j > 0 && s.Depends[j-1].Service >= *dep.Service) {
				return nil, previewErr("service %s depends", s.Service)
			}
			s.Depends = append(s.Depends, PreviewDependency{Service: *dep.Service, Restart: *dep.Restart})
		}
		names[s.Service] = true
		out = append(out, s)
	}
	for _, s := range out {
		for _, dep := range s.Depends {
			if !names[dep.Service] {
				return nil, previewErr("service %s depends on an unknown service", s.Service)
			}
		}
		for _, sh := range s.Shares {
			if !names[sh] {
				return nil, previewErr("service %s shares with an unknown service", s.Service)
			}
		}
	}
	return out, nil
}

// previewReference is a running reference as the script accepts it:
// printable ASCII without spaces, at most 512 bytes.
func previewReference(s string) bool {
	if s == "" || len(s) > 512 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

func parsePreviewTargets(docs []previewTarget, compose bool, services map[string]*PreviewService) ([]PreviewTarget, error) {
	if len(docs) == 0 || len(docs) > MaxPreviewContainers {
		return nil, previewErr("target count")
	}
	out := make([]PreviewTarget, 0, len(docs))
	names := map[string]bool{}
	ids := map[string]bool{}
	count := map[string]int{}
	for i, d := range docs {
		if d.Service == nil || d.ContainerID == nil || d.ContainerName == nil || d.State == nil || d.ImageID == nil ||
			d.RunningReference == nil || d.ConfigurationDigest == nil {
			return nil, previewErr("target %d incomplete", i)
		}
		t := PreviewTarget{Service: *d.Service, ContainerID: *d.ContainerID, ContainerName: *d.ContainerName, State: *d.State,
			ImageID: *d.ImageID, RunningReference: *d.RunningReference, ConfigurationDigest: *d.ConfigurationDigest}
		if compose {
			if services[t.Service] == nil {
				return nil, previewErr("target %d service", i)
			}
		} else if t.Service != "" {
			return nil, previewErr("standalone target with a service")
		}
		if !previewHex64Re.MatchString(t.ContainerID) || !previewCNameRe.MatchString(t.ContainerName) || !states[t.State] ||
			!previewDigestRe.MatchString(t.ImageID) || !previewReference(t.RunningReference) ||
			!previewHex64Re.MatchString(t.ConfigurationDigest) {
			return nil, previewErr("target %d values", i)
		}
		if i > 0 {
			p := out[i-1]
			if p.Service > t.Service || (p.Service == t.Service && p.ContainerID >= t.ContainerID) {
				return nil, previewErr("target %d order", i)
			}
		}
		if ids[t.ContainerID] || names[t.ContainerName] {
			return nil, previewErr("target %d duplicate", i)
		}
		ids[t.ContainerID], names[t.ContainerName] = true, true
		count[t.Service]++
		out = append(out, t)
	}
	for name, s := range services {
		if s.Replicas != count[name] {
			return nil, previewErr("service %s replicas", name)
		}
	}
	return out, nil
}

func parsePreviewImages(docs []previewImageDoc, targets []PreviewTarget) ([]PreviewImage, error) {
	want := map[[2]string]bool{}
	for _, t := range targets {
		want[[2]string{t.ImageID, t.RunningReference}] = true
	}
	if len(docs) != len(want) {
		return nil, previewErr("image count")
	}
	out := make([]PreviewImage, 0, len(docs))
	for i, d := range docs {
		if d.ImageID == nil || d.RunningReference == nil || d.Repository == nil || d.Tag == nil || d.Platform == nil ||
			d.OldDigests == nil || d.Resolved == nil || d.Reason == nil {
			return nil, previewErr("image %d incomplete", i)
		}
		im := PreviewImage{ImageID: *d.ImageID, RunningReference: *d.RunningReference, Repository: *d.Repository, Tag: *d.Tag,
			Platform: *d.Platform, OldDigests: *d.OldDigests, Reason: *d.Reason}
		key := [2]string{im.ImageID, im.RunningReference}
		if !want[key] {
			return nil, previewErr("image %d is no target's", i)
		}
		if i > 0 {
			p := out[i-1]
			if p.ImageID > im.ImageID || (p.ImageID == im.ImageID && p.RunningReference >= im.RunningReference) {
				return nil, previewErr("image %d order", i)
			}
		}
		if !previewImageReasons[im.Reason] {
			return nil, previewErr("image %d reason", i)
		}
		if err := checkPreviewImage(&im, *d.Resolved); err != nil {
			return nil, fmt.Errorf("image %d: %w", i, err)
		}
		out = append(out, im)
	}
	return out, nil
}

func checkPreviewImage(im *PreviewImage, res []previewResDoc) error {
	if im.Reason == "reference_unsupported" {
		if im.Repository != "" || im.Tag != "" || im.Platform != "" || len(im.OldDigests) != 0 || len(res) != 0 {
			return previewErr("facts of an unsupported reference")
		}
		return nil
	}
	// The repository and tag are the canonical parse of the reference.
	ref, err := canonical.ParseImageReference(im.RunningReference)
	if err != nil || ref.Repository != im.Repository || ref.Tag != im.Tag {
		return previewErr("repository or tag")
	}
	if im.Platform != "" && !previewPlatformRe.MatchString(im.Platform) {
		return previewErr("platform")
	}
	if im.Reason != "" {
		if len(im.OldDigests) != 0 || len(res) != 0 || (im.Reason == "platform_unknown" && im.Platform != "") {
			return previewErr("facts beside reason %s", im.Reason)
		}
		return nil
	}
	if im.Platform == "" || len(im.OldDigests) == 0 || len(im.OldDigests) > MaxPreviewOldDigests ||
		!sortedUnique(im.OldDigests, previewDigestRe.MatchString) {
		return previewErr("platform or old digests")
	}
	if len(res) == 0 || len(res) > MaxPreviewTargetTags+1 {
		return previewErr("resolution count")
	}
	tags := map[string]bool{}
	for j, r := range res {
		if r.Tag == nil || r.IndexDigest == nil || r.PlatformDigest == nil || r.Reason == nil {
			return previewErr("resolution %d incomplete", j)
		}
		x := PreviewResolution{Tag: *r.Tag, IndexDigest: *r.IndexDigest, PlatformDigest: *r.PlatformDigest, Reason: *r.Reason}
		if !previewTagRe.MatchString(x.Tag) || tags[x.Tag] || (j == 0 && x.Tag != im.Tag) {
			return previewErr("resolution %d tag", j)
		}
		tags[x.Tag] = true
		switch x.Reason {
		case "":
			if !previewDigestRe.MatchString(x.PlatformDigest) ||
				(x.IndexDigest != "" && (!previewDigestRe.MatchString(x.IndexDigest) || x.IndexDigest == x.PlatformDigest)) {
				return previewErr("resolution %d digests", j)
			}
		case "tag_unresolved":
			if x.IndexDigest != "" || x.PlatformDigest != "" {
				return previewErr("resolution %d digests beside tag_unresolved", j)
			}
		default:
			return previewErr("resolution %d reason", j)
		}
		im.Resolved = append(im.Resolved, x)
	}
	return nil
}

// Available reports whether service svc of the unit can get a new update
// binding from this preview: the unit is available, the service has
// containers and no reason, and every image of its containers has
// facts. Dependency and namespace rules are the planner's.
func (u PreviewUnit) Available(svc string) bool {
	if u.Reason != "" || u.Form != "compose" {
		return false
	}
	i := slices.IndexFunc(u.Services, func(s PreviewService) bool { return s.Service == svc })
	if i < 0 || u.Services[i].Replicas == 0 || len(u.Services[i].Reasons) != 0 {
		return false
	}
	for _, t := range u.Targets {
		if t.Service != svc {
			continue
		}
		j := slices.IndexFunc(u.Images, func(im PreviewImage) bool {
			return im.ImageID == t.ImageID && im.RunningReference == t.RunningReference
		})
		if j < 0 || u.Images[j].Reason != "" {
			return false
		}
	}
	return true
}

// PreviewReasons is every reason the preview can report, for display code
// that must name each one (cu04).
func PreviewReasons() []string {
	var out []string
	for _, m := range []map[string]bool{previewComposeReasons, previewServiceReasons, previewImageReasons} {
		for r := range m {
			if r != "" && !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	out = append(out, "tag_unresolved")
	slices.Sort(out)
	return out
}
