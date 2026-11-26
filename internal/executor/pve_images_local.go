// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// This file is the durable store of the local image entries (trust
// "Local") and the image RPCs of ADR 0008 amendment 2: AddPVELocalImage
// and RemovePVELocalImage (D3 (a), admin only over the admin socket) and
// ListPVEImages (D4 (a), server and admin, read only). The executor is the
// only writer of the local entries: one code path (PveImageCatalog.AddLocal
// and RemoveLocal) validates, persists and then updates the in-memory
// catalog. The server never forwards the local-entry RPCs, and no RPC here
// writes template records.

// Local image limits.
const (
	// maxPveLocalImages bounds the local entries.
	maxPveLocalImages = 64
	// maxPveLocalImageFile bounds pve-catalog-local.json: maxPveLocalImages
	// entries of at most about 2.4 KiB each (the URL is at most
	// release.MaxImageURL bytes), with room for the JSON framing.
	maxPveLocalImageFile = 256 << 10
	// maxPveLocalImageID bounds a local image ID (the catalog grammar
	// allows 64 bytes).
	maxPveLocalImageID = 64
	// pveLocalImageFormat is the "format" of pve-catalog-local.json.
	pveLocalImageFormat = "nebula-local-images-v1"
)

var (
	// ErrPveLocalImageInvalid is returned for a local entry that fails the
	// catalog grammar (release.ValidateImage with local=true, which also
	// requires the "local-" prefix) or a malformed local image ID.
	ErrPveLocalImageInvalid = errors.New("executor: local image entry is invalid")
	// ErrPveLocalImageLimit is returned when a new entry would exceed
	// maxPveLocalImages.
	ErrPveLocalImageLimit = errors.New("executor: too many local image entries")
	// ErrPveLocalImageStore is returned when the local entries cannot be
	// read or written. The catalog then serves no local entry and refuses
	// every change, so an unreadable file is never overwritten.
	ErrPveLocalImageStore = errors.New("executor: local image entries unavailable")
)

// PveLocalImageStore persists the local image entries.
type PveLocalImageStore interface {
	// PveLocalImages returns the stored entries; none when nothing was ever
	// written. Present but invalid content is an error.
	PveLocalImages() ([]release.Image, error)
	// PutPveLocalImages durably replaces the stored entries.
	PutPveLocalImages(imgs []release.Image) error
}

// FilePveLocalImages keeps the local entries in one JSON file beside the
// catalog state (e.g. <state dir>/pve-catalog-local.json), written
// atomically with mode 0600 like FilePveCatalogState. It is safe for
// concurrent use within one process.
type FilePveLocalImages struct {
	// Path is the file.
	Path string

	mu sync.Mutex
}

type pveLocalImageJSON struct {
	ID         string `json:"id"`
	OS         string `json:"os"`
	Release    string `json:"release"`
	Arch       string `json:"arch"`
	URL        string `json:"url"`
	SHA256     string `json:"sha256"`
	DiskFormat string `json:"disk_format"`
}

type pveLocalImageFile struct {
	Format string              `json:"format"`
	Images []pveLocalImageJSON `json:"images"`
}

// checkLocalImages checks a complete set of local entries: each passes the
// catalog grammar as a local entry, the IDs are unique and the count is
// within maxPveLocalImages.
func checkLocalImages(imgs []release.Image) error {
	if len(imgs) > maxPveLocalImages {
		return fmt.Errorf("more than %d local images: %w", maxPveLocalImages, ErrPveLocalImageLimit)
	}
	seen := make(map[string]bool, len(imgs))
	for i, img := range imgs {
		if err := release.ValidateImage(img, true); err != nil {
			return fmt.Errorf("local image %d: %w", i, err)
		}
		if seen[img.ID] {
			return fmt.Errorf("local image %d: duplicate id", i)
		}
		seen[img.ID] = true
	}
	return nil
}

// PveLocalImages implements PveLocalImageStore.
func (s *FilePveLocalImages) PveLocalImages() ([]release.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open local images: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPveLocalImageFile+1))
	if err != nil {
		return nil, fmt.Errorf("read local images: %w", err)
	}
	if len(raw) > maxPveLocalImageFile {
		return nil, fmt.Errorf("local images exceed %d bytes", maxPveLocalImageFile)
	}
	if !utf8.Valid(raw) {
		return nil, errors.New("decode local images: not UTF-8")
	}
	var doc pveLocalImageFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode local images: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode local images: trailing data")
	}
	if doc.Format != pveLocalImageFormat {
		return nil, fmt.Errorf("decode local images: format is not %q", pveLocalImageFormat)
	}
	imgs := make([]release.Image, 0, len(doc.Images))
	for _, j := range doc.Images {
		imgs = append(imgs, release.Image(j))
	}
	if err := checkLocalImages(imgs); err != nil {
		return nil, fmt.Errorf("decode local images: %w", err)
	}
	return imgs, nil
}

// PutPveLocalImages implements PveLocalImageStore. The entries are written
// sorted by ID.
func (s *FilePveLocalImages) PutPveLocalImages(imgs []release.Image) error {
	if err := checkLocalImages(imgs); err != nil {
		return fmt.Errorf("write local images: %w", err)
	}
	doc := pveLocalImageFile{Format: pveLocalImageFormat, Images: make([]pveLocalImageJSON, 0, len(imgs))}
	for _, img := range imgs {
		doc.Images = append(doc.Images, pveLocalImageJSON(img))
	}
	slices.SortFunc(doc.Images, func(a, b pveLocalImageJSON) int { return strings.Compare(a.ID, b.ID) })
	raw, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("encode local images: %w", err)
	}
	if len(raw) > maxPveLocalImageFile {
		return fmt.Errorf("local images exceed %d bytes: %w", maxPveLocalImageFile, ErrPveLocalImageLimit)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeFileAtomic(s.Path, raw)
}

// PveTemplates returns every template record, sorted by remote, node,
// storage and image. It only reads.
func (s *FilePveTemplateStore) PveTemplates() ([]PveTemplateRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recs, err := s.load()
	if err != nil {
		return nil, err
	}
	slices.SortFunc(recs, func(a, b PveTemplateRecord) int {
		for _, c := range [][2]string{{a.RemoteID, b.RemoteID}, {a.Node, b.Node}, {a.Storage, b.Storage}, {a.ImageID, b.ImageID}} {
			if r := strings.Compare(c[0], c[1]); r != 0 {
				return r
			}
		}
		return 0
	})
	return recs, nil
}

// pveTemplateLister is the read-only listing of a PveTemplateStore.
type pveTemplateLister interface {
	PveTemplates() ([]PveTemplateRecord, error)
}

// PveCatalogListing is the read-only view of a PveImageCatalog.
type PveCatalogListing struct {
	// Sequence and Digest identify the loaded signed catalog; zero and
	// empty when none is loaded.
	Sequence int64
	Digest   string
	// Images are the signed entries (by ID), then the local ones (by ID).
	Images []PveImage
}

// validLocalImageID reports whether id can name a local entry: valid
// UTF-8, the "local-" prefix and at most maxPveLocalImageID bytes. The
// full grammar is checked when an entry is added.
func validLocalImageID(id string) bool {
	return len(id) <= maxPveLocalImageID && utf8.ValidString(id) && strings.HasPrefix(id, release.LocalImagePrefix) &&
		len(id) > len(release.LocalImagePrefix)
}

// Fixed refusal reasons of the local-entry audit; never error texts.
const (
	pveLocalRefusedRole    = "role"
	pveLocalRefusedInvalid = "invalid"
	pveLocalRefusedLimit   = "limit"
	pveLocalRefusedStore   = "store"
	pveLocalRefusedNoState = "no_state_dir"
)

// pveCallerHasRole refuses a caller whose peer-credential role (set by the
// policy interceptor from the admin socket's peer UID) is not in roles. It
// repeats the role table's check in the handler, so a role table change
// alone never opens the method.
func pveCallerHasRole(ctx context.Context, roles ...peercred.Role) bool {
	c, ok := peercred.CallerFrom(ctx)
	return ok && slices.Contains(roles, c.Role)
}

// pveImageCatalog returns the executor's one image catalog (that of its
// provisioner), or a FailedPrecondition error when the executor has no
// state directory.
func (s *Service) pveImageCatalog() (*PveImageCatalog, *PveImages, error) {
	p := s.pveProvisioner()
	if p == nil || p.Images == nil || p.Images.Catalog == nil {
		return nil, nil, status.Error(codes.FailedPrecondition, "pve images: the executor has no state directory")
	}
	return p.Images.Catalog, p.Images, nil
}

// auditLocalRefused writes the audit line of a refused local-entry change.
// reason is a fixed token; the image ID is logged only when it is a valid
// local ID.
func (s *Service) auditLocalRefused(ctx context.Context, op, id, reason string) {
	if !validLocalImageID(id) {
		id = ""
	}
	s.log.Warn("audit", "kind", "pve_local_image_refused", "op", op, "image", id, "reason", reason, "by", callerName(ctx))
}

// localImageRPCError maps a local-entry error to its audit reason and
// status.
func localImageRPCError(err error) (string, error) {
	switch {
	case errors.Is(err, ErrPveLocalImageStore):
		// First: a store error may wrap the grammar or limit error of a
		// corrupt file, which is not the caller's entry.
		return pveLocalRefusedStore, status.Error(codes.Unavailable, "local image: the local entries cannot be read or written; nothing changed")
	case errors.Is(err, ErrPveLocalImageInvalid), errors.Is(err, release.ErrFormat):
		return pveLocalRefusedInvalid, status.Error(codes.InvalidArgument, "local image: the entry is invalid; the id must start with \"local-\" and the entry must follow the image catalog grammar (https URL, sha256, qcow2 or raw)")
	case errors.Is(err, ErrPveLocalImageLimit):
		return pveLocalRefusedLimit, status.Error(codes.ResourceExhausted, fmt.Sprintf("local image: at most %d local entries", maxPveLocalImages))
	default:
		return pveLocalRefusedStore, status.Error(codes.Unavailable, "local image: the local entries cannot be read or written; nothing changed")
	}
}

// AddPVELocalImage adds or replaces a local image entry (trust "Local",
// D3 (a)). Only the admin role, identified by the admin socket's peer UID,
// may call it. The entry is validated with the catalog grammar (the
// "local-" prefix included), persisted in the executor's state directory,
// made current and audited with the caller. A refused entry changes
// nothing.
func (s *Service) AddPVELocalImage(ctx context.Context, in *pb.AddPVELocalImageRequest) (*pb.AddPVELocalImageResponse, error) {
	const op = "add"
	pi := in.GetImage()
	if !pveCallerHasRole(ctx, peercred.RoleAdmin) {
		s.auditLocalRefused(ctx, op, pi.GetId(), pveLocalRefusedRole)
		return nil, status.Error(codes.PermissionDenied, "add local image: admin role required")
	}
	cat, _, err := s.pveImageCatalog()
	if err != nil {
		s.auditLocalRefused(ctx, op, pi.GetId(), pveLocalRefusedNoState)
		return nil, err
	}
	if pi == nil {
		s.auditLocalRefused(ctx, op, "", pveLocalRefusedInvalid)
		return nil, status.Error(codes.InvalidArgument, "add local image: no image")
	}
	img := release.Image{ID: pi.GetId(), OS: pi.GetOs(), Release: pi.GetRelease(), Arch: pi.GetArch(), URL: pi.GetUrl(), SHA256: pi.GetSha256(), DiskFormat: pi.GetDiskFormat()}
	replaced, err := cat.addLocal(img)
	if err != nil {
		reason, st := localImageRPCError(err)
		if reason == pveLocalRefusedStore {
			s.log.Error("pve local image store", "op", op, "err", err)
		}
		s.auditLocalRefused(ctx, op, img.ID, reason)
		return nil, st
	}
	s.log.Info("audit", "kind", "pve_local_image_added", "image", img.ID, "os", img.OS, "release", img.Release, "arch", img.Arch,
		"url", img.URL, "sha256", img.SHA256, "disk_format", img.DiskFormat, "replaced", replaced, "by", callerName(ctx))
	return &pb.AddPVELocalImageResponse{}, nil
}

// RemovePVELocalImage removes a local image entry (D3 (a)); admin role
// only. The removal is persisted before the catalog stops serving the
// entry, and audited. A template prepared from it no longer binds.
func (s *Service) RemovePVELocalImage(ctx context.Context, in *pb.RemovePVELocalImageRequest) (*pb.RemovePVELocalImageResponse, error) {
	const op = "remove"
	id := in.GetImageId()
	if !pveCallerHasRole(ctx, peercred.RoleAdmin) {
		s.auditLocalRefused(ctx, op, id, pveLocalRefusedRole)
		return nil, status.Error(codes.PermissionDenied, "remove local image: admin role required")
	}
	cat, _, err := s.pveImageCatalog()
	if err != nil {
		s.auditLocalRefused(ctx, op, id, pveLocalRefusedNoState)
		return nil, err
	}
	if !validLocalImageID(id) {
		s.auditLocalRefused(ctx, op, "", pveLocalRefusedInvalid)
		return nil, status.Error(codes.InvalidArgument, "remove local image: the id must start with \"local-\" and have at most 64 bytes")
	}
	removed, err := cat.RemoveLocal(id)
	if err != nil {
		reason, st := localImageRPCError(err)
		if reason == pveLocalRefusedStore {
			s.log.Error("pve local image store", "op", op, "err", err)
		}
		s.auditLocalRefused(ctx, op, id, reason)
		return nil, st
	}
	s.log.Info("audit", "kind", "pve_local_image_removed", "image", id, "removed", removed, "by", callerName(ctx))
	return &pb.RemovePVELocalImageResponse{Removed: removed}, nil
}

// ListPVEImages lists the image catalog (signed and local entries with
// their trust) and the executor's template records (D4 (a)); role server or
// admin, never the pve-collector. It returns only catalog and record data:
// no credentials, no PVE output, and it writes nothing.
func (s *Service) ListPVEImages(ctx context.Context, _ *pb.ListPVEImagesRequest) (*pb.ListPVEImagesResponse, error) {
	if !pveCallerHasRole(ctx, peercred.RoleServer, peercred.RoleAdmin) {
		return nil, status.Error(codes.PermissionDenied, "list pve images: server or admin role required")
	}
	cat, imgs, err := s.pveImageCatalog()
	if err != nil {
		return nil, err
	}
	l, err := cat.List()
	if err != nil {
		s.log.Error("pve local image store", "op", "list", "err", err)
		return nil, status.Error(codes.Unavailable, "list pve images: the local entries cannot be read")
	}
	lister, ok := imgs.Templates.(pveTemplateLister)
	if !ok {
		return nil, status.Error(codes.Internal, "list pve images: template records cannot be listed")
	}
	recs, err := lister.PveTemplates()
	if err != nil {
		s.log.Error("pve template records", "op", "list", "err", err)
		return nil, status.Error(codes.Unavailable, "list pve images: the template records cannot be read")
	}
	out := &pb.ListPVEImagesResponse{CatalogSequence: l.Sequence, CatalogDigest: l.Digest,
		Images: make([]*pb.PVEImage, 0, len(l.Images)), Templates: make([]*pb.PVETemplateRecord, 0, len(recs))}
	for _, img := range l.Images {
		out.Images = append(out.Images, &pb.PVEImage{
			Image: &pb.PVECatalogImage{Id: img.ID, Os: img.OS, Release: img.Release, Arch: img.Arch, Url: img.URL, Sha256: img.SHA256, DiskFormat: img.DiskFormat},
			Trust: string(img.Trust), CatalogSequence: img.CatalogSequence, CatalogDigest: img.CatalogDigest,
		})
	}
	for _, r := range recs {
		out.Templates = append(out.Templates, &pb.PVETemplateRecord{
			RemoteId: r.RemoteID, Node: r.Node, Storage: r.Storage, ImageId: r.ImageID, Trust: string(r.Trust),
			Vmid: r.VMID, Generation: r.Generation, SourceSha256: r.SourceSHA256, ConfigDigest: r.ConfigDigest,
			TrustGeneration: r.TrustGeneration, ExecutionId: r.ExecutionID, PreparedAtUnix: r.PreparedAt.Unix(),
		})
	}
	return out, nil
}
