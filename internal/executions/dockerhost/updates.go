// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/registrymeta"
)

// ImageUpdate is one image of a docker.check_updates result.
type ImageUpdate struct {
	Image string
	// Status is current, update, pinned or unknown.
	Status string
	// Remote is the registry's digest for the tag (current, update), or for
	// a Private image the digest the executor read.
	Remote string
	Note   string
	// Private is set by ResolvePrivateDigests for an image on an executor
	// private registry: the host cannot read it (it holds no credential),
	// so the executor did, under a registry read lease.
	Private bool
}

// ImageUpdates is a parsed docker.check_updates result.
type ImageUpdates struct {
	Phase   string
	Reason  string
	Images  []ImageUpdate
	Updates int
}

// ErrUpdatesFormat means the result is not a docker.check_updates result.
var ErrUpdatesFormat = errors.New("dockerhost: not a docker.check_updates result")

var (
	imageRefRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,299}$`)
	digestOnlyRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	updateStates = map[string]bool{"current": true, "update": true, "pinned": true, "unknown": true}
)

const maxImages = 50

// ParseImageUpdates reads a docker.check_updates result. Lines that do not
// fit are left out.
func ParseImageUpdates(result []byte) (ImageUpdates, error) {
	var doc struct {
		Format string `json:"format"`
		Phase  string `json:"phase"`
		Reason string `json:"reason"`
		Lines  string `json:"lines"`
	}
	if json.Unmarshal(result, &doc) != nil || doc.Format != "docker-updates-v1" || (doc.Phase != "done" && doc.Phase != "precheck") {
		return ImageUpdates{}, ErrUpdatesFormat
	}
	u := ImageUpdates{Phase: doc.Phase}
	if doc.Phase == "precheck" {
		u.Reason = text(doc.Reason, 300)
		return u, nil
	}
	t, ok := decode(doc.Lines)
	if !ok {
		return ImageUpdates{}, ErrUpdatesFormat
	}
	for _, line := range strings.Split(t, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || len(u.Images) >= maxImages || !imageRefRe.MatchString(f[0]) || !updateStates[f[1]] {
			continue
		}
		x := ImageUpdate{Image: f[0], Status: f[1], Note: text(f[3], 200)}
		if digestOnlyRe.MatchString(f[2]) {
			x.Remote = f[2]
		} else if f[1] == "current" || f[1] == "update" {
			x.Status, x.Note = "unknown", "no valid digest"
		}
		if x.Status == "update" {
			u.Updates++
		}
		u.Images = append(u.Images, x)
	}
	return u, nil
}

// Notes of images ResolvePrivateDigests handled. Fixed text: neither the
// executor's nor the registry's words reach the page.
const (
	privateNoteRead        = "registry digest read by the executor (private registry); the local digest is not compared"
	privateNoteRefused     = "private registry: no approved registry read lease covers this read, or reads are paused"
	privateNoteRateLimited = "private registry: rate limited (the lease's hourly budget or 15-minute interval is used up), retry later"
	privateNoteOutScope    = "private registry: the repository is outside the registry's approved scope"
	privateNoteFailed      = "private registry: the executor could not read the digest"
)

// PrivateDigestSource resolves private image digests through the executor;
// *registrymeta.DigestReader (the server's long-lived, cached reader)
// implements it.
type PrivateDigestSource interface {
	PrivateDigests(ctx context.Context, images []string) (map[string]registrymeta.PrivateDigest, map[string]error, error)
}

// uncachedSource reads every time (registrymeta.PrivateDigests).
type uncachedSource struct{ exec registrymeta.ExecutorRegistry }

func (u uncachedSource) PrivateDigests(ctx context.Context, images []string) (map[string]registrymeta.PrivateDigest, map[string]error, error) {
	return registrymeta.PrivateDigests(ctx, u.exec, images)
}

// ResolvePrivateDigests is the server caller of private registry reads for
// docker.check_updates (cu06 part 1, G13): every image the host reported
// "unknown" that lies on an executor private registry gets the registry's
// current digest from the executor (registrymeta.PrivateDigests, one
// ReadPrivateRegistry tag_digest read per repository and tag, authorized by
// a registry read lease). The credential stays in the executor; the host
// and the server see only the digest. Status stays "unknown", because the
// result carries no local digest to compare with. An error is returned only
// when the executor's registries cannot be listed; u is then unchanged.
// It reads every time; the server uses ResolvePrivateDigestsWith and one
// long-lived registrymeta.DigestReader so a re-render is not rate limited.
func ResolvePrivateDigests(ctx context.Context, u ImageUpdates, exec registrymeta.ExecutorRegistry) (ImageUpdates, error) {
	return ResolvePrivateDigestsWith(ctx, u, uncachedSource{exec: exec})
}

// ResolvePrivateDigestsWith is ResolvePrivateDigests over src.
func ResolvePrivateDigestsWith(ctx context.Context, u ImageUpdates, src PrivateDigestSource) (ImageUpdates, error) {
	var ask []string
	for _, im := range u.Images {
		if im.Status == "unknown" && !slices.Contains(ask, im.Image) {
			ask = append(ask, im.Image)
		}
	}
	if len(ask) == 0 {
		return u, nil
	}
	got, errs, err := src.PrivateDigests(ctx, ask)
	if err != nil {
		return u, err
	}
	out := u
	out.Images = slices.Clone(u.Images)
	for i, im := range out.Images {
		if im.Status != "unknown" {
			continue
		}
		if d, ok := got[im.Image]; ok {
			out.Images[i].Private, out.Images[i].Remote, out.Images[i].Note = true, d.Digest, privateNoteRead
			continue
		}
		e, ok := errs[im.Image]
		if !ok {
			continue
		}
		out.Images[i].Private, out.Images[i].Remote = true, ""
		switch {
		case errors.Is(e, registrymeta.ErrPrivateReadRefused):
			out.Images[i].Note = privateNoteRefused
		case errors.Is(e, registrymeta.ErrPrivateReadRateLimited):
			out.Images[i].Note = privateNoteRateLimited
		case errors.Is(e, registrymeta.ErrOutOfScope):
			out.Images[i].Note = privateNoteOutScope
		default:
			out.Images[i].Note = privateNoteFailed
		}
	}
	return out, nil
}
