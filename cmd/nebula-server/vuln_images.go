// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// inspectActionID is the action whose stored result names the image digests
// a host runs (docker.inspect). A digest is only read when the host's stored
// inspect result names it (decision E4a; see vulnImageService.ObserveImage).
const inspectActionID = "docker.inspect"

// imageLastResults is the part of executions.Service the image inventory
// reads from: the stored latest result of an action on a host.
type imageLastResults interface {
	LastResult(ctx context.Context, actionID, host string) ([]byte, time.Time, bool, error)
}

// imageDigestRe is a sha256 platform digest, as image.packages pins it.
var imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// vulnImageService stores each successful image.packages result as an image
// read (decision E4: the store keeps the last three reads of each image
// repository). It never starts a read and never fails a run; errors are logged
// by class only, never with package names or result text.
type vulnImageService struct {
	store   *vulninventory.Store
	results imageLastResults
	log     *slog.Logger
}

// newVulnImageService returns the service on db (server.db). results supplies
// the stored docker.inspect results that name the digests.
func newVulnImageService(db *sql.DB, results imageLastResults, log *slog.Logger) (*vulnImageService, error) {
	st, err := vulninventory.New(db)
	if err != nil {
		return nil, fmt.Errorf("image inventory store: %w", err)
	}
	return &vulnImageService{store: st, results: results, log: log}, nil
}

// splitImageRef splits a digest-pinned reference (repository@sha256:...) into
// its repository and digest. ok is false for any other form.
func splitImageRef(ref string) (repo, digest string, ok bool) {
	i := strings.LastIndex(ref, "@")
	if i <= 0 {
		return "", "", false
	}
	repo, digest = ref[:i], ref[i+1:]
	if !imageDigestRe.MatchString(digest) {
		return "", "", false
	}
	return repo, digest, true
}

// digestInInspect reports whether the stored docker.inspect result of host
// names digest: as the platform digest of a local image, or as a repository
// digest ending in it. An absent or unreadable inspect result names nothing.
func (v *vulnImageService) digestInInspect(ctx context.Context, host, digest string) (bool, error) {
	raw, _, ok, err := v.results.LastResult(ctx, inspectActionID, host)
	if err != nil {
		return false, fmt.Errorf("inspect lookup: %w", err)
	}
	if !ok {
		return false, nil
	}
	in, err := dockerhost.ParseInspect(raw)
	if err != nil {
		return false, nil
	}
	if in.ImageDigestPlatform == digest {
		return true, nil
	}
	for _, d := range in.Digests {
		if strings.HasSuffix(d, "@"+digest) {
			return true, nil
		}
	}
	return false, nil
}

// ObserveImage parses result (untrusted host output of image.packages for
// imageRef, a repository@sha256 reference) and stores the read of host from
// execution execID at time at. The digest must be named by host's stored
// docker.inspect result; a digest the host's stored results do not name is
// refused and nothing is stored. An unknown read (no package listing) is not
// stored: it has no packages and would push out a kept read. A read the store
// refuses is logged by class and not stored.
//
// ObserveImage starts no read. It only reads what the executions already
// stored, and is called for successful image.packages runs, which only a read
// grant can start (ADR 0011 D3; the grant pins one digest per entry).
func (v *vulnImageService) ObserveImage(parent context.Context, hostID, execID, imageRef string, at time.Time, result []byte) {
	repo, digest, ok := splitImageRef(imageRef)
	if !ok {
		v.log.Error("vulnerability image inventory: image ref", "host", hostID, "execution", execID, "error_class", "image_ref")
		return
	}
	ctx, cancel := context.WithTimeout(parent, observeTimeout)
	defer cancel()
	named, err := v.digestInInspect(ctx, hostID, digest)
	if err != nil {
		v.log.Error("vulnerability image inventory: inspect lookup", "host", hostID, "execution", execID, "error_class", inventoryErrorClass(err))
		return
	}
	if !named {
		v.log.Info("audit", "kind", "vuln_image_read_refused", "host", hostID, "execution", execID, "reason", "digest_not_in_inspect")
		return
	}
	ip, err := actions.ParseImagePackagesResult(imageRef, result)
	if err != nil {
		v.log.Error("vulnerability image inventory: parse", "host", hostID, "execution", execID, "error_class", "parse")
		return
	}
	if !ip.Known {
		v.log.Info("audit", "kind", "vuln_image_read_unknown", "host", hostID, "execution", execID, "reason", ip.Reason)
		return
	}
	read := vulninventory.ImageRead{
		Repository:  repo,
		Digest:      digest,
		HostID:      hostID,
		ExecutionID: execID,
		ReadAt:      at,
		Complete:    ip.Complete,
		Reason:      ip.Reason,
		OSFamily:    ip.OS.Family,
		OSName:      ip.OS.Name,
		Packages:    imagePackages(ip.Packages),
	}
	if _, err := v.store.PutImage(ctx, read); err != nil {
		class := inventoryErrorClass(err)
		v.log.Error("vulnerability image inventory: store read", "host", hostID, "execution", execID, "error_class", class)
		return
	}
	v.log.Info("audit", "kind", "vuln_image_read_stored", "host", hostID, "execution", execID,
		"complete", ip.Complete, "packages", len(ip.Packages))
}

// imagePackages maps the parsed Trivy packages to the stored form.
func imagePackages(in []dockerhost.ImagePackage) []vulninventory.ImagePackage {
	out := make([]vulninventory.ImagePackage, 0, len(in))
	for _, p := range in {
		out = append(out, vulninventory.ImagePackage{
			Ecosystem:     p.Ecosystem,
			Name:          p.Name,
			Version:       p.Version,
			Source:        p.SrcName,
			SourceVersion: p.SrcVersion,
		})
	}
	return out
}

// errNoImageEcosystem is returned by imageEcosystem when the image's OS
// release cannot be named the way the export names ecosystems.
var errNoImageEcosystem = errors.New("image ecosystem unknown")

// imageEcosystem names the OS ecosystem of an image read the way the export
// does (vulninventory.Ecosystem for hosts). Trivy reports a Debian release
// by version ("12.5"), not by codename, so Debian images are not named here.
func imageEcosystem(osFamily, osName string) (string, error) {
	eco, _ := vulninventory.Ecosystem(osFamily, osName, "")
	if eco == "" {
		return "", errNoImageEcosystem
	}
	return eco, nil
}

// imageSubjects returns the export subjects of image reads (ADR 0011 D2, D3):
// one subject per host and platform digest, from the newest read of that
// pair. A read whose OS ecosystem cannot be named is not exported, and only
// the OS packages of the image (those of the image's OS family) are listed as
// components. Subject references carry the host ID and the digest, the same
// join the export uses for image subjects.
func imageSubjects(reads []vulninventory.ImageRead) []api.VulnSubject {
	newest := map[[2]string]vulninventory.ImageRead{}
	for _, r := range reads {
		k := [2]string{r.HostID, r.Digest}
		if cur, ok := newest[k]; !ok || newerImageRead(r, cur) {
			newest[k] = r
		}
	}
	keys := make([][2]string, 0, len(newest))
	for k := range newest {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	out := make([]api.VulnSubject, 0, len(keys))
	for _, k := range keys {
		if sub, ok := imageSubject(newest[k]); ok {
			out = append(out, sub)
		}
	}
	return out
}

// newerImageRead reports whether a is newer than b: the later read time, then
// the higher ID.
func newerImageRead(a, b vulninventory.ImageRead) bool {
	if !a.ReadAt.Equal(b.ReadAt) {
		return a.ReadAt.After(b.ReadAt)
	}
	return a.ID > b.ID
}

// imageSubject maps one image read to an export subject. ok is false when the
// read's ecosystem cannot be named (see imageEcosystem).
func imageSubject(r vulninventory.ImageRead) (api.VulnSubject, bool) {
	eco, err := imageEcosystem(r.OSFamily, r.OSName)
	if err != nil {
		return api.VulnSubject{}, false
	}
	type compKey struct{ source, version string }
	comps := map[compKey]*api.VulnComponent{}
	for _, p := range r.Packages {
		if p.Ecosystem != r.OSFamily {
			continue
		}
		src, srcVer := p.Source, p.SourceVersion
		if src == "" {
			src, srcVer = p.Name, p.Version
		}
		k := compKey{src, srcVer}
		c, ok := comps[k]
		if !ok {
			c = &api.VulnComponent{Source: src, SourceVersion: srcVer}
			comps[k] = c
		}
		c.Binaries = append(c.Binaries, api.VulnBinary{Name: p.Name, Version: p.Version})
	}
	list := make([]api.VulnComponent, 0, len(comps))
	for _, c := range comps {
		sort.Slice(c.Binaries, func(i, j int) bool {
			if c.Binaries[i].Name != c.Binaries[j].Name {
				return c.Binaries[i].Name < c.Binaries[j].Name
			}
			return c.Binaries[i].Version < c.Binaries[j].Version
		})
		list = append(list, *c)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Source != list[j].Source {
			return list[i].Source < list[j].Source
		}
		return list[i].SourceVersion < list[j].SourceVersion
	})
	return api.VulnSubject{
		Kind:       vulnfinding.SubjectImage,
		Ref:        vulnfinding.SubjectRef{ID: r.HostID, ImageDigest: r.Digest},
		Ecosystem:  eco,
		Complete:   r.Complete,
		Components: list,
	}, true
}
