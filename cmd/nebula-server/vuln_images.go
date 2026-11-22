// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// inspectActionID is the action whose stored results name the image digests
// a host runs (docker.inspect, one result per container). A digest is only
// read when a stored inspect result of the host names it (decision E4a; see
// vulnImageService.ObserveImage).
const inspectActionID = "docker.inspect"

// imageActionID is the action whose execution is the read grant of an image
// read (ADR 0011 D3). Its one parameter, image, is the pinned reference.
const imageActionID = "image.packages"

const (
	// ImageInspectMaxAge is how old a stored docker.inspect result may be and
	// still name an image for a read. An inspect of a container removed long
	// ago does not authorise reads of its image any more.
	ImageInspectMaxAge = 24 * time.Hour
	// maxInspectRows bounds the stored inspect results scanned for one read:
	// the newest ones of the host in the ImageInspectMaxAge window.
	maxInspectRows = 500
	// maxInspectResultBytes bounds one stored inspect result the lookup
	// parses. It is the attached-run result limit, so no stored result is
	// larger; a larger row is never read into memory.
	maxInspectResultBytes = hostrun.MaxResult
)

// imageInspectRow is one stored successful docker.inspect result of a host
// and the time it finished.
type imageInspectRow struct {
	Result     []byte
	FinishedAt time.Time
}

// sqlInspects reads the stored docker.inspect results from server.db. It reads
// the executions tables directly: the executions service keeps only the
// newest result per host, which names one container, not every container
// the host runs.
type sqlInspects struct {
	db *sql.DB
}

// InspectResults calls fn for each stored successful docker.inspect result of
// host that finished at or after since, newest first, at most limit of them,
// skipping any result larger than maxInspectResultBytes. Rows are scanned one
// at a time, so at most one result is held in memory; fn returns true to stop
// early. Only a result the database returns is passed to fn.
func (q sqlInspects) InspectResults(ctx context.Context, host string, since time.Time, limit int, fn func(imageInspectRow) bool) error {
	rows, err := q.db.QueryContext(ctx, `SELECT h.result, h.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id
		WHERE e.action_id = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success'
		AND h.finished_at >= ? AND length(h.result) <= ? ORDER BY h.finished_at DESC, e.id DESC LIMIT ?`,
		inspectActionID, host, since.Unix(), maxInspectResultBytes, limit)
	if err != nil {
		return fmt.Errorf("inspect results: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row imageInspectRow
		var at sql.NullInt64
		if err := rows.Scan(&row.Result, &at); err != nil {
			return fmt.Errorf("inspect results: %w", err)
		}
		row.FinishedAt = time.Unix(at.Int64, 0).UTC()
		if fn(row) {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect results: %w", err)
	}
	return nil
}

// imageDigestRe is a sha256 platform digest, as image.packages pins it.
var imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// vulnImageService stores each successful image.packages result as an image
// read (decision E4: the store keeps the last three reads of each image on
// each host). It never starts a read and never fails a run; errors are logged
// by class only, never with package names or result text.
type vulnImageService struct {
	db       *sql.DB
	store    *vulninventory.Store
	inspects sqlInspects
	now      func() time.Time
	log      *slog.Logger
}

// newVulnImageService returns the service on db (server.db). The grants and
// the stored docker.inspect results that name the digests are read from the
// same db.
func newVulnImageService(db *sql.DB, log *slog.Logger) (*vulnImageService, error) {
	st, err := vulninventory.New(db)
	if err != nil {
		return nil, fmt.Errorf("image inventory store: %w", err)
	}
	return &vulnImageService{db: db, store: st, inspects: sqlInspects{db: db}, now: time.Now, log: log}, nil
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

// inspectNames reports whether one parsed docker.inspect result names the
// image repo@digest. A repository digest must be repo@digest exactly. The
// platform digest carries no repository, so it names repo@digest only when
// repo is one of the repositories the image's repository digests give.
func inspectNames(in dockerhost.Inspect, repo, digest string) bool {
	repos := map[string]bool{}
	for _, d := range in.Digests {
		r, dg, ok := splitImageRef(d)
		if !ok {
			continue
		}
		if r == repo && dg == digest {
			return true
		}
		repos[r] = true
	}
	return in.ImageDigestPlatform == digest && repos[repo]
}

// namedByInspect reports whether any of the host's stored docker.inspect
// results from the last ImageInspectMaxAge names repo@digest. The results of
// every container of the host count, not only the newest one. An absent or
// unreadable result names nothing.
func (v *vulnImageService) namedByInspect(ctx context.Context, host, repo, digest string) (bool, error) {
	since := v.now().Add(-ImageInspectMaxAge)
	named := false
	err := v.inspects.InspectResults(ctx, host, since, maxInspectRows, func(row imageInspectRow) bool {
		if row.FinishedAt.Before(since) {
			return false
		}
		in, err := dockerhost.ParseInspect(row.Result)
		if err != nil {
			return false
		}
		named = inspectNames(in, repo, digest)
		return named
	})
	if err != nil {
		return false, fmt.Errorf("inspect lookup: %w", err)
	}
	return named, nil
}

// imageGrant is the read grant of one image read: the reference the
// image.packages execution pinned and the time the host finished it.
type imageGrant struct {
	Ref        string
	FinishedAt time.Time
}

// grantedImage loads the grant of execID on host from the stored execution.
// ok is false when there is no successful image.packages run of execID on
// host, or its parameters do not carry exactly one image reference (a run
// started by a lease or a schedule stores no image parameter, so its reads are
// refused). Nothing the host returned is read here.
func grantedImage(ctx context.Context, db *sql.DB, host, execID string) (g imageGrant, ok bool, err error) {
	var action, params string
	var at sql.NullInt64
	err = db.QueryRowContext(ctx, `SELECT e.action_id, e.params, h.finished_at FROM executions e
		JOIN execution_hosts h ON h.execution_id = e.id
		WHERE e.id = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success'`,
		execID, host).Scan(&action, &params, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return imageGrant{}, false, nil
	}
	if err != nil {
		return imageGrant{}, false, fmt.Errorf("grant lookup: %w", err)
	}
	if action != imageActionID || !at.Valid {
		return imageGrant{}, false, nil
	}
	var p map[string]string
	if json.Unmarshal([]byte(params), &p) != nil || len(p) != 1 {
		return imageGrant{}, false, nil
	}
	ref, ok := p["image"]
	if !ok {
		return imageGrant{}, false, nil
	}
	return imageGrant{Ref: ref, FinishedAt: time.Unix(at.Int64, 0).UTC()}, true, nil
}

// ObserveImage parses result (untrusted host output of image.packages on host
// in execution execID) and stores the read. The image and the read time come
// from the stored execution, not from the caller: the read is stored only when
// execID is a successful image.packages run of host whose stored parameter
// names the image (its read grant, ADR 0011 D3), and when a docker.inspect
// result of host from the last ImageInspectMaxAge names the repository and
// digest of that image. Anything else is refused and nothing is stored. An
// unknown read (no package listing) is not stored: it has no packages and
// would push out a kept read. A read the store refuses is logged by class and
// not stored; a read that retention discards at once is logged as
// discarded_by_retention.
//
// ObserveImage starts no read. It only reads what the executions already
// stored.
//
// NOT WIRED: nothing in the server calls ObserveImage yet. Wiring must pass
// the execution's ID and the result only; the grant is read from server.db.
func (v *vulnImageService) ObserveImage(parent context.Context, hostID, execID string, result []byte) {
	ctx, cancel := context.WithTimeout(parent, observeTimeout)
	defer cancel()
	grant, granted, err := grantedImage(ctx, v.db, hostID, execID)
	if err != nil {
		v.log.Error("vulnerability image inventory: grant lookup", "host", hostID, "execution", execID, "error_class", inventoryErrorClass(err))
		return
	}
	if !granted {
		v.log.Info("audit", "kind", "vuln_image_read_refused", "host", hostID, "execution", execID, "reason", "not_granted")
		return
	}
	imageRef := grant.Ref
	repo, digest, ok := splitImageRef(imageRef)
	if !ok {
		v.log.Error("vulnerability image inventory: image ref", "host", hostID, "execution", execID, "error_class", "image_ref")
		return
	}
	named, err := v.namedByInspect(ctx, hostID, repo, digest)
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
		ReadAt:      grant.FinishedAt,
		Complete:    ip.Complete,
		Reason:      ip.Reason,
		OSFamily:    ip.OS.Family,
		OSName:      ip.OS.Name,
		Packages:    imagePackages(ip.Packages),
	}
	_, err = v.store.PutImage(ctx, read)
	if errors.Is(err, vulninventory.ErrDiscardedByRetention) {
		v.log.Info("audit", "kind", "vuln_image_read_discarded", "host", hostID, "execution", execID,
			"reason", "discarded_by_retention")
		return
	}
	if err != nil {
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
