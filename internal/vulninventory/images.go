// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// Image inventory (ADR 0011 D3, image.packages; decision E4). An image read
// is the package list of one local container image, pinned to one platform
// digest, as image.packages reports it. The store keeps the last
// ImageReadsKept reads of each image (the digest, per host) and deletes the
// older ones in the same transaction as an insert (migration 0053), except
// the reads a snapshot pins (migration 0056); PruneSnapshots deletes those
// once no snapshot pins them. The
// repository of a read is a name the host's inspect result gave the image;
// it is not part of the key, so one image under several names shares one
// budget.
const (
	// ImageReadsKept is how many reads of one image on one host the store
	// keeps: the newest ones by read time (decision E4, "je Image"). Hosts
	// never share this budget.
	ImageReadsKept = 3
	// MaxImagePackages bounds the packages of one image read (ADR 0011 D3:
	// 5,000 packages per image). It equals dockerhost.MaxImagePackages.
	MaxImagePackages = 5000

	maxRepositoryBytes     = 255
	maxImageEcosystemBytes = 64
	maxImageNameBytes      = 128
	maxImageVersionBytes   = 128
	maxImageSourceBytes    = 128
	maxImageSourceVerBytes = 128
	maxImageOSFamilyBytes  = 64
	maxImageOSNameBytes    = 128

	// maxImagePackageJSONBytes is the worst case of one encoded package,
	// with its separator: every field at its byte limit, and no byte escaped
	// by json.Marshal (the patterns below are ASCII without quotes or
	// backslashes). Encoded: {"ecosystem":"<64>","name":"<128>",
	// "version":"<128>","source":"<128>","source_version":"<128>"} is 647
	// bytes, plus one separator.
	maxImagePackageJSONBytes = 648
	// MaxImageBodyBytes bounds the stored image body: MaxImagePackages
	// packages at their worst encoded size, plus the "[]" envelope
	// (3,240,002 bytes). The body CHECK in migration 0053 repeats this number.
	MaxImageBodyBytes = MaxImagePackages*maxImagePackageJSONBytes + 2
)

// Patterns for the image package fields. The package name and version
// patterns are those of the host export's ASCII rules; the ecosystem is the
// Trivy result type ("debian", "gobinary", ...).
var (
	imageRepositoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}$`)
	imageDigestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	imageEcosystemPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	imageNamePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,127}$`)
)

// ImagePackage is one installed package of an image: its Trivy ecosystem,
// name and version, and its source package (empty when Trivy reports none).
type ImagePackage struct {
	Ecosystem     string
	Name          string
	Version       string
	Source        string
	SourceVersion string
}

// ImageRead is one image.packages read: the packages of the image at
// Repository@Digest as read on Host by one execution. It holds no address,
// host name, label, secret or log.
type ImageRead struct {
	// ID is set by the reads of the store; PutImage ignores it.
	ID          int64
	Repository  string
	Digest      string
	HostID      string
	ExecutionID string
	ReadAt      time.Time
	Complete    bool
	Reason      string
	OSFamily    string
	OSName      string
	Packages    []ImagePackage
}

// imageBodyPackage is the canonical JSON encoding of one package. Field order
// is fixed, so two equal reads encode to the same bytes.
type imageBodyPackage struct {
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
}

// checkImagePackage validates one package against the field limits and
// patterns. Source and source version may be empty (Trivy reports none).
func checkImagePackage(p ImagePackage) error {
	if err := checkPattern("image package ecosystem", p.Ecosystem, imageEcosystemPattern, true); err != nil {
		return err
	}
	if err := checkPattern("image package name", p.Name, imageNamePattern, true); err != nil {
		return err
	}
	if err := checkPattern("image package version", p.Version, versionPattern, true); err != nil {
		return err
	}
	if err := checkPattern("image package source", p.Source, imageNamePattern, false); err != nil {
		return err
	}
	if p.Source == "" && p.SourceVersion != "" {
		return fmt.Errorf("%w: image package source version without a source", ErrInvalidRead)
	}
	return checkPattern("image package source version", p.SourceVersion, versionPattern, false)
}

// encodeImageBody validates pkgs, sorts them canonically and returns the
// canonical JSON and the package count. pkgs is not modified.
func encodeImageBody(pkgs []ImagePackage) ([]byte, error) {
	if err := checkBodyCount("image packages", len(pkgs), MaxImagePackages); err != nil {
		return nil, err
	}
	canon := make([]imageBodyPackage, 0, len(pkgs))
	for _, p := range pkgs {
		if err := checkImagePackage(p); err != nil {
			return nil, err
		}
		canon = append(canon, imageBodyPackage(p))
	}
	sort.Slice(canon, func(i, j int) bool {
		a, b := canon[i], canon[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.SourceVersion < b.SourceVersion
	})
	body, err := json.Marshal(canon)
	if err != nil {
		return nil, fmt.Errorf("vulninventory: encode image body: %w", err)
	}
	if len(body) > MaxImageBodyBytes {
		return nil, fmt.Errorf("%w: image body is %d bytes, limit %d", ErrLimit, len(body), MaxImageBodyBytes)
	}
	return body, nil
}

// decodeImageBody parses a stored image body and checks it as encodeImageBody
// would have: size, field patterns and canonical bytes.
func decodeImageBody(body []byte) ([]ImagePackage, error) {
	if len(body) > MaxImageBodyBytes {
		return nil, fmt.Errorf("%w: image body is %d bytes, limit %d", ErrLimit, len(body), MaxImageBodyBytes)
	}
	var canon []imageBodyPackage
	if err := json.Unmarshal(body, &canon); err != nil {
		return nil, fmt.Errorf("vulninventory: decode image body: %w", err)
	}
	pkgs := make([]ImagePackage, 0, len(canon))
	for _, p := range canon {
		pkgs = append(pkgs, ImagePackage(p))
	}
	again, err := encodeImageBody(pkgs)
	if err != nil {
		return nil, fmt.Errorf("vulninventory: decode image body: %w", err)
	}
	if string(again) != string(body) {
		return nil, fmt.Errorf("vulninventory: decode image body: body is not canonical")
	}
	return pkgs, nil
}

// validateImageRead checks the header fields of r. The packages are checked by
// encodeImageBody.
func validateImageRead(r ImageRead, now time.Time) error {
	if err := checkPattern("repository", r.Repository, imageRepositoryPattern, true); err != nil {
		return err
	}
	if !imageDigestPattern.MatchString(r.Digest) {
		return fmt.Errorf("%w: digest is not a sha256 digest", ErrInvalidRead)
	}
	if err := checkText("host id", r.HostID, maxHostIDBytes, true); err != nil {
		return err
	}
	if err := checkText("execution id", r.ExecutionID, maxExecutionIDBytes, true); err != nil {
		return err
	}
	if r.ReadAt.IsZero() || r.ReadAt.Unix() <= 0 {
		return fmt.Errorf("%w: read time is unset", ErrInvalidRead)
	}
	if limit := now.Add(MaxReadSkew); r.ReadAt.After(limit) {
		return fmt.Errorf("%w: read time is more than %s after the store clock", ErrInvalidRead, MaxReadSkew)
	}
	if err := checkText("reason", r.Reason, MaxReasonBytes, false); err != nil {
		return err
	}
	if err := checkText("os family", r.OSFamily, maxImageOSFamilyBytes, false); err != nil {
		return err
	}
	return checkText("os name", r.OSName, maxImageOSNameBytes, false)
}

// ErrDuplicateRead is returned by PutImage when a read of the same execution on
// the same host is already stored (migration 0054): the replay writes nothing,
// runs no retention and has no row ID.
var ErrDuplicateRead = errors.New("vulninventory: image read already stored for this execution")

// ErrDiscardedByRetention is returned by PutImage when the new read is older
// than the ImageReadsKept newest reads of its host and digest: it was written
// and deleted by the retention of the same transaction, so it has no row ID.
var ErrDiscardedByRetention = errors.New("vulninventory: image read discarded by retention")

// PutImage validates r, inserts it as a new immutable image read and then
// keeps only the ImageReadsKept newest reads of its host and digest (the
// repository is not part of the key), in one transaction. A read that a
// snapshot pins is kept even beyond that count, so a digest can have more than
// ImageReadsKept reads stored until PruneSnapshots removes the snapshot that
// pins them. It returns the new
// row ID. When retention deletes the new read itself, it returns 0 and
// ErrDiscardedByRetention; the retention still commits. A read of an execution
// that is stored already on the host returns ErrDuplicateRead and writes and
// deletes nothing. A rejected read writes nothing and deletes nothing.
func (s *Store) PutImage(ctx context.Context, r ImageRead) (int64, error) {
	if err := validateImageRead(r, s.now()); err != nil {
		return 0, fmt.Errorf("vulninventory: put image: %w", err)
	}
	body, err := encodeImageBody(r.Packages)
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put image: %w", err)
	}
	complete := 0
	if r.Complete {
		complete = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put image: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `INSERT INTO vuln_image_reads (repository, digest, host_id, execution_id, read_at,
		complete, reason, os_family, os_name, packages, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id, execution_id) DO NOTHING`,
		r.Repository, r.Digest, r.HostID, r.ExecutionID, r.ReadAt.UTC().Unix(), complete, r.Reason,
		r.OSFamily, r.OSName, len(r.Packages), body)
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put image: insert: %w", err)
	}
	// A replay of an execution that is stored already changes no row. It
	// returns before the retention, so it cannot push out a kept read.
	inserted, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put image: rows: %w", err)
	}
	if inserted == 0 {
		return 0, ErrDuplicateRead
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put image: row id: %w", err)
	}
	// A read that a snapshot pins stays (ADR 0011 amendment 2026-11-23); the
	// RESTRICT foreign key of migration 0056 would refuse its delete anyway.
	if _, err := tx.ExecContext(ctx, `DELETE FROM vuln_image_reads WHERE host_id = ? AND digest = ? AND id NOT IN (
		SELECT id FROM vuln_image_reads WHERE host_id = ? AND digest = ? ORDER BY read_at DESC, id DESC LIMIT ?)
		AND id NOT IN (SELECT image_read_id FROM vuln_inventory_snapshot_image_reads)`,
		r.HostID, r.Digest, r.HostID, r.Digest, ImageReadsKept); err != nil {
		return 0, fmt.Errorf("vulninventory: put image: keep newest: %w", err)
	}
	var kept int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM vuln_image_reads WHERE id = ?`, id).Scan(&kept); err != nil {
		return 0, fmt.Errorf("vulninventory: put image: check kept: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("vulninventory: put image: commit: %w", err)
	}
	if kept == 0 {
		return 0, ErrDiscardedByRetention
	}
	return id, nil
}

// ImageReads returns the kept reads of the image with digest on host, newest
// first (by read time, then ID), with their packages. It returns at most
// ImageReadsKept reads; an unknown image has none.
func (s *Store) ImageReads(ctx context.Context, hostID, digest string) ([]ImageRead, error) {
	if err := checkText("host id", hostID, maxHostIDBytes, true); err != nil {
		return nil, fmt.Errorf("vulninventory: image reads: %w", err)
	}
	if !imageDigestPattern.MatchString(digest) {
		return nil, fmt.Errorf("vulninventory: image reads: %w: digest is not a sha256 digest", ErrInvalidRead)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, repository, digest, host_id, execution_id, read_at, complete,
		reason, os_family, os_name, body FROM vuln_image_reads WHERE host_id = ? AND digest = ?
		ORDER BY read_at DESC, id DESC LIMIT ?`, hostID, digest, ImageReadsKept)
	if err != nil {
		return nil, fmt.Errorf("vulninventory: image reads: %w", err)
	}
	defer rows.Close()
	var out []ImageRead
	for rows.Next() {
		var r ImageRead
		var readAt int64
		var complete int
		var body []byte
		if err := rows.Scan(&r.ID, &r.Repository, &r.Digest, &r.HostID, &r.ExecutionID, &readAt, &complete,
			&r.Reason, &r.OSFamily, &r.OSName, &body); err != nil {
			return nil, fmt.Errorf("vulninventory: image reads: %w", err)
		}
		r.ReadAt = time.Unix(readAt, 0).UTC()
		r.Complete = complete == 1
		pkgs, err := decodeImageBody(body)
		if err != nil {
			return nil, fmt.Errorf("vulninventory: image read %d: %w", r.ID, err)
		}
		r.Packages = pkgs
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulninventory: image reads: %w", err)
	}
	return out, nil
}
