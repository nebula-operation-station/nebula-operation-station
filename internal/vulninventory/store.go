// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"
)

// Limits. Every one is enforced by Put (or by the read path that decodes what
// Put wrote); an input over a limit is rejected with ErrLimit or
// ErrInvalidRead, never cut short.
const (
	// MaxBinaries bounds the binary packages of one read (ADR 0011 D3:
	// osdebian.MaxPackages, 20,000 packages per host).
	MaxBinaries = 20000
	// MaxComponents bounds the source packages of one read. A source package
	// has at least one binary in practice, so MaxBinaries also bounds it.
	MaxComponents = MaxBinaries
	// MaxReasonBytes bounds Read.Reason (why a read is partial or failed).
	MaxReasonBytes = 128

	maxHostIDBytes        = 128
	maxExecutionIDBytes   = 64
	maxEcosystemBytes     = 64
	maxKernelReleaseBytes = 128
	maxKernelStateBytes   = 32
	maxKernelSourceBytes  = 64
	maxKernelVersionBytes = 256
	// maxNameBytes and maxVersionBytes match the package name and version
	// patterns of the export (internal/web/api/vuln_export.go: 2 to 128
	// characters, ASCII only, so bytes equal characters there).
	maxNameBytes    = 128
	maxVersionBytes = 128
	// maxArchBytes matches the export's architecture pattern (32 bytes).
	maxArchBytes = 32

	// The body is the canonical JSON of the components. Its size bound is
	// derived from the field limits above; the worst case of one encoded
	// binary is
	//   {"name":"<128>","version":"<128>","arch":"<32>"}  = 322 bytes
	// plus one separator, 323. One encoded component without its binaries is
	//   {"source":"<128>","source_version":"<128>","binaries":[]}  = 303 bytes
	// plus one separator, 304. The envelope is "[]", 2 bytes.
	maxBinaryJSONBytes    = 323
	maxComponentJSONBytes = 304
	maxBodyEnvelopeBytes  = 2
	// MaxBodyBytes bounds the stored body: MaxComponents components and
	// MaxBinaries binaries at their maximum encoded size (12,540,002 bytes).
	MaxBodyBytes = MaxComponents*maxComponentJSONBytes + MaxBinaries*maxBinaryJSONBytes + maxBodyEnvelopeBytes
)

var (
	// ErrNoRead is returned when the host (or read ID) has no matching read.
	ErrNoRead = errors.New("vulninventory: no read")
	// ErrInvalidRead is returned for input that fails a format check: empty
	// required fields, invalid UTF-8, a zero read time, a negative count.
	ErrInvalidRead = errors.New("vulninventory: invalid read")
	// ErrLimit is returned for input over a size or count limit.
	ErrLimit = errors.New("vulninventory: limit exceeded")
)

// Kernel is the running kernel as NOS mapped it for one read (ADR 0011 D3:
// `uname -r` release and `uname -v` build string).
type Kernel struct {
	Release string
	State   string
	Source  string
	Version string
}

// Binary is one installed binary package of a source package.
type Binary struct {
	Name    string
	Version string
	Arch    string
}

// Component is one installed source package and its binary packages.
type Component struct {
	Source        string
	SourceVersion string
	Binaries      []Binary
}

// Read is one NOS read of a host's installed source packages. It holds no
// address, host name, label, secret or log (ADR 0011 D3).
type Read struct {
	// ID is set by Get, Latest, LastComplete and LatestAll; Put ignores it.
	ID          int64
	HostID      string
	ExecutionID string
	ReadAt      time.Time
	// Complete is the D3 completeness flag.
	Complete bool
	// Reason says why the read is partial or failed, at most MaxReasonBytes.
	Reason string
	// Dropped counts the package lines the read could not use.
	Dropped    int
	Ecosystem  string
	Kernel     Kernel
	Components []Component
}

// Store reads and writes inventory reads in server.db.
type Store struct {
	db *sql.DB
}

// New returns a Store on db, which must hold the migrated server schema.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("vulninventory: new: nil database")
	}
	return &Store{db: db}, nil
}

// bodyComponent and bodyBinary are the canonical JSON encoding of the
// components. Field order and names are fixed here, so two equal reads
// always encode to the same bytes.
type bodyComponent struct {
	Source        string       `json:"source"`
	SourceVersion string       `json:"source_version"`
	Binaries      []bodyBinary `json:"binaries"`
}

type bodyBinary struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// checkText rejects a field that is empty (when required), longer than max
// bytes, or not valid UTF-8.
func checkText(field, v string, max int, required bool) error {
	if required && v == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidRead, field)
	}
	if len(v) > max {
		return fmt.Errorf("%w: %s is %d bytes, limit %d", ErrInvalidRead, field, len(v), max)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidRead, field)
	}
	return nil
}

// checkBodySize rejects a body longer than MaxBodyBytes.
func checkBodySize(n int) error {
	if n > MaxBodyBytes {
		return fmt.Errorf("%w: body is %d bytes, limit %d", ErrLimit, n, MaxBodyBytes)
	}
	return nil
}

// canonicalBody validates the components of r and returns their canonical
// JSON (sorted by source, then source version; binaries by name, version and
// arch) and the number of binaries. It does not modify comps.
func canonicalBody(comps []Component) ([]byte, int, error) {
	if len(comps) > MaxComponents {
		return nil, 0, fmt.Errorf("%w: %d components, limit %d", ErrLimit, len(comps), MaxComponents)
	}
	binaries := 0
	out := make([]bodyComponent, 0, len(comps))
	for i, c := range comps {
		if err := checkText("component source", c.Source, maxNameBytes, true); err != nil {
			return nil, 0, err
		}
		if err := checkText("component source version", c.SourceVersion, maxVersionBytes, true); err != nil {
			return nil, 0, err
		}
		binaries += len(c.Binaries)
		if binaries > MaxBinaries {
			return nil, 0, fmt.Errorf("%w: more than %d binaries (component %d)", ErrLimit, MaxBinaries, i)
		}
		bs := make([]bodyBinary, 0, len(c.Binaries))
		for _, b := range c.Binaries {
			if err := checkText("binary name", b.Name, maxNameBytes, true); err != nil {
				return nil, 0, err
			}
			if err := checkText("binary version", b.Version, maxVersionBytes, true); err != nil {
				return nil, 0, err
			}
			if err := checkText("binary arch", b.Arch, maxArchBytes, false); err != nil {
				return nil, 0, err
			}
			bs = append(bs, bodyBinary(b))
		}
		sort.Slice(bs, func(x, y int) bool {
			if bs[x].Name != bs[y].Name {
				return bs[x].Name < bs[y].Name
			}
			if bs[x].Version != bs[y].Version {
				return bs[x].Version < bs[y].Version
			}
			return bs[x].Arch < bs[y].Arch
		})
		out = append(out, bodyComponent{Source: c.Source, SourceVersion: c.SourceVersion, Binaries: bs})
	}
	sort.SliceStable(out, func(x, y int) bool {
		if out[x].Source != out[y].Source {
			return out[x].Source < out[y].Source
		}
		return out[x].SourceVersion < out[y].SourceVersion
	})
	body, err := json.Marshal(out)
	if err != nil {
		return nil, 0, fmt.Errorf("vulninventory: encode body: %w", err)
	}
	if err := checkBodySize(len(body)); err != nil {
		return nil, 0, err
	}
	return body, binaries, nil
}

// validateRead checks the header fields of r. Components are checked by
// canonicalBody.
func validateRead(r Read) error {
	if err := checkText("host id", r.HostID, maxHostIDBytes, true); err != nil {
		return err
	}
	if err := checkText("execution id", r.ExecutionID, maxExecutionIDBytes, true); err != nil {
		return err
	}
	if r.ReadAt.IsZero() || r.ReadAt.Unix() <= 0 {
		return fmt.Errorf("%w: read time is unset", ErrInvalidRead)
	}
	if err := checkText("reason", r.Reason, MaxReasonBytes, false); err != nil {
		return err
	}
	if r.Dropped < 0 {
		return fmt.Errorf("%w: dropped is negative", ErrInvalidRead)
	}
	if err := checkText("ecosystem", r.Ecosystem, maxEcosystemBytes, false); err != nil {
		return err
	}
	if err := checkText("kernel release", r.Kernel.Release, maxKernelReleaseBytes, false); err != nil {
		return err
	}
	if err := checkText("kernel state", r.Kernel.State, maxKernelStateBytes, false); err != nil {
		return err
	}
	if err := checkText("kernel source", r.Kernel.Source, maxKernelSourceBytes, false); err != nil {
		return err
	}
	return checkText("kernel version", r.Kernel.Version, maxKernelVersionBytes, false)
}

// Put validates r and inserts it as a new immutable read. It returns the new
// row ID. A read over a limit or with an invalid field is rejected and nothing
// is written.
func (s *Store) Put(ctx context.Context, r Read) (int64, error) {
	if err := validateRead(r); err != nil {
		return 0, fmt.Errorf("vulninventory: put: %w", err)
	}
	body, binaries, err := canonicalBody(r.Components)
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put: %w", err)
	}
	complete := 0
	if r.Complete {
		complete = 1
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO vuln_inventory_reads (host_id, execution_id, read_at, complete, reason,
		dropped, ecosystem, kernel_release, kernel_state, kernel_source, kernel_version, binaries, sources, body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.HostID, r.ExecutionID, r.ReadAt.UTC().Unix(), complete, r.Reason, r.Dropped, r.Ecosystem,
		r.Kernel.Release, r.Kernel.State, r.Kernel.Source, r.Kernel.Version, binaries, len(r.Components), body)
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("vulninventory: put: row id: %w", err)
	}
	return id, nil
}

// readColumns are the columns of a read without its body; headerColumns add
// the body.
const (
	headerColumns = `id, host_id, execution_id, read_at, complete, reason, dropped, ecosystem,
		kernel_release, kernel_state, kernel_source, kernel_version`
	fullColumns = headerColumns + `, body`
)

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanRead reads one row of headerColumns (withBody false) or fullColumns
// (withBody true).
func scanRead(sc rowScanner, withBody bool) (Read, error) {
	var r Read
	var readAt int64
	var complete int
	var body []byte
	dest := []any{&r.ID, &r.HostID, &r.ExecutionID, &readAt, &complete, &r.Reason, &r.Dropped, &r.Ecosystem,
		&r.Kernel.Release, &r.Kernel.State, &r.Kernel.Source, &r.Kernel.Version}
	if withBody {
		dest = append(dest, &body)
	}
	if err := sc.Scan(dest...); err != nil {
		return Read{}, err
	}
	r.ReadAt = time.Unix(readAt, 0).UTC()
	r.Complete = complete == 1
	if withBody {
		var bc []bodyComponent
		if err := json.Unmarshal(body, &bc); err != nil {
			return Read{}, fmt.Errorf("vulninventory: decode body of read %d: %w", r.ID, err)
		}
		r.Components = make([]Component, 0, len(bc))
		for _, c := range bc {
			bs := make([]Binary, 0, len(c.Binaries))
			for _, b := range c.Binaries {
				bs = append(bs, Binary(b))
			}
			r.Components = append(r.Components, Component{Source: c.Source, SourceVersion: c.SourceVersion, Binaries: bs})
		}
	}
	return r, nil
}

// one returns the single read matching query (with args), or ErrNoRead.
func (s *Store) one(ctx context.Context, what, query string, args ...any) (Read, error) {
	r, err := scanRead(s.db.QueryRowContext(ctx, query, args...), true)
	if errors.Is(err, sql.ErrNoRows) {
		return Read{}, fmt.Errorf("vulninventory: %s: %w", what, ErrNoRead)
	}
	if err != nil {
		return Read{}, fmt.Errorf("vulninventory: %s: %w", what, err)
	}
	return r, nil
}

// Latest returns the newest read of host: the highest read_at, then the
// highest id. It returns ErrNoRead when the host has no read.
func (s *Store) Latest(ctx context.Context, host string) (Read, error) {
	if err := checkText("host id", host, maxHostIDBytes, true); err != nil {
		return Read{}, fmt.Errorf("vulninventory: latest: %w", err)
	}
	return s.one(ctx, "latest "+host, `SELECT `+fullColumns+` FROM vuln_inventory_reads
		WHERE host_id = ? ORDER BY read_at DESC, id DESC LIMIT 1`, host)
}

// LastComplete returns the newest complete read of host (D5: the basis of a
// closure when the latest read is partial). It returns ErrNoRead when the host
// has no complete read.
func (s *Store) LastComplete(ctx context.Context, host string) (Read, error) {
	if err := checkText("host id", host, maxHostIDBytes, true); err != nil {
		return Read{}, fmt.Errorf("vulninventory: last complete: %w", err)
	}
	return s.one(ctx, "last complete "+host, `SELECT `+fullColumns+` FROM vuln_inventory_reads
		WHERE host_id = ? AND complete = 1 ORDER BY read_at DESC, id DESC LIMIT 1`, host)
}

// Get returns the read with the given ID, or ErrNoRead.
func (s *Store) Get(ctx context.Context, id int64) (Read, error) {
	return s.one(ctx, fmt.Sprintf("get %d", id), `SELECT `+fullColumns+` FROM vuln_inventory_reads WHERE id = ?`, id)
}

// LatestAll returns the newest read of every host, ordered by host ID, without
// the components. It is for the export's choice of reads and for the UI.
func (s *Store) LatestAll(ctx context.Context) ([]Read, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+headerColumns+` FROM vuln_inventory_reads AS r
		WHERE r.id = (SELECT n.id FROM vuln_inventory_reads AS n WHERE n.host_id = r.host_id
			ORDER BY n.read_at DESC, n.id DESC LIMIT 1)
		ORDER BY r.host_id`)
	if err != nil {
		return nil, fmt.Errorf("vulninventory: latest all: %w", err)
	}
	defer rows.Close()
	var out []Read
	for rows.Next() {
		r, err := scanRead(rows, false)
		if err != nil {
			return nil, fmt.Errorf("vulninventory: latest all: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulninventory: latest all: %w", err)
	}
	return out, nil
}

// Prune deletes the reads no closure or snapshot still needs and returns how
// many it deleted. For a host with keepHosts[host] true it keeps the newest
// read, the last complete read and every read a snapshot points at. For any
// other host (absent, or false) it keeps only the reads a snapshot points at,
// so such a host's newest and last complete reads go too once no snapshot
// refers to them. The whole prune runs in one transaction.
func (s *Store) Prune(ctx context.Context, keepHosts map[string]bool) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("vulninventory: prune: begin: %w", err)
	}
	defer tx.Rollback()

	hosts, err := distinctHosts(ctx, tx)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, host := range hosts {
		n, err := pruneHost(ctx, tx, host, keepHosts[host])
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("vulninventory: prune: commit: %w", err)
	}
	return deleted, nil
}

// pruneHost deletes the unneeded reads of one host inside tx and returns how
// many rows it deleted. keep selects the rule (see Prune).
func pruneHost(ctx context.Context, tx *sql.Tx, host string, keep bool) (int, error) {
	const notSnapshotted = `NOT EXISTS (SELECT 1 FROM vuln_inventory_snapshot_reads AS s WHERE s.read_id = vuln_inventory_reads.id)`
	var res sql.Result
	var err error
	if keep {
		var latest int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM vuln_inventory_reads WHERE host_id = ?
			ORDER BY read_at DESC, id DESC LIMIT 1`, host).Scan(&latest); err != nil {
			return 0, fmt.Errorf("vulninventory: prune: latest %s: %w", host, err)
		}
		// A host with no complete read has NULL here; IS NOT (not <>) then
		// excludes nothing, so the newest read is still the only one kept.
		var lastComplete sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM vuln_inventory_reads WHERE host_id = ? AND complete = 1
			ORDER BY read_at DESC, id DESC LIMIT 1`, host).Scan(&lastComplete); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("vulninventory: prune: last complete %s: %w", host, err)
		}
		res, err = tx.ExecContext(ctx, `DELETE FROM vuln_inventory_reads WHERE host_id = ?
			AND id IS NOT ? AND id IS NOT ? AND `+notSnapshotted, host, latest, lastComplete)
	} else {
		res, err = tx.ExecContext(ctx, `DELETE FROM vuln_inventory_reads WHERE host_id = ? AND `+notSnapshotted, host)
	}
	if err != nil {
		return 0, fmt.Errorf("vulninventory: prune %s: %w", host, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("vulninventory: prune %s: %w", host, err)
	}
	return int(n), nil
}

// distinctHosts returns every host ID that has at least one read, in order.
func distinctHosts(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT host_id FROM vuln_inventory_reads ORDER BY host_id`)
	if err != nil {
		return nil, fmt.Errorf("vulninventory: prune: hosts: %w", err)
	}
	defer rows.Close()
	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("vulninventory: prune: hosts: %w", err)
		}
		hosts = append(hosts, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulninventory: prune: hosts: %w", err)
	}
	return hosts, nil
}
