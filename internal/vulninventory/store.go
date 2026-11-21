// SPDX-License-Identifier: AGPL-3.0-or-later

package vulninventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Limits. Every one is enforced by Put (or by the read path that decodes what
// Put wrote); an input over a limit is rejected with ErrLimit or
// ErrInvalidRead, never cut short.
const (
	// MaxBinaries bounds the binary packages of one read (ADR 0011 D3:
	// osdebian.MaxPackages, 20,000 packages per host).
	MaxBinaries = 20000
	// MaxComponentBinaries bounds the binaries of one component. It is the
	// export's limit (vulnfinding.MaxBinaries): the export drops a component
	// with more binaries, so Put refuses to store one.
	MaxComponentBinaries = vulnfinding.MaxBinaries
	// MaxComponents bounds the source packages of one read. A source package
	// has at least one binary in practice, so MaxBinaries also bounds it.
	MaxComponents = MaxBinaries
	// MaxDropped bounds Read.Dropped. The dpkg list parser accepts twice
	// MaxBinaries stanzas (osdebian.MaxCandidateStanzas = 2 * MaxPackages),
	// so a read cannot honestly report more dropped lines than that.
	MaxDropped = 2 * MaxBinaries
	// MaxReasonBytes bounds Read.Reason (why a read is partial or failed).
	MaxReasonBytes = 128
	// MaxReadSkew is how far after the store's clock a read time may be. A
	// read stamped further ahead would stay the newest read of its host, and
	// so protected, until the clock caught up. Put refuses such a read.
	MaxReadSkew = 5 * time.Minute

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
	// derived from the field limits above. Package names, versions and
	// architectures are restricted to the export's ASCII patterns (see
	// namePattern etc.), so no byte of a field is escaped by json.Marshal
	// (escaping would grow a byte to six). The worst case of one encoded
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
	// The body column CHECK in migration 0052 repeats this number.
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
	// Dropped counts the package lines the read could not use, at most MaxDropped.
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

// Patterns of the export (internal/web/api/vuln_export.go: exportPackageRe,
// exportVersionRe, exportArchRe). Package names and versions are ASCII, so a
// valid field has no byte that json.Marshal escapes.
var (
	namePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{1,127}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+~:_-]{0,127}$`)
	archPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// checkPattern rejects a value that does not match re. An empty value is
// rejected only when required; otherwise it is allowed. The value itself is
// not echoed: it comes from a managed host and may be hostile.
func checkPattern(field, v string, re *regexp.Regexp, required bool) error {
	if v == "" {
		if required {
			return fmt.Errorf("%w: %s is empty", ErrInvalidRead, field)
		}
		return nil
	}
	if !re.MatchString(v) {
		return fmt.Errorf("%w: %s does not match the export pattern", ErrInvalidRead, field)
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

// checkBodyCount rejects a count over its limit.
func checkBodyCount(what string, n, limit int) error {
	if n > limit {
		return fmt.Errorf("%w: %d %s, limit %d", ErrLimit, n, what, limit)
	}
	return nil
}

// canonicalComponents validates comps and returns them in canonical order
// (sorted by source, then source version; binaries by name, version and
// arch) together with the number of binaries. Two components with the same
// source and source version, and two identical binaries in one component,
// are rejected: the canonical order must be total for the body to be
// canonical. comps is not modified.
func canonicalComponents(comps []Component) ([]bodyComponent, int, error) {
	if err := checkBodyCount("components", len(comps), MaxComponents); err != nil {
		return nil, 0, err
	}
	binaries := 0
	out := make([]bodyComponent, 0, len(comps))
	seen := make(map[[2]string]bool, len(comps))
	for _, c := range comps {
		if err := checkPattern("component source", c.Source, namePattern, true); err != nil {
			return nil, 0, err
		}
		if err := checkPattern("component source version", c.SourceVersion, versionPattern, true); err != nil {
			return nil, 0, err
		}
		key := [2]string{c.Source, c.SourceVersion}
		if seen[key] {
			return nil, 0, fmt.Errorf("%w: duplicate component %s", ErrInvalidRead, c.Source)
		}
		seen[key] = true
		if err := checkBodyCount("binaries in one component", len(c.Binaries), MaxComponentBinaries); err != nil {
			return nil, 0, err
		}
		binaries += len(c.Binaries)
		if err := checkBodyCount("binaries", binaries, MaxBinaries); err != nil {
			return nil, 0, err
		}
		bs := make([]bodyBinary, 0, len(c.Binaries))
		for _, b := range c.Binaries {
			if err := checkPattern("binary name", b.Name, namePattern, true); err != nil {
				return nil, 0, err
			}
			if err := checkPattern("binary version", b.Version, versionPattern, true); err != nil {
				return nil, 0, err
			}
			if err := checkPattern("binary arch", b.Arch, archPattern, false); err != nil {
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
		for i := 1; i < len(bs); i++ {
			if bs[i] == bs[i-1] {
				return nil, 0, fmt.Errorf("%w: duplicate binary %s in component %s", ErrInvalidRead, bs[i].Name, c.Source)
			}
		}
		out = append(out, bodyComponent{Source: c.Source, SourceVersion: c.SourceVersion, Binaries: bs})
	}
	sort.Slice(out, func(x, y int) bool {
		if out[x].Source != out[y].Source {
			return out[x].Source < out[y].Source
		}
		return out[x].SourceVersion < out[y].SourceVersion
	})
	return out, binaries, nil
}

// encodeBody returns the canonical JSON of comps and the number of binaries.
// It validates comps and checks the body size.
func encodeBody(comps []Component) ([]byte, int, error) {
	canon, binaries, err := canonicalComponents(comps)
	if err != nil {
		return nil, 0, err
	}
	body, err := json.Marshal(canon)
	if err != nil {
		return nil, 0, fmt.Errorf("vulninventory: encode body: %w", err)
	}
	if err := checkBodySize(len(body)); err != nil {
		return nil, 0, err
	}
	return body, binaries, nil
}

// decodeBody parses a stored body and checks it as Put would have: size,
// field patterns, uniqueness and canonical bytes. A body that does not
// re-encode to itself was not written by Put.
func decodeBody(body []byte) ([]Component, error) {
	if err := checkBodySize(len(body)); err != nil {
		return nil, err
	}
	var bc []bodyComponent
	if err := json.Unmarshal(body, &bc); err != nil {
		return nil, fmt.Errorf("vulninventory: decode body: %w", err)
	}
	comps := make([]Component, 0, len(bc))
	for _, c := range bc {
		bs := make([]Binary, 0, len(c.Binaries))
		for _, b := range c.Binaries {
			bs = append(bs, Binary(b))
		}
		comps = append(comps, Component{Source: c.Source, SourceVersion: c.SourceVersion, Binaries: bs})
	}
	again, _, err := encodeBody(comps)
	if err != nil {
		return nil, fmt.Errorf("vulninventory: decode body: %w", err)
	}
	if string(again) != string(body) {
		return nil, fmt.Errorf("vulninventory: decode body: body is not canonical")
	}
	return comps, nil
}

// validateRead checks the header fields of r. Components are checked by
// encodeBody.
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
	if limit := nowFunc().Add(MaxReadSkew); r.ReadAt.After(limit) {
		return fmt.Errorf("%w: read time is more than %s after the store clock", ErrInvalidRead, MaxReadSkew)
	}
	if err := checkText("reason", r.Reason, MaxReasonBytes, false); err != nil {
		return err
	}
	if r.Dropped < 0 {
		return fmt.Errorf("%w: dropped is negative", ErrInvalidRead)
	}
	if err := checkBodyCount("dropped lines", r.Dropped, MaxDropped); err != nil {
		return err
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
	body, binaries, err := encodeBody(r.Components)
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
// (withBody true). A body is decoded and checked with decodeBody.
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
		comps, err := decodeBody(body)
		if err != nil {
			return Read{}, fmt.Errorf("read %d: %w", r.ID, err)
		}
		r.Components = comps
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

// Read-path statements. The plan tests run these same strings, so an index
// that the store relies on is checked where it is used.
const (
	// latestQuery is the newest read of one host (param: host ID). It seeks
	// vuln_inventory_reads_host_read and reads one entry.
	latestQuery = `SELECT ` + fullColumns + ` FROM vuln_inventory_reads
		WHERE host_id = ? ORDER BY read_at DESC, id DESC LIMIT 1`
	// lastCompleteQuery is the newest complete read of one host (param: host
	// ID). It seeks vuln_inventory_reads_host_complete.
	lastCompleteQuery = `SELECT ` + fullColumns + ` FROM vuln_inventory_reads
		WHERE host_id = ? AND complete = 1 ORDER BY read_at DESC, id DESC LIMIT 1`
	// latestAllQuery is the newest read of every host, without components.
	// The host list is taken once (one scan of the host_id index, grouped);
	// each host then costs one index seek for its newest read. There is no
	// sort of the table and no correlated sort per row.
	latestAllQuery = `SELECT ` + headerColumns + ` FROM vuln_inventory_reads
		WHERE id IN (SELECT (SELECT n.id FROM vuln_inventory_reads AS n WHERE n.host_id = h.host_id
			ORDER BY n.read_at DESC, n.id DESC LIMIT 1)
			FROM (SELECT host_id FROM vuln_inventory_reads GROUP BY host_id) AS h)`
)

// Latest returns the newest read of host: the highest read_at, then the
// highest id. It returns ErrNoRead when the host has no read.
func (s *Store) Latest(ctx context.Context, host string) (Read, error) {
	if err := checkText("host id", host, maxHostIDBytes, true); err != nil {
		return Read{}, fmt.Errorf("vulninventory: latest: %w", err)
	}
	return s.one(ctx, "latest "+host, latestQuery, host)
}

// LastComplete returns the newest complete read of host (D5: the basis of a
// closure when the latest read is partial). It returns ErrNoRead when the host
// has no complete read.
func (s *Store) LastComplete(ctx context.Context, host string) (Read, error) {
	if err := checkText("host id", host, maxHostIDBytes, true); err != nil {
		return Read{}, fmt.Errorf("vulninventory: last complete: %w", err)
	}
	return s.one(ctx, "last complete "+host, lastCompleteQuery, host)
}

// Get returns the read with the given ID, or ErrNoRead.
func (s *Store) Get(ctx context.Context, id int64) (Read, error) {
	return s.one(ctx, fmt.Sprintf("get %d", id), `SELECT `+fullColumns+` FROM vuln_inventory_reads WHERE id = ?`, id)
}

// LatestAll returns the newest read of every host, ordered by host ID, without
// the components. It is for the export's choice of reads and for the UI.
func (s *Store) LatestAll(ctx context.Context) ([]Read, error) {
	rows, err := s.db.QueryContext(ctx, latestAllQuery)
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
	// One row per host, so sorting the few result rows in Go is cheap and keeps
	// the SQL free of a sort.
	sort.Slice(out, func(i, j int) bool { return out[i].HostID < out[j].HostID })
	return out, nil
}

// The delete rule of migration 0052 (vuln_inventory_reads_protected) runs once per
// row of a DELETE. Its comment there says the check sees the rows as they were
// before the statement. That is wrong, and 0052 is not edited for it: SQLite
// runs the BEFORE trigger for each row after the earlier rows of the same
// statement are gone, so the check sees those deletions. The rule still holds.
// Deleting an unprotected row never changes which read is the newest, the last
// complete one or a pinned one, and a protected row aborts the whole statement,
// which rolls the earlier deletions back (store_test.go checks this).
//
// Retention of reads is decision E1 in docs/implementation/vuln-inventory-decisions.md
// and is not decided. The database (migration 0052) already refuses to delete a
// snapshot-pinned read, the newest read of a host and the last complete read of
// a host. This package deletes no reads and has no Prune.
