// SPDX-License-Identifier: AGPL-3.0-or-later

package fimstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// Table names of the two entry tables. Both have the same columns; the
// names are constants, never input.
const (
	proposalEntries  = "fim_baseline_proposal_entries"
	proposalMounts   = "fim_baseline_proposal_mounts"
	approvedMounts   = "fim_baseline_mounts"
	entryColumns     = "host_id, path, type, size, mode, uid, gid, inode, mtime, ctime, hash_kind, hash_secret, hash_sum, link"
	entryReadColumns = "path, type, size, mode, uid, gid, inode, mtime, ctime, hash_kind, hash_secret, hash_sum, link"
	entryPlaceholder = "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?"
)

// copyEntriesSQL copies the proposal entries of one host to the approved
// entries inside the database, so the record list never passes through
// memory. It takes the host ID once.
const copyEntriesSQL = `INSERT INTO fim_baseline_entries (` + entryColumns + `)
	SELECT ` + entryColumns + ` FROM fim_baseline_proposal_entries WHERE host_id = ?`

// copyMountsSQL copies the proposal mounts of one host to the approved mounts.
// It takes the host ID once.
const copyMountsSQL = `INSERT INTO fim_baseline_mounts (host_id, path, fstype)
	SELECT host_id, path, fstype FROM fim_baseline_proposal_mounts WHERE host_id = ?`

// insertMounts writes the mount entries of host into table. It returns the
// number of rows written.
func insertMounts(ctx context.Context, tx *sql.Tx, table string, host HostID, ms []fimscan.Mount) (int64, error) {
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO `+table+` (host_id, path, fstype) VALUES (?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("prepare mounts: %w", err)
	}
	defer stmt.Close()
	for i := range ms {
		if _, err := stmt.ExecContext(ctx, host, ms[i].Path, ms[i].FSType); err != nil {
			return 0, fmt.Errorf("write mount %d: %w", i, err)
		}
	}
	return int64(len(ms)), nil
}

// readMounts returns the mount entries of host in table, sorted by raw path
// bytes. The strings and byte slices it returns are owned by the caller.
func readMounts(ctx context.Context, q queryer, table string, host HostID) ([]fimscan.Mount, error) {
	rows, err := q.QueryContext(ctx, `SELECT path, fstype FROM `+table+` WHERE host_id = ? ORDER BY path`, host)
	if err != nil {
		return nil, fmt.Errorf("query mounts: %w", err)
	}
	defer rows.Close()
	var out []fimscan.Mount
	for rows.Next() {
		var m fimscan.Mount
		if err := rows.Scan(&m.Path, &m.FSType); err != nil {
			return nil, fmt.Errorf("scan mount: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read mounts: %w", err)
	}
	return out, nil
}

// readEntries returns every entry of host in table, sorted by raw path bytes.
// It reads the whole list into memory; callers hold it only for one check.
func readEntries(ctx context.Context, q queryer, table string, host HostID) ([]fimscan.Record, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+entryReadColumns+` FROM `+table+` WHERE host_id = ? ORDER BY path`, host)
	if err != nil {
		return nil, fmt.Errorf("query entries: %w", err)
	}
	defer rows.Close()
	var out []fimscan.Record
	for rows.Next() {
		rec, err := scanEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("read entries: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read entries: %w", err)
	}
	return out, nil
}

// insertEntries writes entries, already sorted by raw path bytes, into table
// for host. It returns the number of rows written.
func insertEntries(ctx context.Context, tx *sql.Tx, table string, host HostID, entries []fimscan.Record) (int64, error) {
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO `+table+` (`+entryColumns+`) VALUES (`+entryPlaceholder+`)`)
	if err != nil {
		return 0, fmt.Errorf("prepare entries: %w", err)
	}
	defer stmt.Close()
	for i := range entries {
		e := &entries[i]
		var (
			sum  any
			link any
			sec  int64
		)
		if e.Hash.Kind != fimscan.HashNone {
			sum = e.Hash.Sum[:]
		}
		if e.Hash.Secret {
			sec = 1
		}
		if e.Link != nil {
			link = e.Link
		}
		if _, err := stmt.ExecContext(ctx, host, e.Path, int64(e.Type), e.Size, int64(e.Mode),
			int64(e.UID), int64(e.GID), int64(e.Inode), e.Mtime, e.Ctime,
			int64(e.Hash.Kind), sec, sum, link); err != nil {
			return 0, fmt.Errorf("write entry %d: %w", i, err)
		}
	}
	return int64(len(entries)), nil
}

// scanEntry reads the current row of an entry query into a record. The
// columns are those of the stream query in ForEachApproved.
func scanEntry(rows *sql.Rows) (fimscan.Record, error) {
	var (
		r                                  fimscan.Record
		typ, size, mode, uid, gid, inode   int64
		mtime, ctime, hashKind, hashSecret int64
		hashSum, link                      []byte
	)
	if err := rows.Scan(&r.Path, &typ, &size, &mode, &uid, &gid, &inode, &mtime, &ctime,
		&hashKind, &hashSecret, &hashSum, &link); err != nil {
		return fimscan.Record{}, fmt.Errorf("scan entry: %w", err)
	}
	r.Type = fimscan.Type(typ)
	r.Size = size
	r.Mode = uint32(mode)
	r.UID = uint32(uid)
	r.GID = uint32(gid)
	r.Inode = uint64(inode)
	r.Mtime = mtime
	r.Ctime = ctime
	r.Hash.Kind = fimscan.HashKind(hashKind)
	r.Hash.Secret = hashSecret == 1
	if r.Hash.Kind != fimscan.HashNone {
		if err := copyDigest((*fimbaseline.Digest)(&r.Hash.Sum), hashSum); err != nil {
			return fimscan.Record{}, fmt.Errorf("scan entry hash: %w", err)
		}
	}
	if link != nil {
		r.Link = link
	}
	return r, nil
}
