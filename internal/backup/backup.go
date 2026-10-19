// SPDX-License-Identifier: AGPL-3.0-or-later

// Package backup writes and reads Nebula backup archives (spec 15, M10-2):
// a gzip-compressed tar holding manifest.json first and then the files,
// encrypted with age to the recipients chosen at setup. The manifest names
// the Nebula version, the schema versions and the SHA-256 of every file;
// reading checks all of it. A backup never holds the passphrase, the
// plaintext vault master key, a plaintext secret or the event key: the
// SSH keys and the vault stay encrypted with the passphrase.
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// Format of the manifest.
const Format = "nebula-backup-v1"

// Limits.
const (
	MaxFiles    = 128
	MaxFileSize = 512 << 20
	MaxTotal    = 2 << 30
	maxManifest = 1 << 20
)

// Paths inside the archive.
const (
	ServerDB   = "server/server.db"
	ExecutorDB = "executor/executor.db"
)

var pathRe = regexp.MustCompile(`^(server/server\.db|server/config/(server\.json|backup-recipients)|` +
	`server/systemd/nebula-(executor|server)\.service\.d/[0-9a-z][0-9a-z-]{0,40}\.conf|` +
	`executor/executor\.db|executor/keys/[a-z0-9][a-z0-9_-]{0,63}\.(key|pub))$`)

// ValidPath reports whether p is a path a backup may hold.
func ValidPath(p string) bool { return pathRe.MatchString(p) }

// File is one file of a backup.
type File struct {
	Path string
	Mode uint32
	Data []byte
}

// Entry is a file as the manifest lists it.
type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// Manifest describes a backup.
type Manifest struct {
	Format    string         `json:"format"`
	Version   string         `json:"nebula_version"`
	CreatedAt string         `json:"created_at"`
	Host      string         `json:"host"`
	Kind      string         `json:"kind"` // config or full
	Encrypted bool           `json:"encrypted"`
	Schemas   map[string]int `json:"schemas"` // server, executor
	Files     []Entry        `json:"files"`
}

// Errors.
var (
	ErrNotBackup = errors.New("backup: not a Nebula backup")
	ErrChecksum  = errors.New("backup: a file does not match its checksum")
	ErrEncrypted = errors.New("backup: the archive is encrypted; give the age identity")
)

// Write writes the archive: m (its Files are filled in) and files,
// encrypted to recipients (none: not encrypted).
func Write(w io.Writer, m Manifest, files []File, recipients []age.Recipient) error {
	if len(files) == 0 || len(files) > MaxFiles {
		return fmt.Errorf("backup: %d files (1 to %d)", len(files), MaxFiles)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	m.Format, m.Files, m.Encrypted = Format, nil, len(recipients) > 0
	var total int64
	seen := map[string]bool{}
	for _, f := range files {
		if !ValidPath(f.Path) || seen[f.Path] {
			return fmt.Errorf("backup: %q is not a backup path (or twice)", f.Path)
		}
		seen[f.Path] = true
		if int64(len(f.Data)) > MaxFileSize {
			return fmt.Errorf("backup: %s is too large", f.Path)
		}
		total += int64(len(f.Data))
		s := sha256.Sum256(f.Data)
		m.Files = append(m.Files, Entry{Path: f.Path, Size: int64(len(f.Data)), SHA256: hex.EncodeToString(s[:]), Mode: f.Mode & 0o777})
	}
	if total > MaxTotal {
		return errors.New("backup: the backup is too large")
	}
	return writeArchive(w, m, files, recipients)
}

// writeArchive writes m (as given) and files.
func writeArchive(w io.Writer, m Manifest, files []File, recipients []age.Recipient) error {
	man, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out := w
	var enc io.WriteCloser
	if len(recipients) > 0 {
		if enc, err = age.Encrypt(w, recipients...); err != nil {
			return fmt.Errorf("backup: encrypt: %w", err)
		}
		out = enc
	}
	zw := gzip.NewWriter(out)
	tw := tar.NewWriter(zw)
	mtime := time.Unix(0, 0)
	add := func(name string, mode uint32, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: int64(mode & 0o777), Size: int64(len(b)), Typeflag: tar.TypeReg, ModTime: mtime, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := add("manifest.json", 0o600, man); err != nil {
		return err
	}
	for _, f := range files {
		if err := add(f.Path, f.Mode, f.Data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if enc != nil {
		return enc.Close()
	}
	return nil
}

// ageHeader starts every age file.
var ageHeader = []byte("age-encryption.org/v1\n")

// Read reads and checks an archive: the manifest first, every file listed
// exactly once with its size and SHA-256, nothing else. identities decrypt
// an encrypted archive.
func Read(r io.Reader, identities []age.Identity) (Manifest, []File, error) {
	br := bufio.NewReader(r)
	head, _ := br.Peek(len(ageHeader))
	in := io.Reader(br)
	encrypted := bytes.Equal(head, ageHeader)
	if encrypted {
		if len(identities) == 0 {
			return Manifest{}, nil, ErrEncrypted
		}
		d, err := age.Decrypt(br, identities...)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("backup: decrypt: %w", err)
		}
		in = d
	}
	zr, err := gzip.NewReader(in)
	if err != nil {
		return Manifest{}, nil, ErrNotBackup
	}
	tr := tar.NewReader(io.LimitReader(zr, MaxTotal+maxManifest+int64(MaxFiles+1)*4096))
	h, err := tr.Next()
	if err != nil || h.Name != "manifest.json" || h.Typeflag != tar.TypeReg || h.Size > maxManifest {
		return Manifest{}, nil, ErrNotBackup
	}
	mb, err := io.ReadAll(io.LimitReader(tr, maxManifest))
	if err != nil {
		return Manifest{}, nil, ErrNotBackup
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(mb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || m.Format != Format || len(m.Files) == 0 || len(m.Files) > MaxFiles {
		return Manifest{}, nil, ErrNotBackup
	}
	if m.Encrypted != encrypted {
		return Manifest{}, nil, errors.New("backup: the manifest does not match how the archive is encrypted")
	}
	want := map[string]Entry{}
	for _, e := range m.Files {
		if !ValidPath(e.Path) || e.Size < 0 || e.Size > MaxFileSize {
			return Manifest{}, nil, fmt.Errorf("backup: the manifest lists %q", e.Path)
		}
		if _, dup := want[e.Path]; dup {
			return Manifest{}, nil, fmt.Errorf("backup: the manifest lists %q twice", e.Path)
		}
		want[e.Path] = e
	}
	var files []File
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("backup: the archive is damaged: %w", err)
		}
		e, ok := want[h.Name]
		if !ok || h.Typeflag != tar.TypeReg || h.Size != e.Size {
			return Manifest{}, nil, fmt.Errorf("backup: unexpected entry %q", h.Name)
		}
		delete(want, h.Name)
		b, err := io.ReadAll(io.LimitReader(tr, e.Size+1))
		if err != nil || int64(len(b)) != e.Size {
			return Manifest{}, nil, fmt.Errorf("backup: %s is truncated", h.Name)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != e.SHA256 {
			return Manifest{}, nil, fmt.Errorf("%w: %s", ErrChecksum, h.Name)
		}
		files = append(files, File{Path: h.Name, Mode: e.Mode, Data: b})
	}
	if len(want) > 0 {
		var missing []string
		for p := range want {
			missing = append(missing, p)
		}
		sort.Strings(missing)
		return Manifest{}, nil, fmt.Errorf("backup: missing %s", strings.Join(missing, ", "))
	}
	return m, files, nil
}

// ParseRecipients reads age recipients, one per line ("#" comments and
// empty lines ignored).
func ParseRecipients(b []byte) ([]age.Recipient, error) {
	rs, err := age.ParseRecipients(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("backup: recipients: %w", err)
	}
	return rs, nil
}

// ParseIdentities reads an age identity file.
func ParseIdentities(b []byte) ([]age.Identity, error) {
	ids, err := age.ParseIdentities(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("backup: identity: %w", err)
	}
	return ids, nil
}

// CheckSQLite opens a database file read-only, runs PRAGMA integrity_check
// and returns its schema version (the newest schema_migrations row).
func CheckSQLite(path string) (int, error) {
	if strings.ContainsAny(path, "?#") {
		return 0, errors.New("backup: path must not contain ? or #")
	}
	c, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	var res string
	if err := c.QueryRow(`PRAGMA integrity_check`).Scan(&res); err != nil {
		return 0, fmt.Errorf("backup: integrity check of %s: %w", path, err)
	}
	if res != "ok" {
		return 0, fmt.Errorf("backup: integrity check of %s failed: %s", path, res)
	}
	var v int
	if err := c.QueryRow(`SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&v); err != nil {
		return 0, fmt.Errorf("backup: schema version of %s: %w", path, err)
	}
	return v, nil
}

// SnapshotSQLite writes a consistent copy of a live database (WAL mode,
// another process writing) to dst with VACUUM INTO and checks the copy.
func SnapshotSQLite(src, dst string) (int, error) {
	if strings.ContainsAny(src, "?#") || strings.ContainsAny(dst, "?#") {
		return 0, errors.New("backup: path must not contain ? or #")
	}
	c, err := sql.Open("sqlite", "file:"+src+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if _, err := c.Exec(`VACUUM INTO ?`, dst); err != nil {
		return 0, fmt.Errorf("backup: snapshot of %s: %w", src, err)
	}
	return CheckSQLite(dst)
}
