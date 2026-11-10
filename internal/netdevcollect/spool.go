// SPDX-License-Identifier: AGPL-3.0-or-later

// Package netdevcollect is the network device collector's spool (ADR 0010
// D4, Q9; ticket ND-14). The collector writes one sanitized read result per
// file; nebula-server lists, takes and, after it has stored a result,
// confirms it, which removes the file.
//
// The spool follows internal/pvecollect/spool.go: the directory is reached
// through a symlink-free, descriptor-relative walk from /, files are
// published atomically (temp file, fsync, rename without replace in the
// same directory, directory fsync), names follow a strict grammar and are
// checked against the record on read-back, and every file is read through
// a no-follow, non-blocking, size-bounded open. The package has no network,
// database or secret access.
package netdevcollect

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"golang.org/x/sys/unix"
)

// Typed read names. They mirror the NetDeviceRead values of the executor
// API (ADR 0010 D4) and are the only reads the spool accepts.
const (
	// ReadCBSVersion is the CBS device facts read.
	ReadCBSVersion = "cbs_version"
	// ReadCBSVLANs is the CBS VLAN list read.
	ReadCBSVLANs = "cbs_vlans"
	// ReadCBSInterfaces is the CBS ports read.
	ReadCBSInterfaces = "cbs_interfaces"
	// ReadCBSMACTable is the CBS MAC address table read.
	ReadCBSMACTable = "cbs_mac_table"
	// ReadCBSLLDP is the CBS LLDP neighbors read.
	ReadCBSLLDP = "cbs_lldp"
	// ReadPANOSZones is the PAN-OS zones read.
	ReadPANOSZones = "panos_zones"
	// ReadPANOSObjects is the PAN-OS address and service objects read.
	ReadPANOSObjects = "panos_objects"
	// ReadPANOSSecurityRules is the PAN-OS security rules read.
	ReadPANOSSecurityRules = "panos_security_rules"
	// ReadPANOSNATRules is the PAN-OS NAT rules read.
	ReadPANOSNATRules = "panos_nat_rules"
	// ReadPANOSRuleHitCounts is the PAN-OS rule hit-count read.
	ReadPANOSRuleHitCounts = "panos_rule_hit_counts"
)

// readLimits is the closed set of reads with the byte limit of one read's
// payload: the ADR 0010 D3 transport cap of the command or response the
// read is parsed from.
var readLimits = map[string]int{
	ReadCBSVersion:         netdevcontract.MaxCBSCommandOutputBytes,
	ReadCBSVLANs:           netdevcontract.MaxCBSCommandOutputBytes,
	ReadCBSInterfaces:      netdevcontract.MaxCBSCommandOutputBytes,
	ReadCBSMACTable:        netdevcontract.MaxCBSCommandOutputBytes,
	ReadCBSLLDP:            netdevcontract.MaxCBSCommandOutputBytes,
	ReadPANOSZones:         netdevcontract.MaxPANOSResponseBytes,
	ReadPANOSObjects:       netdevcontract.MaxPANOSResponseBytes,
	ReadPANOSSecurityRules: netdevcontract.MaxPANOSResponseBytes,
	ReadPANOSNATRules:      netdevcontract.MaxPANOSResponseBytes,
	ReadPANOSRuleHitCounts: netdevcontract.MaxPANOSResponseBytes,
}

// ReadLimit returns the payload byte limit of a read and false for a name
// outside the closed set of reads.
func ReadLimit(read string) (int, bool) {
	n, ok := readLimits[read]
	return n, ok
}

const (
	// maxRecordOverhead bounds the record envelope around a payload: the
	// field names, a device_id, a read name, a trust generation and a
	// timestamp need far less.
	maxRecordOverhead = 4 << 10
	// spoolDirMode is the provisioned mode of the spool directory: the
	// collector owns it, the shared server group lists, reads and unlinks
	// entries, and setgid keeps the shared group on new files.
	spoolDirMode = os.FileMode(0o770) | os.ModeSetgid
	// spoolFileMode is the mode of every published spool file.
	spoolFileMode = 0o640
	// randomChars is the length of the random name part (crypto/rand.Text).
	randomChars = 26
	// tempPrefix starts every unpublished file; it never matches the
	// spool name grammar.
	tempPrefix = ".tmp-"
)

// Sentinel errors for spool operations.
var (
	// ErrSymlink means an operation refused a symbolic link.
	ErrSymlink = errors.New("netdevcollect: symlink refused")
	// ErrOversize means a payload or spool file exceeds its size limit.
	ErrOversize = errors.New("netdevcollect: over the size limit")
	// ErrBadName means a spool file name does not follow the grammar.
	ErrBadName = errors.New("netdevcollect: malformed spool file name")
	// ErrUnknownRead means a read name is outside the closed set.
	ErrUnknownRead = errors.New("netdevcollect: unknown read")
	// ErrInvalidRecord means a record is malformed, or a spool file itself
	// is at fault: not regular, a symlink, oversize, wrongly owned or with
	// the wrong mode, or its record does not match its name. Only such a
	// file may be discarded; other errors say nothing about the file.
	ErrInvalidRecord = errors.New("netdevcollect: invalid spool record")
	// ErrReplayed means a record was already confirmed, or is older than
	// the last confirmed record of its device and read.
	ErrReplayed = errors.New("netdevcollect: replayed spool record")
	// ErrExists means a spool name is already taken; nothing is replaced.
	ErrExists = errors.New("netdevcollect: spool file already exists")
	// ErrChanged means a spool entry was replaced between Take and Confirm.
	ErrChanged = errors.New("netdevcollect: spool file changed since it was taken")
	// ErrDirMode means the spool directory does not have its provisioned
	// mode.
	ErrDirMode = errors.New("netdevcollect: spool directory has the wrong mode")
	// ErrSpoolOwnership means the spool directory is not owned by the
	// collector UID and the shared server group.
	ErrSpoolOwnership = errors.New("netdevcollect: spool directory has foreign ownership")
)

// errNonRegular means an operation refused a file that is not regular.
var errNonRegular = errors.New("netdevcollect: nonregular spool file")

// spoolNameRe is the grammar <device>-<read>-<unix nanos>-<random>.json.
// Read names contain no hyphen or digit, so the split is unambiguous.
var spoolNameRe = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)-([a-z_]+)-([1-9][0-9]{0,18})-([A-Z2-7]{26})\.json$`)

// Record is one spooled read result.
type Record struct {
	DeviceID        string    `json:"device_id"`
	Read            string    `json:"read"`
	TrustGeneration uint64    `json:"trust_generation"`
	ObservedAt      time.Time `json:"observed_at"`
	// Incomplete marks a result whose list hit its limit (ADR 0010 D3).
	Incomplete bool `json:"incomplete"`
	// Data is the sanitized read result, a JSON object or array.
	Data json.RawMessage `json:"data"`
}

// Spool is the on-disk network device spool in Dir, an absolute path that
// install.sh provisions with mode 0770 plus setgid, the collector UID and
// the shared server group. Now supplies observation times and must be set
// for Write. A Spool is safe for concurrent use and must not be copied
// after first use; its replay watermarks live in memory.
type Spool struct {
	Dir string
	Now func() time.Time

	mu   sync.Mutex
	seen map[string]watermark
}

// watermark is the last confirmed observation of one device and read.
type watermark struct {
	nanos int64
	// names holds the confirmed names observed exactly at nanos.
	names map[string]struct{}
}

// spoolName is a parsed spool file name.
type spoolName struct {
	device string
	read   string
	nanos  int64
}

func (n spoolName) key() string { return n.device + "\x00" + n.read }

func formatSpoolName(device, read string, nanos int64, random string) string {
	return fmt.Sprintf("%s-%s-%d-%s.json", device, read, nanos, random)
}

func parseSpoolName(name string) (spoolName, error) {
	m := spoolNameRe.FindStringSubmatch(name)
	if m == nil || !netdevcontract.ValidDeviceID(m[1]) {
		return spoolName{}, ErrBadName
	}
	if _, ok := readLimits[m[2]]; !ok {
		return spoolName{}, ErrBadName
	}
	nanos, err := strconv.ParseInt(m[3], 10, 64)
	if err != nil {
		return spoolName{}, ErrBadName
	}
	if formatSpoolName(m[1], m[2], nanos, m[4]) != name {
		return spoolName{}, ErrBadName
	}
	return spoolName{device: m[1], read: m[2], nanos: nanos}, nil
}

// defaultRandomText is the source of the random name part.
func defaultRandomText() string { return rand.Text() }

// randomText returns the random name part. It is a variable so that tests
// can force a name collision.
var randomText = defaultRandomText

// beforeRename runs, when set, after a temp file is written and synced and
// before it is published. Tests use it to simulate a crash.
var beforeRename func(dir *os.File, tmpName string) error

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecord, fmt.Sprintf(format, args...))
}

// validatePayload checks a read payload: within the read's limit, valid
// UTF-8 and exactly one JSON object or array.
func validatePayload(payload []byte, limit int) error {
	if len(payload) > limit {
		return fmt.Errorf("%w: payload has %d bytes, limit %d", ErrOversize, len(payload), limit)
	}
	if !utf8.Valid(payload) {
		return invalid("payload is not valid UTF-8")
	}
	if !json.Valid(payload) {
		return invalid("payload is not one JSON value")
	}
	if t := bytes.TrimLeft(payload, " \t\r\n"); t[0] != '{' && t[0] != '[' {
		return invalid("payload is not a JSON object or array")
	}
	return nil
}

func validTrustGeneration(g uint64) bool {
	return g >= 1 && g <= netdevcontract.MaxTrustGeneration
}

// Write validates one read result and publishes it atomically as
// <device>-<read>-<unix nanos>-<random>.json, observed at s.Now(). It
// never replaces an existing file and returns the published name.
func (s *Spool) Write(ctx context.Context, deviceID, read string, trustGeneration uint64, incomplete bool, payload []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.Now == nil {
		return "", errors.New("netdevcollect: spool clock is not set")
	}
	if !netdevcontract.ValidDeviceID(deviceID) {
		return "", invalid("malformed device_id")
	}
	limit, ok := readLimits[read]
	if !ok {
		return "", ErrUnknownRead
	}
	if !validTrustGeneration(trustGeneration) {
		return "", invalid("trust generation out of range")
	}
	if err := validatePayload(payload, limit); err != nil {
		return "", fmt.Errorf("write %s %s: %w", deviceID, read, err)
	}
	observed := s.Now().UTC()
	nanos := observed.UnixNano()
	if nanos <= 0 || !time.Unix(0, nanos).Equal(observed) {
		return "", invalid("observation time out of range")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	rec := Record{DeviceID: deviceID, Read: read, TrustGeneration: trustGeneration, ObservedAt: observed, Incomplete: incomplete, Data: payload}
	if err := enc.Encode(rec); err != nil {
		return "", invalid("encode record: %v", err)
	}
	if buf.Len() > limit+maxRecordOverhead {
		return "", ErrOversize
	}
	name := formatSpoolName(deviceID, read, nanos, randomText())
	if _, err := parseSpoolName(name); err != nil {
		return "", fmt.Errorf("netdevcollect: generated name: %w", err)
	}
	dir, err := s.openDir(true)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if err := writeAt(dir, name, buf.Bytes()); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return "", fmt.Errorf("%w: %s", ErrExists, name)
		}
		return "", fmt.Errorf("netdevcollect: publish %s: %w", name, err)
	}
	return name, nil
}

// writeAt publishes a fully written, synced file relative to the pinned
// directory. The temp file never matches the name grammar, and the rename
// never replaces an existing entry.
func writeAt(dir *os.File, name string, raw []byte) error {
	tmpName := tempPrefix + randomText()
	fd, err := unix.Openat(int(dir.Fd()), tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, spoolFileMode)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmpName)
	defer f.Close()
	defer unix.Unlinkat(int(dir.Fd()), tmpName, 0)
	if _, err := f.Write(raw); err != nil {
		return err
	}
	if err := f.Chmod(spoolFileMode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if beforeRename != nil {
		if err := beforeRename(dir, tmpName); err != nil {
			return err
		}
	}
	if err := unix.Renameat2(int(dir.Fd()), tmpName, int(dir.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return dir.Sync()
}

// List returns the names of all well-named regular spool files ordered by
// observation time, then name. It refuses symbolic links and skips other
// entries, including unpublished temp files.
func (s *Spool) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, err := s.openDir(false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("netdevcollect: list spool: %w", err)
	}
	type item struct {
		name  string
		nanos int64
	}
	var items []item
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s", ErrSymlink, e.Name())
		}
		if !e.Type().IsRegular() {
			continue
		}
		if n, err := parseSpoolName(e.Name()); err == nil {
			items = append(items, item{name: e.Name(), nanos: n.nanos})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].nanos != items[j].nanos {
			return items[i].nanos < items[j].nanos
		}
		return items[i].name < items[j].name
	})
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.name
	}
	return names, nil
}

// Taken is a read, validated record whose file stays in the spool until
// Confirm.
type Taken struct {
	// Record is the validated record.
	Record Record

	spool    *Spool
	name     string
	parsed   spoolName
	limit    int64
	dev, ino uint64
	// digest is the SHA-256 of the file content Take validated; inode
	// numbers alone are reused after an unlink.
	digest [sha256.Size]byte
}

// Take reads and validates one named spool file without removing it. The
// record must match its file name and must not be a replay. Errors that
// condemn the file wrap ErrInvalidRecord; the caller may Discard it.
func (s *Spool) Take(ctx context.Context, name string) (*Taken, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := parseSpoolName(name)
	if err != nil {
		return nil, err
	}
	dir, err := s.openDir(false)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	limit := readLimits[parsed.read]
	raw, st, err := readAt(dir, name, int64(limit+maxRecordOverhead))
	if err != nil {
		if errors.Is(err, ErrSymlink) || errors.Is(err, ErrOversize) || errors.Is(err, errNonRegular) {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidRecord, name, err)
		}
		return nil, fmt.Errorf("netdevcollect: read %s: %w", name, err)
	}
	var dirSt unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &dirSt); err != nil {
		return nil, fmt.Errorf("netdevcollect: stat spool: %w", err)
	}
	if st.Uid != dirSt.Uid {
		return nil, invalid("%s is owned by uid %d, the spool by %d", name, st.Uid, dirSt.Uid)
	}
	if st.Mode&0o7777 != spoolFileMode {
		return nil, invalid("%s has mode %#o, want %#o", name, st.Mode&0o7777, spoolFileMode)
	}
	rec, err := decodeRecord(raw, limit)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if rec.DeviceID != parsed.device || rec.Read != parsed.read || rec.ObservedAt.UnixNano() != parsed.nanos {
		return nil, invalid("%s: record does not match the file name", name)
	}
	if err := s.checkReplay(parsed, name); err != nil {
		return nil, err
	}
	return &Taken{Record: rec, spool: s, name: name, parsed: parsed, limit: int64(limit + maxRecordOverhead),
		dev: uint64(st.Dev), ino: st.Ino, digest: sha256.Sum256(raw)}, nil
}

// Confirm removes the taken file after the caller has stored its record
// and advances the replay watermark. It refuses an entry that was replaced
// or rewritten since Take (same inode and same content required).
func (t *Taken) Confirm(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := t.spool.openDir(false)
	if err != nil {
		return err
	}
	defer dir.Close()
	raw, st, err := readAt(dir, t.name, t.limit)
	if errors.Is(err, ErrSymlink) || errors.Is(err, ErrOversize) || errors.Is(err, errNonRegular) {
		return fmt.Errorf("%w: %s: %w", ErrChanged, t.name, err)
	}
	if err != nil {
		return fmt.Errorf("netdevcollect: confirm %s: %w", t.name, err)
	}
	if uint64(st.Dev) != t.dev || st.Ino != t.ino || sha256.Sum256(raw) != t.digest {
		return fmt.Errorf("%w: %s", ErrChanged, t.name)
	}
	if err := unix.Unlinkat(int(dir.Fd()), t.name, 0); err != nil {
		return fmt.Errorf("netdevcollect: confirm %s: %w", t.name, err)
	}
	t.spool.markConfirmed(t.parsed, t.name)
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("netdevcollect: confirm %s: sync spool: %w", t.name, err)
	}
	return nil
}

// Discard removes a well-named regular spool file, typically one Take
// condemned with ErrInvalidRecord or ErrReplayed. Unlink never follows a
// final symlink; symbolic links are refused.
func (s *Spool) Discard(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := parseSpoolName(name); err != nil {
		return err
	}
	dir, err := s.openDir(false)
	if err != nil {
		return err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("netdevcollect: discard %s: %w", name, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return fmt.Errorf("%w: %s", ErrSymlink, name)
	case unix.S_IFREG:
	default:
		return fmt.Errorf("%w: %s", errNonRegular, name)
	}
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil {
		return fmt.Errorf("netdevcollect: discard %s: %w", name, err)
	}
	return dir.Sync()
}

func (s *Spool) checkReplay(n spoolName, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.seen[n.key()]
	if !ok {
		return nil
	}
	if n.nanos < w.nanos {
		return fmt.Errorf("%w: %s is older than the last confirmed record", ErrReplayed, name)
	}
	if _, dup := w.names[name]; dup && n.nanos == w.nanos {
		return fmt.Errorf("%w: %s was already confirmed", ErrReplayed, name)
	}
	return nil
}

func (s *Spool) markConfirmed(n spoolName, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = make(map[string]watermark)
	}
	w, ok := s.seen[n.key()]
	switch {
	case !ok || n.nanos > w.nanos:
		s.seen[n.key()] = watermark{nanos: n.nanos, names: map[string]struct{}{name: {}}}
	case n.nanos == w.nanos:
		w.names[name] = struct{}{}
	}
}

// decodeRecord strictly decodes a record: one JSON object with exactly the
// six record fields, no duplicates, no nulls, no trailing data.
func decodeRecord(raw []byte, limit int) (Record, error) {
	var rec Record
	if !utf8.Valid(raw) {
		return rec, invalid("record is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return rec, invalid("record is not a JSON object")
	}
	fields := map[string]any{
		"device_id":        &rec.DeviceID,
		"read":             &rec.Read,
		"trust_generation": &rec.TrustGeneration,
		"observed_at":      &rec.ObservedAt,
		"incomplete":       &rec.Incomplete,
		"data":             &rec.Data,
	}
	seen := make(map[string]bool, len(fields))
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return rec, invalid("record key: %v", err)
		}
		key, _ := tok.(string)
		dst, known := fields[key]
		if !known {
			return rec, invalid("unknown record field")
		}
		if seen[key] {
			return rec, invalid("duplicate record field %s", key)
		}
		seen[key] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return rec, invalid("record field %s: %v", key, err)
		}
		if string(v) == "null" {
			return rec, invalid("record field %s is null", key)
		}
		if err := json.Unmarshal(v, dst); err != nil {
			return rec, invalid("record field %s: %v", key, err)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return rec, invalid("record object is not closed")
	}
	if _, err := dec.Token(); err != io.EOF {
		return rec, invalid("trailing data after the record")
	}
	if len(seen) != len(fields) {
		return rec, invalid("record field missing")
	}
	if !netdevcontract.ValidDeviceID(rec.DeviceID) {
		return rec, invalid("malformed device_id")
	}
	if _, ok := readLimits[rec.Read]; !ok {
		return rec, invalid("unknown read")
	}
	if !validTrustGeneration(rec.TrustGeneration) {
		return rec, invalid("trust generation out of range")
	}
	if err := validatePayload(rec.Data, limit); err != nil {
		if errors.Is(err, ErrOversize) {
			return rec, fmt.Errorf("%w: %w", ErrInvalidRecord, err)
		}
		return rec, err
	}
	return rec, nil
}

// readAt rejects symlinks on open and validates the opened descriptor,
// never a preceding path stat. NONBLOCK keeps a substituted FIFO from
// blocking.
func readAt(dir *os.File, name string, limit int64) ([]byte, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, st, ErrSymlink
	}
	if err != nil {
		return nil, st, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, st, errNonRegular
	}
	if st.Size > limit {
		return nil, st, ErrOversize
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, st, err
	}
	if int64(len(raw)) > limit {
		return nil, st, ErrOversize
	}
	return raw, st, nil
}

// openDir pins the spool directory. The writer (collector) side checks
// ownership and repairs the mode like pvecollect; the reader (server) side
// only accepts the exact provisioned mode and never changes it.
func (s *Spool) openDir(writer bool) (*os.File, error) {
	if !filepath.IsAbs(s.Dir) {
		return nil, errors.New("netdevcollect: spool directory must be absolute")
	}
	dir, err := openDirPath(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("netdevcollect: open spool %s: %w", s.Dir, err)
	}
	if writer {
		err = ensureDirMode(dir, spoolDirMode)
	} else {
		err = checkDirMode(dir, spoolDirMode)
	}
	if err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

// openDirPath walks from /, pinning and rejecting symlinks at every
// component. It never creates directories.
func openDirPath(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(filepath.Clean(path), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			err = directoryError(fd, part, err)
			unix.Close(fd)
			return nil, err
		}
		unix.Close(fd)
		fd = next
	}
	readFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(readFD), path), nil
}

func directoryError(fd int, name string, err error) error {
	var st unix.Stat_t
	if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return ErrSymlink
	}
	return err
}

// chmodDir changes an open directory's mode. It is a variable so that tests
// can simulate the EPERM that the collector's systemd hardening returns.
var chmodDir = func(dir *os.File, mode os.FileMode) error { return dir.Chmod(mode) }

// dirModeMask covers the mode bits the directory checks compare.
const dirModeMask = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// spoolGroupName is the shared group of the collector and the server that
// install.sh and the container image give the spool directory.
const spoolGroupName = "nebula-rpc"

// spoolOwnership returns the UID and GID the spool directory must have. It
// is a variable so that tests can simulate other owners.
var spoolOwnership = defaultSpoolOwnership

// spoolGroupLookup resolves the shared spool group by name. It is a
// variable so that tests can simulate the group database.
var spoolGroupLookup = user.LookupGroup

// spoolSupplementaryGroups returns the process's supplementary GIDs. It is
// a variable so that tests can simulate group membership.
var spoolSupplementaryGroups = os.Getgroups

// defaultSpoolOwnership expects the effective UID as owner. The group is
// spoolGroupName when this process is a member of it; otherwise, where no
// shared group is set up, it is the process's own effective GID. Any group
// the process cannot resolve fails closed.
func defaultSpoolOwnership() (uint32, uint32, error) {
	uid, egid := uint32(os.Geteuid()), uint32(os.Getegid())
	g, err := spoolGroupLookup(spoolGroupName)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return uid, egid, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("look up group %s: %w", spoolGroupName, err)
	}
	gid64, err := strconv.ParseUint(g.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("group %s has invalid gid %q", spoolGroupName, g.Gid)
	}
	gid := uint32(gid64)
	if gid == egid {
		return uid, gid, nil
	}
	groups, err := spoolSupplementaryGroups()
	if err != nil {
		return 0, 0, fmt.Errorf("read supplementary groups: %w", err)
	}
	for _, sg := range groups {
		if sg >= 0 && uint32(sg) == gid {
			return uid, gid, nil
		}
	}
	return uid, egid, nil
}

// ensureDirMode checks that the open spool directory is owned by the
// collector UID and the shared group (spoolOwnership) and fails otherwise;
// it never changes ownership. A directory with exactly want (permission
// bits plus setgid, sticky and setuid) is left untouched; any other mode,
// supersets included, is changed to exactly want. Under the collector's
// RestrictSUIDSGID=yes that chmod fails, so deployments provision the final
// mode (install.sh) and a running collector never changes it.
func ensureDirMode(dir *os.File, want os.FileMode) error {
	wantUID, wantGID, err := spoolOwnership()
	if err != nil {
		return fmt.Errorf("%s: expected ownership: %w", dir.Name(), err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return fmt.Errorf("%s: stat: %w", dir.Name(), err)
	}
	if st.Uid != wantUID || st.Gid != wantGID {
		return fmt.Errorf("%w: %s is owned by %d:%d, want %d:%d (create it with install.sh)", ErrSpoolOwnership, dir.Name(), st.Uid, st.Gid, wantUID, wantGID)
	}
	fi, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("%s: stat: %w", dir.Name(), err)
	}
	got := fi.Mode() & dirModeMask
	if got == want {
		return nil
	}
	if err := chmodDir(dir, want); err != nil {
		return fmt.Errorf("%w: %s has mode %v, want %v (create it with install.sh): %w", ErrDirMode, dir.Name(), got, want, err)
	}
	return nil
}

// checkDirMode accepts only a directory with exactly want; the importer
// side never changes the mode.
func checkDirMode(dir *os.File, want os.FileMode) error {
	fi, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("%s: stat: %w", dir.Name(), err)
	}
	if got := fi.Mode() & dirModeMask; got != want {
		return fmt.Errorf("%w: %s has mode %v, want %v", ErrDirMode, dir.Name(), got, want)
	}
	return nil
}
