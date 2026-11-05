// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iconjob is the spool format between the server and the one-shot
// icon fetcher nebula-iconfetch (ADR 0009 D6, TM16). The server writes a
// job (catalog key and a URL that already passed the iconfetch policy)
// into jobs/; the helper writes the sanitized icon or an error into
// results/. Each side writes only its own directory.
//
// The package uses the standard library only, so the helper that imports
// it links no database, vault or catalog code.
package iconjob

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Format strings of the two file kinds.
const (
	JobFormat    = "nebula-iconfetch-job-v1"
	ResultFormat = "nebula-iconfetch-result-v1"
)

// Limits, next to the code that enforces them.
const (
	// MaxJobBytes bounds a job file.
	MaxJobBytes = 8 << 10
	// MaxResultBytes bounds a result file: two small PNGs, base64-encoded.
	MaxResultBytes = 512 << 10
	// MaxPNGBytes bounds each PNG in a result before encoding.
	MaxPNGBytes = 160 << 10
	// MaxURLLen bounds the job URL (same as iconfetch.MaxURLLen).
	MaxURLLen = 2048
	// MaxActorLen bounds the requesting admin's name.
	MaxActorLen = 64
	// MaxErrorLen bounds the error text of a result.
	MaxErrorLen = 512
	// maxKeyLen bounds a catalog key (same as softwarecat).
	maxKeyLen = 64
	// idLen is the length of a job ID in hex digits.
	idLen = 32
	// MaxListEntries bounds how many directory entries one spool listing
	// reads, so a flooded directory cannot make a listing unbounded.
	MaxListEntries = 4096
	// listBatch is the number of entries read per ReadDir call.
	listBatch = 256
)

// ErrInvalid marks a job or result that violates the spool format.
var ErrInvalid = errors.New("iconjob: invalid spool file")

// Job asks the helper to fetch one icon URL for a catalog key.
// RequestedBy is for the server's audit trail only; the helper ignores it.
type Job struct {
	Format      string `json:"format"`
	ID          string `json:"id"`
	Key         string `json:"key"`
	URL         string `json:"url"`
	RequestedBy string `json:"requested_by"`
	CreatedAt   int64  `json:"created_at"`
}

// Result is the helper's answer to a job: either OK with the sanitized
// icon (SHA256 is the hex SHA-256 of PNG128) or an Error text.
type Result struct {
	Format     string `json:"format"`
	Job        string `json:"job"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	PNG64      []byte `json:"png64,omitempty"`
	PNG128     []byte `json:"png128,omitempty"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at"`
}

// NewID returns a random job ID.
func NewID() (string, error) {
	var b [idLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("iconjob: job ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidID reports whether s is a job ID: 32 lowercase hex digits.
func ValidID(s string) bool {
	if len(s) != idLen {
		return false
	}
	return isLowerHex(s)
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ValidKey reports whether s is a catalog key (same rule as
// softwarecat.NewKey, duplicated so the helper does not link softwarecat).
func ValidKey(s string) bool {
	if len(s) == 0 || len(s) > maxKeyLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '.' || c == '_' || c == '-'))) {
			return false
		}
	}
	return true
}

// printableASCII reports whether s is non-empty printable ASCII without
// spaces of at most limit bytes.
func printableASCII(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

// validActor accepts printable UTF-8 without control characters.
func validActor(s string) bool {
	if s == "" || len(s) > MaxActorLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

// Validate checks the job's shape. The URL policy itself (allowlist, no
// IP literals) is internal/iconfetch's; both sides apply it.
func (j *Job) Validate() error {
	switch {
	case j.Format != JobFormat:
		return fmt.Errorf("%w: job format %q", ErrInvalid, j.Format)
	case !ValidID(j.ID):
		return fmt.Errorf("%w: job ID", ErrInvalid)
	case !ValidKey(j.Key):
		return fmt.Errorf("%w: catalog key", ErrInvalid)
	case !printableASCII(j.URL, MaxURLLen) || !strings.HasPrefix(j.URL, "https://"):
		return fmt.Errorf("%w: URL", ErrInvalid)
	case !validActor(j.RequestedBy):
		return fmt.Errorf("%w: requested_by", ErrInvalid)
	case j.CreatedAt <= 0:
		return fmt.Errorf("%w: created_at", ErrInvalid)
	}
	return nil
}

// CleanError bounds and sanitizes an error text for a result: printable
// ASCII only, other bytes become '?', at most MaxErrorLen bytes.
func CleanError(s string) string {
	b := make([]byte, 0, min(len(s), MaxErrorLen))
	for i := 0; i < len(s) && len(b) < MaxErrorLen; i++ {
		c := s[i]
		if c < ' ' || c >= 0x7f {
			c = '?'
		}
		b = append(b, c)
	}
	if len(b) == 0 {
		return "failed"
	}
	return string(b)
}

// Validate checks the result's shape: a failure carries only an error
// text, a success carries two bounded PNGs whose hash matches. It does
// not decode the PNGs; the server sanitizes them again on import.
func (r *Result) Validate() error {
	if r.Format != ResultFormat {
		return fmt.Errorf("%w: result format %q", ErrInvalid, r.Format)
	}
	if !ValidID(r.Job) {
		return fmt.Errorf("%w: job ID", ErrInvalid)
	}
	if !r.OK {
		if r.Error == "" || CleanError(r.Error) != r.Error || r.SHA256 != "" || r.PNG64 != nil || r.PNG128 != nil {
			return fmt.Errorf("%w: failed result", ErrInvalid)
		}
		return nil
	}
	if r.Error != "" {
		return fmt.Errorf("%w: successful result with an error", ErrInvalid)
	}
	if len(r.PNG64) == 0 || len(r.PNG64) > MaxPNGBytes || len(r.PNG128) == 0 || len(r.PNG128) > MaxPNGBytes {
		return fmt.Errorf("%w: PNG sizes", ErrInvalid)
	}
	if len(r.SHA256) != sha256.Size*2 || !isLowerHex(r.SHA256) {
		return fmt.Errorf("%w: sha256", ErrInvalid)
	}
	sum := sha256.Sum256(r.PNG128)
	if hex.EncodeToString(sum[:]) != r.SHA256 {
		return fmt.Errorf("%w: sha256 does not match png128", ErrInvalid)
	}
	return nil
}

// Spool is the directory pair the server and the helper exchange files
// in: jobs/ (server writes, helper reads) and results/ (helper writes,
// server reads).
type Spool struct{ Dir string }

// JobsDir is the directory the server writes jobs into.
func (s Spool) JobsDir() string { return filepath.Join(s.Dir, "jobs") }

// ResultsDir is the directory the helper writes results into.
func (s Spool) ResultsDir() string { return filepath.Join(s.Dir, "results") }

// Available reports whether the jobs directory exists (the helper is
// installed).
func (s Spool) Available() bool {
	st, err := os.Stat(s.JobsDir())
	return err == nil && st.IsDir()
}

// fileID returns the job ID of a spool file name, or "".
func fileID(name string) string {
	id, ok := strings.CutSuffix(name, ".json")
	if !ok || !ValidID(id) {
		return ""
	}
	return id
}

// writeAtomic writes data to dir/name through a temporary file and a
// rename, so a reader never sees a partial file.
func writeAtomic(dir, name string, data []byte) (err error) {
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create spool file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o640); err != nil {
		return fmt.Errorf("chmod spool file: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write spool file: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync spool file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close spool file: %w", err)
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename spool file: %w", err)
	}
	return nil
}

// readFile reads a regular file (no symlink) of at most limit bytes.
func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, classifyOpen(err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: not a regular file", ErrInvalid)
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%w: file too large", ErrInvalid)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: file too large", ErrInvalid)
	}
	return b, nil
}

// classifyOpen marks open errors that a retry cannot fix as ErrInvalid:
// a symbolic link (ELOOP from O_NOFOLLOW) or a file this process may not
// read (EACCES, EPERM) violates the spool format, so the caller drops
// the job instead of retrying it forever. Other errors are returned as
// they are (os.ErrNotExist in particular stays recognizable).
func classifyOpen(err error) error {
	switch {
	case errors.Is(err, syscall.ELOOP):
		return fmt.Errorf("%w: symbolic link: %w", ErrInvalid, err)
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Errorf("%w: not readable: %w", ErrInvalid, err)
	}
	return err
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: data after the JSON object", ErrInvalid)
	}
	return nil
}

// WriteJob writes a valid job (server side).
func (s Spool) WriteJob(j Job) error {
	if err := j.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(j)
	if err != nil {
		return fmt.Errorf("encode job %s: %w", j.ID, err)
	}
	return writeAtomic(s.JobsDir(), j.ID+".json", b)
}

// ReadJob reads and validates one job (server side, on import).
func (s Spool) ReadJob(id string) (Job, error) {
	if !ValidID(id) {
		return Job{}, fmt.Errorf("%w: job ID", ErrInvalid)
	}
	b, err := readFile(filepath.Join(s.JobsDir(), id+".json"), MaxJobBytes)
	if err != nil {
		return Job{}, fmt.Errorf("read job %s: %w", id, err)
	}
	var j Job
	if err := decodeStrict(b, &j); err != nil {
		return Job{}, fmt.Errorf("read job %s: %w", id, err)
	}
	if j.ID != id {
		return Job{}, fmt.Errorf("%w: job ID does not match its file name", ErrInvalid)
	}
	if err := j.Validate(); err != nil {
		return Job{}, err
	}
	return j, nil
}

// RemoveJob removes a job file (server side, after import or on cancel).
// A result without its job is never imported again; the helper prunes
// it. A missing file is not an error.
func (s Spool) RemoveJob(id string) error {
	if !ValidID(id) {
		return fmt.Errorf("%w: job ID", ErrInvalid)
	}
	if err := os.Remove(filepath.Join(s.JobsDir(), id+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove job %s: %w", id, err)
	}
	return nil
}

// PendingJobs lists the jobs without a result, oldest first (helper
// side). Invalid job files are returned as errors by ID, so the helper
// can answer them with a failed result.
func (s Spool) PendingJobs() ([]Job, map[string]error, error) {
	ids, err := s.list(s.JobsDir())
	if err != nil {
		return nil, nil, err
	}
	var jobs []Job
	bad := map[string]error{}
	for _, id := range ids {
		if _, err := os.Lstat(filepath.Join(s.ResultsDir(), id+".json")); err == nil {
			continue
		}
		j, err := s.ReadJob(id)
		if err != nil {
			bad[id] = err
			continue
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(i, k int) bool { return jobs[i].CreatedAt < jobs[k].CreatedAt })
	return jobs, bad, nil
}

// FinishedJobs lists, sorted by ID, the IDs of jobs that have a result
// file and whose job file is still in jobs/ (server side). The server
// removes the job file once it has handled the result and never writes
// results/, so a result without its job (already imported or cancelled)
// is skipped here until the helper prunes it; it never takes a place in
// the caller's per-run budget. Only jobs/ (written by the server) is
// listed, at most MaxListEntries entries; each listed job costs one Lstat
// in results/, so the helper cannot make this call unbounded by flooding
// results/. No file is opened.
func (s Spool) FinishedJobs() ([]string, error) {
	jobs, err := s.list(s.JobsDir())
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, id := range jobs {
		if _, err := os.Lstat(filepath.Join(s.ResultsDir(), id+".json")); err == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// list returns, sorted, the job IDs among the first MaxListEntries
// entries of dir. Entries beyond the cap are left for a later call
// (after earlier files are handled or pruned).
func (s Spool) list(dir string) ([]string, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("list spool %s: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	var ids []string
	for seen := 0; seen < MaxListEntries; {
		n := min(listBatch, MaxListEntries-seen)
		entries, err := d.ReadDir(n)
		seen += len(entries)
		for _, e := range entries {
			if id := fileID(e.Name()); id != "" {
				ids = append(ids, id)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list spool %s: %w", dir, err)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// WriteResult writes a valid result (helper side).
func (s Spool) WriteResult(r Result) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode result %s: %w", r.Job, err)
	}
	if len(b) > MaxResultBytes {
		return fmt.Errorf("%w: result too large", ErrInvalid)
	}
	return writeAtomic(s.ResultsDir(), r.Job+".json", b)
}

// ReadResult reads and validates the result of a job (server side); it
// returns an error wrapping os.ErrNotExist while there is none.
func (s Spool) ReadResult(id string) (Result, error) {
	if !ValidID(id) {
		return Result{}, fmt.Errorf("%w: job ID", ErrInvalid)
	}
	b, err := readFile(filepath.Join(s.ResultsDir(), id+".json"), MaxResultBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read result %s: %w", id, err)
	}
	var r Result
	if err := decodeStrict(b, &r); err != nil {
		return Result{}, fmt.Errorf("read result %s: %w", id, err)
	}
	if r.Job != id {
		return Result{}, fmt.Errorf("%w: result for another job", ErrInvalid)
	}
	if err := r.Validate(); err != nil {
		return Result{}, err
	}
	return r, nil
}

// PruneResults removes result files and stale temporary files older than
// age (helper side). It is the only cleanup of results/: the server reads
// that directory but never writes it, and skips results whose job it has
// already removed (see FinishedJobs).
func (s Spool) PruneResults(age time.Duration, now time.Time) {
	entries, err := os.ReadDir(s.ResultsDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if (fileID(e.Name()) != "" || strings.HasPrefix(e.Name(), ".tmp-")) && now.Sub(info.ModTime()) > age {
			_ = os.Remove(filepath.Join(s.ResultsDir(), e.Name()))
		}
	}
}
