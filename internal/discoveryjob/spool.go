// SPDX-License-Identifier: AGPL-3.0-or-later

package discoveryjob

import (
	"bytes"
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
)

// Spool is the directory pair the server and discovery exchange files in:
// jobs/ (written by the server, read by discovery) and results/ (written
// by discovery, read by the server). Each side can only write its own
// directory (file system permissions, see deploy/).
type Spool struct{ Dir string }

// JobsDir and ResultsDir are the two directories.
func (s Spool) JobsDir() string    { return filepath.Join(s.Dir, "jobs") }
func (s Spool) ResultsDir() string { return filepath.Join(s.Dir, "results") }

// Available reports whether the jobs directory exists (discovery is
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
func writeAtomic(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o640); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, name))
}

// readFile reads a regular file (no symlink) of at most limit bytes.
func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if st.Size() > limit {
		return nil, errors.New("file too large")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file too large")
	}
	return b, nil
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON object")
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
		return err
	}
	return writeAtomic(s.JobsDir(), j.ID+".json", b)
}

// RemoveJob removes a job file (server side, after its result was read
// or when it is cancelled).
func (s Spool) RemoveJob(id string) error {
	if !ValidID(id) {
		return errors.New("invalid job ID")
	}
	err := os.Remove(filepath.Join(s.JobsDir(), id+".json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PendingJobs lists the jobs without a result, oldest first (discovery
// side). Invalid job files are returned as errors by ID, so discovery can
// answer them with a failed result.
func (s Spool) PendingJobs() ([]Job, map[string]error, error) {
	entries, err := os.ReadDir(s.JobsDir())
	if err != nil {
		return nil, nil, err
	}
	var jobs []Job
	bad := map[string]error{}
	for _, e := range entries {
		id := fileID(e.Name())
		if id == "" {
			continue
		}
		if _, err := os.Lstat(filepath.Join(s.ResultsDir(), id+".json")); err == nil {
			continue
		}
		b, err := readFile(filepath.Join(s.JobsDir(), e.Name()), MaxJobBytes)
		if err != nil {
			bad[id] = err
			continue
		}
		var j Job
		if err := decodeStrict(b, &j); err != nil {
			bad[id] = fmt.Errorf("invalid job: %w", err)
			continue
		}
		if j.ID != id {
			bad[id] = errors.New("job ID does not match its file name")
			continue
		}
		if err := j.Validate(); err != nil {
			bad[id] = err
			continue
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(i, k int) bool { return jobs[i].CreatedAt < jobs[k].CreatedAt })
	return jobs, bad, nil
}

// WriteResult writes a result (discovery side).
func (s Spool) WriteResult(r Result) error {
	if err := r.Clean(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(b) > MaxResultBytes {
		r.Hosts, r.OK, r.Error = nil, false, "the result is too large; scan fewer addresses or ports"
		if b, err = json.Marshal(r); err != nil {
			return err
		}
	}
	return writeAtomic(s.ResultsDir(), r.Job+".json", b)
}

// ReadResult reads and cleans the result of a job (server side); it
// returns os.ErrNotExist while there is none.
func (s Spool) ReadResult(id string) (Result, error) {
	if !ValidID(id) {
		return Result{}, errors.New("invalid job ID")
	}
	b, err := readFile(filepath.Join(s.ResultsDir(), id+".json"), MaxResultBytes)
	if err != nil {
		return Result{}, err
	}
	var r Result
	if err := decodeStrict(b, &r); err != nil {
		return Result{}, fmt.Errorf("invalid result: %w", err)
	}
	if r.Job != id {
		return Result{}, errors.New("result for another job")
	}
	if err := r.Clean(); err != nil {
		return Result{}, err
	}
	return r, nil
}

// PruneResults removes result files older than age (discovery side; the
// server reads results within a minute).
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
