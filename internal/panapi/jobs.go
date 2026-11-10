// SPDX-License-Identifier: AGPL-3.0-or-later

package panapi

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// MaxJobDetailLines bounds the detail lines kept from one job. Further
// lines are dropped and Job.DetailsTruncated is set.
const MaxJobDetailLines = 64

// maxJobTypeBytes bounds the job type ("Commit", "Validate", ...).
const maxJobTypeBytes = 64

// maxJobProgress is the highest progress value (percent).
const maxJobProgress = 100

// Sentinel errors for job parsing. Neither repeats device text.
var (
	// ErrInvalidJob is returned when a well-formed job response carries
	// content NOS refuses: a missing or repeated field, a job ID other
	// than the requested one, a progress outside 0-100, a malformed type
	// or detail line, more than one job, or a status and result that
	// contradict each other.
	ErrInvalidJob = errors.New("panapi: invalid job content")

	// ErrUnknownJobState is returned when the job status or result is
	// missing or not one of the values NOS knows. A caller waiting for a
	// job must treat the job's outcome as unknown, never as success.
	ErrUnknownJobState = errors.New("panapi: unknown job status or result")
)

// JobStatus is the PAN-OS job status.
type JobStatus string

// Job statuses. The mapping is complete: any other value is refused with
// ErrUnknownJobState.
const (
	JobActive   JobStatus = "ACT"
	JobFinished JobStatus = "FIN"
	JobPending  JobStatus = "PEND"
)

// JobResult is the PAN-OS job result.
type JobResult string

// Job results. The mapping is complete: any other value is refused with
// ErrUnknownJobState.
const (
	JobResultOK      JobResult = "OK"
	JobResultFail    JobResult = "FAIL"
	JobResultPending JobResult = "PEND"
)

// Job is one PAN-OS job (commit, validate, ...). Status and Result are
// consistent: a finished job has result OK or FAIL, an active or pending
// job has result PEND. Details holds the non-blank detail lines in device
// order, trimmed of surrounding white space, at most MaxJobDetailLines;
// they are untrusted device text (printable, within the XML text limit)
// and must be rendered as text only.
type Job struct {
	ID               uint64
	Type             string
	Status           JobStatus
	Result           JobResult
	Progress         int
	Details          []string
	DetailsTruncated bool
}

// Done reports whether the job has finished (successfully or not).
func (j Job) Done() bool { return j.Status == JobFinished }

// xmlJobResponse and the types below are the element allowlist for the
// reply to show jobs id (exact form *verify* on the lab firewall, ND-03).
// Single-valued elements are slices so that a repetition is detected;
// every other element (user, times, description, warnings, ...) is dropped
// with its subtree.
type (
	xmlJobResponse struct {
		Result []xmlJobResult `xml:"result"`
	}
	xmlJobResult struct {
		Job []xmlJob `xml:"job"`
	}
	xmlJob struct {
		ID       []string        `xml:"id"`
		Type     []string        `xml:"type"`
		Status   []string        `xml:"status"`
		Result   []string        `xml:"result"`
		Progress []string        `xml:"progress"`
		Details  []xmlJobDetails `xml:"details"`
	}
	xmlJobDetails struct {
		Lines []string `xml:"line"`
	}
)

// ParseJob parses the reply to a show jobs id request for job id. It
// performs no I/O. The response is capped at MaxOtherResponseBytes and
// passes the same limit checks and strict decoding as every ND-09 parser.
// The reply must hold exactly one job with exactly the requested ID, so a
// reply about another job is never taken for this one. Progress must be a
// plain decimal 0-100 (*verify* in ND-03 that finished jobs report a
// number, not a time). On error the result is zero. Errors never contain
// device text.
func ParseJob(data []byte, id uint64) (Job, error) {
	j, err := parseJob(data, id)
	if err != nil {
		return Job{}, fmt.Errorf("parse job: %w", err)
	}
	return j, nil
}

func parseJob(data []byte, id uint64) (Job, error) {
	if id == 0 {
		return Job{}, fmt.Errorf("%w: job ID 0 requested", ErrInvalidJob)
	}
	if err := netdevcontract.CheckXML(data, int(MaxOtherResponseBytes)); err != nil {
		if errors.Is(err, netdevcontract.ErrOverLimit) {
			return Job{}, fmt.Errorf("%w: %w", ErrXMLLimit, err)
		}
		return Job{}, fmt.Errorf("%w: XML check failed", ErrMalformedResponse)
	}
	if err := checkResponse(data); err != nil {
		return Job{}, err
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	// Entity and CharsetReader stay nil: only the predefined entities and
	// UTF-8 are accepted.
	var resp xmlJobResponse
	if err := dec.Decode(&resp); err != nil {
		return Job{}, fmt.Errorf("%w: decode failed", ErrMalformedResponse)
	}
	switch len(resp.Result) {
	case 0:
		return Job{}, fmt.Errorf("%w: no result element", ErrMalformedResponse)
	case 1:
	default:
		return Job{}, fmt.Errorf("%w: result repeated", ErrInvalidJob)
	}
	switch len(resp.Result[0].Job) {
	case 0:
		return Job{}, fmt.Errorf("%w: no job element", ErrMalformedResponse)
	case 1:
	default:
		return Job{}, fmt.Errorf("%w: more than one job", ErrInvalidJob)
	}
	e := resp.Result[0].Job[0]

	var j Job
	s, err := jobField(e.ID, "id")
	if err != nil {
		return Job{}, err
	}
	if j.ID, err = parseDecimal(s); err != nil || j.ID != id {
		return Job{}, fmt.Errorf("%w: job ID is malformed or not the requested one", ErrInvalidJob)
	}

	if j.Type, err = jobField(e.Type, "type"); err != nil {
		return Job{}, err
	}
	if !validJobType(j.Type) {
		return Job{}, fmt.Errorf("%w: type is malformed", ErrInvalidJob)
	}

	if j.Status, j.Result, err = jobState(e.Status, e.Result); err != nil {
		return Job{}, err
	}

	if s, err = jobField(e.Progress, "progress"); err != nil {
		return Job{}, err
	}
	p, err := parseDecimal(s)
	if err != nil || p > maxJobProgress {
		return Job{}, fmt.Errorf("%w: progress is not a percentage", ErrInvalidJob)
	}
	j.Progress = int(p)

	if j.Details, j.DetailsTruncated, err = jobDetails(e.Details); err != nil {
		return Job{}, err
	}
	return j, nil
}

// jobField returns the single value of a required job element; what is a
// fixed element name.
func jobField(vs []string, what string) (string, error) {
	switch len(vs) {
	case 0:
		return "", fmt.Errorf("%w: %s missing", ErrInvalidJob, what)
	case 1:
		return vs[0], nil
	}
	return "", fmt.Errorf("%w: %s repeated", ErrInvalidJob, what)
}

// jobState maps status and result exactly (no trimming, no case folding)
// and checks that they agree.
func jobState(status, result []string) (JobStatus, JobResult, error) {
	if len(status) > 1 || len(result) > 1 {
		return "", "", fmt.Errorf("%w: status or result repeated", ErrInvalidJob)
	}
	if len(status) == 0 || len(result) == 0 {
		return "", "", fmt.Errorf("%w: status or result missing", ErrUnknownJobState)
	}
	st := JobStatus(status[0])
	switch st {
	case JobActive, JobFinished, JobPending:
	default:
		return "", "", fmt.Errorf("%w: status", ErrUnknownJobState)
	}
	res := JobResult(result[0])
	switch res {
	case JobResultOK, JobResultFail, JobResultPending:
	default:
		return "", "", fmt.Errorf("%w: result", ErrUnknownJobState)
	}
	if (st == JobFinished) == (res == JobResultPending) {
		return "", "", fmt.Errorf("%w: status and result contradict each other", ErrInvalidJob)
	}
	return st, res, nil
}

// validJobType reports whether t is a short token of letters, digits,
// space, '-', '_' and '.'.
func validJobType(t string) bool {
	if t == "" || len(t) > maxJobTypeBytes {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == ' ', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// jobDetails returns the non-blank detail lines, trimmed, cut at
// MaxJobDetailLines. A line that is not printable text is refused.
func jobDetails(ds []xmlJobDetails) ([]string, bool, error) {
	switch len(ds) {
	case 0:
		return nil, false, nil
	case 1:
	default:
		return nil, false, fmt.Errorf("%w: details repeated", ErrInvalidJob)
	}
	var out []string
	for _, l := range ds[0].Lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if len(out) == MaxJobDetailLines {
			return out, true, nil
		}
		if !validText(l, MaxXMLTextBytes) {
			return nil, false, fmt.Errorf("%w: detail line is not printable text", ErrInvalidJob)
		}
		out = append(out, l)
	}
	return out, false, nil
}
