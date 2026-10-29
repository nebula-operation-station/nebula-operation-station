// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi provides typed, read-only readers for the Proxmox VE JSON
// API. It is built up ticket by ticket (ADR 0006); nothing in this package
// mutates cluster state.
//
// Every value read from a PVE host is untrusted input: responses are size
// limited, schema-validated and reduced to nonsecret evidence. Authorization
// headers and response bodies are never logged.
package pveapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits for backup evidence reads.
const (
	// defaultTimeout bounds a single API call when the caller does not set
	// Client.Timeout.
	defaultTimeout = 30 * time.Second
	// defaultMaxResponseBytes bounds one API response body.
	defaultMaxResponseBytes = int64(4 << 20)

	// maxListings is the maximum number of entries accepted from one
	// listing endpoint (storage content, cluster backup jobs).
	maxListings = 10000
	// maxJSONDepth bounds containers in the strict JSON walk, including
	// unknown fields, before recursive descent.
	maxJSONDepth = 32
	// Correlation limits bound scanning and the aggregate per-guest output.
	maxCorrelationWork        = 1000000
	maxCorrelatedRecords      = 50000
	maxCorrelationOutputBytes = 16 << 20
	// maxVolidBytes bounds a PVE volume ID (storage:backup/name).
	maxVolidBytes = 256
	// maxNotesBytes bounds a notes field; only its length is kept.
	maxNotesBytes = 1024
	// maxFieldBytes bounds short free-form fields (schedule, time, mode,
	// storage type, task type).
	maxFieldBytes = 64
	// maxActorBytes bounds a task actor (user@realm).
	maxActorBytes = 128
	// maxTargetBytes bounds a task target (e.g. qemu/100).
	maxTargetBytes = 128
	// maxExitStatusBytes bounds a task ExitStatus string.
	maxExitStatusBytes = 64
	// maxVMIDsPerJob bounds each guest selection/exclusion list.
	maxVMIDsPerJob = 1024
	// maxVMIDListBytes bounds list text before splitting it into IDs.
	maxVMIDListBytes = maxVMIDsPerJob * 12
	// maxPathBytes bounds an API path built from validated names.
	maxPathBytes = 256

	// maxVMID is the exclusive upper bound for guest IDs (PVE uses 31-bit
	// vmids).
	maxVMID = uint64(1) << 31
	// maxCTimeUnix is the largest accepted ctime (2^32-1: PVE stores
	// ctime as a 32-bit unsigned value).
	maxCTimeUnix = int64(1)<<32 - 1
)

// Backup evidence sources, kinds and statuses (ADR 0006, P1-20).
const (
	// SourceVZDump is evidence produced by vzdump (PVE backup tasks and
	// non-PBS backup volumes).
	SourceVZDump = "vzdump"
	// SourcePBS is evidence from Proxmox Backup Server volumes.
	SourcePBS = "pbs"

	// KindTask is evidence from a recent backup task summary.
	KindTask = "task"
	// KindCatalog is evidence from a detectable catalog entry.
	KindCatalog = "catalog"

	// StatusSuccess is a finished task with ExitStatus OK.
	StatusSuccess = "success"
	// StatusFailed is a finished task without ExitStatus OK.
	StatusFailed = "failed"
	// StatusCatalog is a catalog entry with no (or no successful)
	// verification.
	StatusCatalog = "catalog"
	// StatusVerified is a PBS catalog entry with a successful
	// verification.
	StatusVerified = "verified"
)

// TaskExitOK is the ExitStatus of a successfully finished PVE task.
const TaskExitOK = "OK"

// Dataset reasons for unavailable backup evidence.
const (
	// ReasonDenied is the dataset reason for a read that PVE denied
	// (HTTP 401/403).
	ReasonDenied = "denied: insufficient read privileges"
	// ReasonFiltered is the dataset reason for a read that PVE may have
	// filtered because the token lacks VM.Backup and
	// Datastore.AllocateSpace on the listed storages.
	ReasonFiltered = "filtered: insufficient read privileges"
	// ReasonNoTasks is the dataset reason when no task summaries were
	// supplied (the task read was not performed).
	ReasonNoTasks = "no task summaries supplied"
)

// TriState is a yes/no/unknown hint.
//
// TODO(p120): replace with pvecontract.TriState once P1-02 (branch
// agent/p102-pve-contracts) lands on main.
type TriState string

// TriState values.
const (
	TriYes     TriState = "yes"
	TriNo      TriState = "no"
	TriUnknown TriState = "unknown"
)

// Availability is the state of one dataset in an observation.
type Availability string

// Availability values.
const (
	// Available means the dataset was read and is complete; Value may be
	// empty.
	Available Availability = "available"
	// Unavailable means the dataset could not be read (denied or
	// filtered); Value is zero and Reason explains why.
	Unavailable Availability = "unavailable"
)

// Dataset distinguishes a present value (which may be empty) from an
// unavailable one, so "no backup found" never renders as "no data".
//
// TODO(p120): replace with pvecontract.Dataset once P1-02 (branch
// agent/p102-pve-contracts) lands on main.
type Dataset[T any] struct {
	State  Availability `json:"state"`
	Value  T            `json:"value"`
	Reason string       `json:"reason,omitempty"`
}

// AvailableDataset wraps a present value.
func AvailableDataset[T any](value T) Dataset[T] {
	return Dataset[T]{State: Available, Value: value}
}

// UnavailableDataset wraps an absent value with a human-readable reason.
// The zero value of T is used; it must never carry data.
func UnavailableDataset[T any](reason string) Dataset[T] {
	return Dataset[T]{State: Unavailable, Reason: reason}
}

// IsAvailable reports whether the dataset was read and is complete.
func (d Dataset[T]) IsAvailable() bool { return d.State == Available }

// BackupEvidence is one nonsecret backup observation for one guest: a
// recent task summary or a detectable catalog entry.
type BackupEvidence struct {
	Source       string   `json:"source"`
	Kind         string   `json:"kind"`
	Status       string   `json:"status"`
	Name         string   `json:"name"`
	StartedUnix  int64    `json:"started_unix"`
	FinishedUnix int64    `json:"finished_unix"`
	Verified     TriState `json:"verified"`
}

// CatalogEntry is one backup volume seen in a storage content listing.
// Only nonsecret metadata is kept: volid, vmid, ctime, size and the length
// of notes. Notes contents, digests and image data never appear.
type CatalogEntry struct {
	VolID       string
	VMID        uint64
	Source      string
	CTimeUnix   int64
	SizeBytes   int64
	NotesLength int
	// Verified is derived from PBS verification.state when present;
	// TriUnknown otherwise.
	Verified TriState
}

// BackupJob is one /cluster/backup job definition (nonsecret fields only).
type BackupJob struct {
	Schedule string
	Day      string
	Time     string
	Mode     string
	Storage  string
	All      bool
	Pool     string
	// VMIDs is the explicit guest selection from the PVE vmid list.
	VMIDs []uint64
	// Exclude removes guests from an All selection.
	Exclude []uint64
	// Node restricts coverage to guests currently on this node.
	Node string
	// Enabled reports whether the job runs; PVE defaults it to true.
	Enabled bool
	// NotesLength is the length of the job notes; the notes content is
	// never kept.
	NotesLength int
}

// CoversVMID reports whether the job selection covers the guest vmid.
// Disabled jobs and node-restricted jobs (which require node information)
// cover nothing. Pools not present in pools are treated as unknown.
func (j BackupJob) CoversVMID(vmid uint64, pools map[string]map[uint64]bool) bool {
	return j.coversGuest(vmid, "", pools)
}

func (j BackupJob) coversGuest(vmid uint64, node string, pools map[string]map[uint64]bool) bool {
	if !j.Enabled || (j.Node != "" && j.Node != node) {
		return false
	}
	if j.Pool != "" {
		return pools[j.Pool][vmid]
	}
	for _, id := range j.VMIDs {
		if id == vmid {
			return true
		}
	}
	if j.All {
		for _, id := range j.Exclude {
			if id == vmid {
				return false
			}
		}
		return true
	}
	return false
}

// TaskSummary is one bounded backup task summary supplied by the caller
// (the task reader, P1-19). ReadBackups only keeps the nonsecret fields
// needed for evidence.
type TaskSummary struct {
	Node         string
	Actor        string
	Type         string
	Target       string
	VMID         uint64
	StartedUnix  int64
	FinishedUnix int64
	// ExitStatus is the terminal task result; empty means no terminal
	// result was observed. A result also requires valid start/end times.
	ExitStatus string
}

// BackupSource is one node/storage pair that can hold backup volumes.
type BackupSource struct {
	Node    string
	Storage string
	// Type is the storage type; "pbs" selects SourcePBS, anything else
	// SourceVZDump.
	Type string
}

// ReadScope describes what the read-only token can see.
type ReadScope struct {
	// FullContent reports whether the token has VM.Backup and
	// Datastore.AllocateSpace on the listed storages, so content
	// listings are complete. When false, PVE may silently omit volumes;
	// the catalog is then reported unavailable, never empty.
	FullContent bool
}

// BackupsOptions selects the inputs of one ReadBackups call.
type BackupsOptions struct {
	// Sources are the node/storage pairs to list for backup volumes.
	Sources []BackupSource
	// Scope describes the read privileges of the token.
	Scope ReadScope
	// Tasks are recent backup task summaries (P1-19). nil means no task
	// data was read; a non-nil empty slice means the task read completed
	// and found no backup tasks.
	Tasks []TaskSummary
	// Pools maps pool name to member vmids for job selection coverage.
	// Pools not present are treated as unknown.
	Pools map[string]map[uint64]bool
	// GuestNodes maps guest IDs to their current inventory node. A
	// node-restricted job never covers guests with unknown placement.
	// Storage locations and historical tasks do not establish placement.
	GuestNodes map[uint64]string
}

// BackupsObservation is the correlated, nonsecret backup evidence for one
// observation cycle.
type BackupsObservation struct {
	Catalog Dataset[[]CatalogEntry]
	Jobs    Dataset[[]BackupJob]
	// Guests is sorted by VMID.
	Guests []GuestBackups
}

// GuestBackups is the correlated backup evidence for one guest (vmid).
type GuestBackups struct {
	VMID    uint64
	Catalog Dataset[[]BackupEvidence]
	Tasks   Dataset[[]BackupEvidence]
	Jobs    Dataset[[]BackupJob]
}

// ErrDenied reports that PVE denied a read (HTTP 401/403). ReadBackups maps
// it to an unavailable dataset; getJSON returns it wrapped.
var ErrDenied = errors.New("pveapi: denied")

// Client is a typed READ-ONLY client for the PVE JSON API. It performs GET
// requests only, with an injected *http.Client, base URL and token header
// supplier. It never logs headers or bodies.
type Client struct {
	// BaseURL is the PVE API root, e.g. https://pve1:8006/api2/json.
	BaseURL string
	// HTTP performs the requests. A nil value is replaced with a default
	// client; production wiring should supply a pinned HTTPS transport
	// (P1-03).
	HTTP *http.Client
	// TokenHeader supplies the Authorization header value per call.
	TokenHeader func() string
	// Timeout bounds a single API call; zero uses defaultTimeout.
	Timeout time.Duration
	// MaxResponseBytes bounds one response body; zero uses
	// defaultMaxResponseBytes.
	MaxResponseBytes int64
}

// NewClient validates the base URL (absolute http/https URL ending in
// /api2/json) and the token supplier, and fills defaults. httpc may be nil.
func NewClient(baseURL string, httpc *http.Client, token func() string) (*Client, error) {
	if token == nil {
		return nil, errors.New("pveapi: token header supplier is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errors.New("pveapi: invalid base URL")
	}
	if !strings.HasSuffix(u.Path, "/api2/json") {
		return nil, errors.New("pveapi: base URL must end with /api2/json")
	}
	if httpc == nil {
		httpc = &http.Client{}
	}
	return &Client{
		BaseURL:          u.Scheme + "://" + u.Host + u.Path,
		HTTP:             httpc,
		TokenHeader:      token,
		Timeout:          defaultTimeout,
		MaxResponseBytes: defaultMaxResponseBytes,
	}, nil
}

// ReadBackups reads backup evidence for the given sources and correlates it
// per guest (ADR 0006, P1-20).
//
// Denied reads (HTTP 401/403) and filtered reads yield unavailable datasets
// with a reason; they are not errors. I/O and schema errors are returned so
// the caller can retry with backoff.
func (c *Client) ReadBackups(ctx context.Context, opts BackupsOptions) (BackupsObservation, error) {
	sources, err := validateOptions(opts)
	if err != nil {
		return BackupsObservation{}, err
	}
	obs := BackupsObservation{}

	if !opts.Scope.FullContent {
		obs.Catalog = UnavailableDataset[[]CatalogEntry](ReasonFiltered)
	} else {
		entries, err := c.readCatalog(ctx, sources)
		switch {
		case err == nil:
			if entries == nil {
				entries = []CatalogEntry{}
			}
			obs.Catalog = AvailableDataset(entries)
		case errors.Is(err, ErrDenied):
			obs.Catalog = UnavailableDataset[[]CatalogEntry](ReasonDenied)
		default:
			return BackupsObservation{}, err
		}
	}

	jobs, err := c.readJobs(ctx)
	switch {
	case err == nil:
		if jobs == nil {
			jobs = []BackupJob{}
		}
		obs.Jobs = AvailableDataset(jobs)
	case errors.Is(err, ErrDenied):
		obs.Jobs = UnavailableDataset[[]BackupJob](ReasonDenied)
	default:
		return BackupsObservation{}, err
	}

	obs.Guests, err = correlate(obs.Catalog, obs.Jobs, opts.Tasks, opts.Pools, opts.GuestNodes)
	if err != nil {
		return BackupsObservation{}, err
	}
	return obs, nil
}

// readCatalog lists backup volumes on every source. It returns the union of
// entries, or an error (ErrDenied wrapped if any source denied the read): a
// partial catalog must never be presented as complete.
func (c *Client) readCatalog(ctx context.Context, sources []BackupSource) ([]CatalogEntry, error) {
	var all []CatalogEntry
	for _, src := range sources {
		var raw []rawContentEntry
		path := "/nodes/" + src.Node + "/storage/" + src.Storage + "/content"
		if err := c.getJSON(ctx, path, url.Values{"content": {"backup"}}, &raw); err != nil {
			return nil, err
		}
		if len(raw) > maxListings {
			return nil, fmt.Errorf("pveapi: content %s: more than %d entries", src.Storage, maxListings)
		}
		source := SourceVZDump
		if strings.EqualFold(src.Type, "pbs") {
			source = SourcePBS
		}
		for i := range raw {
			entry, err := raw[i].toCatalogEntry(source)
			if err != nil {
				return nil, fmt.Errorf("pveapi: content %s: %w", src.Storage, err)
			}
			all = append(all, entry)
		}
	}
	return all, nil
}

// readJobs lists the cluster-wide backup job definitions.
func (c *Client) readJobs(ctx context.Context) ([]BackupJob, error) {
	var raw []rawJob
	if err := c.getJSON(ctx, "/cluster/backup", nil, &raw); err != nil {
		return nil, err
	}
	if len(raw) > maxListings {
		return nil, fmt.Errorf("pveapi: backup jobs: more than %d entries", maxListings)
	}
	jobs := make([]BackupJob, 0, len(raw))
	for i := range raw {
		job, err := raw[i].toJob()
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, nil
}

// getJSON performs a GET on BaseURL+path (with query) and decodes the PVE
// "data" envelope field into out.
//
// It never logs headers or bodies. Denied reads (HTTP 401/403) return
// ErrDenied wrapped; the caller maps that to an unavailable dataset.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	if err := validatePath(path); err != nil {
		return err
	}
	token := c.TokenHeader()
	if token == "" {
		return errors.New("pveapi: token header supplier returned no token")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	endpoint := c.BaseURL + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("pveapi: build request: %w", err)
	}
	req.Header.Set("Authorization", token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("pveapi: get %s: %w", path, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s", ErrDenied, path)
	default:
		return fmt.Errorf("pveapi: get %s: unexpected status %d", path, resp.StatusCode)
	}
	max := c.MaxResponseBytes
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return fmt.Errorf("pveapi: get %s: read: %w", path, err)
	}
	if int64(len(body)) > max {
		return fmt.Errorf("pveapi: get %s: response exceeds %d bytes", path, max)
	}
	if err := strictJSON(body); err != nil {
		return fmt.Errorf("pveapi: get %s: %w", path, err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("pveapi: get %s: envelope: %w", path, err)
	}
	if len(envelope) != 1 {
		return fmt.Errorf("pveapi: get %s: envelope must contain exactly one field", path)
	}
	data, ok := envelope["data"]
	if !ok {
		return fmt.Errorf("pveapi: get %s: missing data field", path)
	}
	if string(data) == "null" {
		return fmt.Errorf("pveapi: get %s: data is null", path)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("pveapi: get %s: data: %w", path, err)
	}
	return nil
}

// strictJSON validates that raw is a single JSON document without duplicate
// object keys at any depth.
func strictJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := strictWalk(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("pveapi: trailing data after JSON document")
	}
	return nil
}

func strictWalk(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		if depth >= maxJSONDepth {
			return errors.New("pveapi: JSON depth limit exceeded")
		}
		switch v {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, isString := keyTok.(string)
				if !isString {
					return errors.New("pveapi: object key is not a string")
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("pveapi: duplicate key %q", key[:min(len(key), 32)])
				}
				seen[key] = struct{}{}
				if err := strictWalk(dec, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		case '[':
			for dec.More() {
				if err := strictWalk(dec, depth+1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pveapi: unexpected delimiter %q", v)
		}
	}
	return nil
}

// rawContentEntry is one entry of a storage content listing (PVE 8 and 9
// shapes). Unknown fields are ignored for forward compatibility.
type rawContentEntry struct {
	Volid        string          `json:"volid"`
	Content      string          `json:"content"`
	VMID         uint64          `json:"vmid"`
	CTime        int64           `json:"ctime"`
	Size         int64           `json:"size"`
	Notes        string          `json:"notes"`
	Verification json.RawMessage `json:"verification"`
}

// toCatalogEntry validates the entry and reduces it to nonsecret metadata.
func (e rawContentEntry) toCatalogEntry(source string) (CatalogEntry, error) {
	if e.Content != "backup" {
		return CatalogEntry{}, errors.New("content entry: unexpected content type")
	}
	if !validVolid(e.Volid) {
		return CatalogEntry{}, errors.New("content entry: invalid volid")
	}
	if e.VMID == 0 || e.VMID >= maxVMID {
		return CatalogEntry{}, errors.New("content entry: invalid vmid")
	}
	if e.CTime <= 0 || e.CTime > maxCTimeUnix {
		return CatalogEntry{}, errors.New("content entry: invalid ctime")
	}
	if e.Size < 0 {
		return CatalogEntry{}, errors.New("content entry: negative size")
	}
	if !utf8.ValidString(e.Notes) || len(e.Notes) > maxNotesBytes {
		return CatalogEntry{}, errors.New("content entry: invalid notes")
	}
	verified := TriUnknown
	if len(e.Verification) != 0 {
		v, err := parseVerification(e.Verification)
		if err != nil {
			return CatalogEntry{}, err
		}
		if source == SourcePBS {
			verified = v
		}
	}
	return CatalogEntry{
		VolID:       e.Volid,
		VMID:        e.VMID,
		Source:      source,
		CTimeUnix:   e.CTime,
		SizeBytes:   e.Size,
		NotesLength: len(e.Notes),
		Verified:    verified,
	}, nil
}

func parseVerification(raw json.RawMessage) (TriState, error) {
	var v struct {
		State string          `json:"state"`
		UPID  json.RawMessage `json:"upid"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || (v.State != "ok" && v.State != "failed") {
		return "", errors.New("content entry: invalid verification")
	}
	if len(v.UPID) != 0 {
		var upid string
		if err := json.Unmarshal(v.UPID, &upid); err != nil || upid == "" || !validPrintable(upid, maxVolidBytes) {
			return "", errors.New("content entry: invalid verification")
		}
	}
	if v.State == "ok" {
		return TriYes, nil
	}
	return TriNo, nil
}

// rawJob is one /cluster/backup job definition (PVE 8 and 9 shapes).
// Unknown fields are ignored for forward compatibility.
type rawJob struct {
	Schedule string          `json:"schedule"`
	Day      string          `json:"day"`
	Time     string          `json:"time"`
	Mode     string          `json:"mode"`
	Storage  string          `json:"storage"`
	All      flexBool        `json:"all"`
	Pool     string          `json:"pool"`
	VMID     string          `json:"vmid"`
	Exclude  string          `json:"exclude"`
	Node     string          `json:"node"`
	Enabled  json.RawMessage `json:"enabled"`
	Notes    string          `json:"notes"`
}

// toJob validates the job definition and reduces it to nonsecret fields.
func (r rawJob) toJob() (BackupJob, error) {
	if !validText(r.Schedule, maxFieldBytes) {
		return BackupJob{}, errors.New("backup job: invalid schedule")
	}
	if !validPrintable(r.Day, maxFieldBytes) {
		return BackupJob{}, errors.New("backup job: invalid day")
	}
	if !validPrintable(r.Time, maxFieldBytes) {
		return BackupJob{}, errors.New("backup job: invalid time")
	}
	if !validPrintable(r.Mode, maxFieldBytes) {
		return BackupJob{}, errors.New("backup job: invalid mode")
	}
	if !validSlug(r.Storage) {
		return BackupJob{}, errors.New("backup job: invalid storage")
	}
	if r.Pool != "" && !validSlug(r.Pool) {
		return BackupJob{}, errors.New("backup job: invalid pool")
	}
	vmids, err := parseVMIDList(r.VMID)
	if err != nil {
		return BackupJob{}, errors.New("backup job: invalid vmid selection")
	}
	exclude, err := parseVMIDList(r.Exclude)
	if err != nil {
		return BackupJob{}, errors.New("backup job: invalid exclusions")
	}
	if len(vmids) != 0 && (bool(r.All) || r.Pool != "" || len(exclude) != 0) {
		return BackupJob{}, errors.New("backup job: conflicting guest selections")
	}
	if r.Node != "" && !validSlug(r.Node) {
		return BackupJob{}, errors.New("backup job: invalid node")
	}
	enabled := flexBool(true)
	if len(r.Enabled) != 0 {
		if err := json.Unmarshal(r.Enabled, &enabled); err != nil {
			return BackupJob{}, err
		}
	}
	if !utf8.ValidString(r.Notes) || len(r.Notes) > maxNotesBytes {
		return BackupJob{}, errors.New("backup job: invalid notes")
	}
	return BackupJob{
		Schedule:    r.Schedule,
		Day:         r.Day,
		Time:        r.Time,
		Mode:        r.Mode,
		Storage:     r.Storage,
		All:         bool(r.All) || (len(exclude) != 0 && r.Pool == ""),
		Pool:        r.Pool,
		VMIDs:       vmids,
		Exclude:     exclude,
		Node:        r.Node,
		Enabled:     bool(enabled),
		NotesLength: len(r.Notes),
	}, nil
}

// flexBool unmarshals JSON true/false or 0/1. PVE renders booleans as
// integers in most endpoints and passes some through as JSON booleans.
type flexBool bool

// UnmarshalJSON implements json.Unmarshaler for the 0/1 and true/false
// shapes.
func (b *flexBool) UnmarshalJSON(raw []byte) error {
	switch strings.Trim(string(raw), " \t") {
	case "true", "1":
		*b = true
	case "false", "0":
		*b = false
	default:
		return errors.New("pveapi: expected boolean or 0/1")
	}
	return nil
}

var vmidListPattern = regexp.MustCompile(`^[0-9]+(?:[ \t]*[,;][ \t]*[0-9]+|[ \t]+[0-9]+)*$`)

func parseVMIDList(raw string) ([]uint64, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > maxVMIDListBytes || !vmidListPattern.MatchString(raw) {
		return nil, errors.New("invalid guest list")
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' })
	if len(parts) > maxVMIDsPerJob {
		return nil, errors.New("too many guest IDs")
	}
	ids := make([]uint64, 0, len(parts))
	for _, part := range parts {
		id, err := strconv.ParseUint(part, 10, 64)
		if err != nil || id == 0 || id >= maxVMID {
			return nil, errors.New("invalid guest ID")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// validateOptions checks every caller-supplied value before any I/O and
// returns the de-duplicated source list in stable order.
func validateOptions(opts BackupsOptions) ([]BackupSource, error) {
	sources := make([]BackupSource, 0, len(opts.Sources))
	seen := make(map[BackupSource]struct{}, len(opts.Sources))
	for _, s := range opts.Sources {
		if !validSlug(s.Node) {
			return nil, errors.New("pveapi: invalid node name")
		}
		if !validSlug(s.Storage) {
			return nil, errors.New("pveapi: invalid storage name")
		}
		if s.Type == "" || !validPrintable(s.Type, maxFieldBytes) {
			return nil, errors.New("pveapi: invalid storage type")
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		sources = append(sources, s)
	}
	for _, t := range opts.Tasks {
		if !validSlug(t.Node) {
			return nil, errors.New("pveapi: task: invalid node name")
		}
		if !validPrintable(t.Actor, maxActorBytes) {
			return nil, errors.New("pveapi: task: invalid actor")
		}
		if !validPrintable(t.Type, maxFieldBytes) {
			return nil, errors.New("pveapi: task: invalid type")
		}
		if !validPrintable(t.Target, maxTargetBytes) {
			return nil, errors.New("pveapi: task: invalid target")
		}
		if t.VMID != 0 && t.VMID >= maxVMID {
			return nil, errors.New("pveapi: task: invalid vmid")
		}
		if t.StartedUnix < 0 || t.StartedUnix > maxCTimeUnix ||
			t.FinishedUnix < 0 || t.FinishedUnix > maxCTimeUnix {
			return nil, errors.New("pveapi: task: invalid timestamps")
		}
		if t.StartedUnix > 0 && t.FinishedUnix > 0 && t.FinishedUnix < t.StartedUnix {
			return nil, errors.New("pveapi: task: finished before start")
		}
		if !validText(t.ExitStatus, maxExitStatusBytes) {
			return nil, errors.New("pveapi: task: invalid exit status")
		}
	}
	for name, members := range opts.Pools {
		if !validSlug(name) {
			return nil, errors.New("pveapi: invalid pool name")
		}
		for vmid := range members {
			if vmid == 0 || vmid >= maxVMID {
				return nil, errors.New("pveapi: invalid pool member vmid")
			}
		}
	}
	for vmid, node := range opts.GuestNodes {
		if vmid == 0 || vmid >= maxVMID || !validSlug(node) {
			return nil, errors.New("pveapi: invalid guest node mapping")
		}
	}
	return sources, nil
}

// correlationBudget bounds aggregate scanning, records and encoded output.
// Remaining counters avoid overflow when checking hostile aggregate sizes.
type correlationBudget struct {
	work, records, bytes int
}

func (b *correlationBudget) useWork(n int) error {
	if n > b.work {
		return errors.New("pveapi: correlation work limit exceeded")
	}
	b.work -= n
	return nil
}

func (b *correlationBudget) reserveRecord(size int) error {
	if b.records == 0 {
		return errors.New("pveapi: correlation record limit exceeded")
	}
	if size > b.bytes {
		return errors.New("pveapi: correlation output limit exceeded")
	}
	b.records--
	b.bytes -= size
	return nil
}

func (b *correlationBudget) evidence(e BackupEvidence) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("pveapi: size correlation evidence: %w", err)
	}
	return b.reserveRecord(len(raw) + 1) // include the array separator
}

// correlate builds the per-guest evidence from the three datasets. Every
// enumeration and coverage scan consumes work, and every record is reserved
// before appending it. Limit failures discard the entire observation.
func correlate(catalog Dataset[[]CatalogEntry], jobs Dataset[[]BackupJob], tasks []TaskSummary, pools map[string]map[uint64]bool, guestNodes map[uint64]string) ([]GuestBackups, error) {
	budget := correlationBudget{work: maxCorrelationWork, records: maxCorrelatedRecords, bytes: maxCorrelationOutputBytes}
	vmids := make(map[uint64]struct{})
	addVMID := func(id uint64) error {
		if _, ok := vmids[id]; ok {
			return nil
		}
		// This bounds the guest object and dataset wrappers, including
		// unavailable reasons, independently of the nested records.
		const guestOverheadBytes = 1024
		if err := budget.reserveRecord(guestOverheadBytes); err != nil {
			return err
		}
		vmids[id] = struct{}{}
		return nil
	}
	if err := budget.useWork(len(guestNodes)); err != nil {
		return nil, err
	}
	for id := range guestNodes {
		if err := addVMID(id); err != nil {
			return nil, err
		}
	}
	catalogByVMID := make(map[uint64][]BackupEvidence)
	if catalog.IsAvailable() {
		if err := budget.useWork(len(catalog.Value)); err != nil {
			return nil, err
		}
		for _, e := range catalog.Value {
			if err := addVMID(e.VMID); err != nil {
				return nil, err
			}
			ev := catalogEvidence(e)
			if err := budget.evidence(ev); err != nil {
				return nil, err
			}
			catalogByVMID[e.VMID] = append(catalogByVMID[e.VMID], ev)
		}
	}
	var tasksByVMID map[uint64][]BackupEvidence
	if tasks != nil {
		if err := budget.useWork(len(tasks)); err != nil {
			return nil, err
		}
		tasksByVMID = make(map[uint64][]BackupEvidence)
		for _, t := range tasks {
			if (t.Type != "backup" && t.Type != "vzdump") || t.VMID == 0 {
				continue
			}
			if err := addVMID(t.VMID); err != nil {
				return nil, err
			}
			ev, complete := taskEvidence(t)
			if !complete {
				continue
			}
			if err := budget.evidence(ev); err != nil {
				return nil, err
			}
			tasksByVMID[t.VMID] = append(tasksByVMID[t.VMID], ev)
		}
	}
	var jobBytes []int
	if jobs.IsAvailable() {
		if err := budget.useWork(len(jobs.Value)); err != nil {
			return nil, err
		}
		jobBytes = make([]int, len(jobs.Value))
		for i, j := range jobs.Value {
			if err := budget.useWork(len(j.VMIDs) + len(j.Exclude)); err != nil {
				return nil, err
			}
			encoded, err := json.Marshal(j)
			if err != nil {
				return nil, fmt.Errorf("pveapi: size correlation job: %w", err)
			}
			jobBytes[i] = len(encoded) + 1
			if !j.Enabled {
				continue
			}
			if j.Pool != "" {
				if err := budget.useWork(len(pools[j.Pool])); err != nil {
					return nil, err
				}
				for vmid, member := range pools[j.Pool] {
					if member {
						if err := addVMID(vmid); err != nil {
							return nil, err
						}
					}
				}
			} else if !j.All {
				for _, id := range j.VMIDs {
					if err := addVMID(id); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	ids := make([]uint64, 0, len(vmids))
	for id := range vmids {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	guests := make([]GuestBackups, 0, len(ids))
	for _, id := range ids {
		g := GuestBackups{VMID: id}
		if catalog.IsAvailable() {
			evs := catalogByVMID[id]
			if evs == nil {
				evs = []BackupEvidence{}
			}
			g.Catalog = AvailableDataset(evs)
		} else {
			g.Catalog = UnavailableDataset[[]BackupEvidence](catalog.Reason)
		}
		if tasksByVMID == nil {
			g.Tasks = UnavailableDataset[[]BackupEvidence](ReasonNoTasks)
		} else {
			evs := tasksByVMID[id]
			if evs == nil {
				evs = []BackupEvidence{}
			}
			g.Tasks = AvailableDataset(evs)
		}
		if jobs.IsAvailable() {
			var cov []BackupJob
			for i, j := range jobs.Value {
				if err := budget.useWork(1 + len(j.VMIDs) + len(j.Exclude)); err != nil {
					return nil, err
				}
				if j.coversGuest(id, guestNodes[id], pools) {
					if err := budget.reserveRecord(jobBytes[i]); err != nil {
						return nil, err
					}
					cov = append(cov, j)
				}
			}
			if cov == nil {
				cov = []BackupJob{}
			}
			g.Jobs = AvailableDataset(cov)
		} else {
			g.Jobs = UnavailableDataset[[]BackupJob](jobs.Reason)
		}
		guests = append(guests, g)
	}
	return guests, nil
}

// catalogEvidence converts a catalog entry into guest backup evidence.
func catalogEvidence(e CatalogEntry) BackupEvidence {
	status := StatusCatalog
	if e.Source == SourcePBS && e.Verified == TriYes {
		status = StatusVerified
	}
	return BackupEvidence{
		Source:       e.Source,
		Kind:         KindCatalog,
		Status:       status,
		Name:         e.VolID,
		FinishedUnix: e.CTimeUnix,
		Verified:     e.Verified,
	}
}

// taskEvidence converts a task summary into guest backup evidence. PVE
// backup tasks are vzdump runs regardless of destination storage.
func taskEvidence(t TaskSummary) (BackupEvidence, bool) {
	if t.ExitStatus == "" || t.StartedUnix <= 0 || t.FinishedUnix <= 0 ||
		t.FinishedUnix < t.StartedUnix || t.FinishedUnix > maxCTimeUnix {
		return BackupEvidence{}, false
	}
	status := StatusFailed
	if t.ExitStatus == TaskExitOK {
		status = StatusSuccess
	}
	return BackupEvidence{
		Source:       SourceVZDump,
		Kind:         KindTask,
		Status:       status,
		Name:         t.Target,
		StartedUnix:  t.StartedUnix,
		FinishedUnix: t.FinishedUnix,
		Verified:     TriUnknown,
	}, true
}

// validSlug reports whether s is a PVE node/storage/pool name: 1..64 bytes
// of [A-Za-z0-9_-].
func validSlug(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case b == '-' || b == '_':
		default:
			return false
		}
	}
	return true
}

// validPrintable reports whether s is at most max bytes of printable ASCII
// (0x21..0x7e). Empty is allowed.
func validPrintable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

// validText reports whether s is at most max bytes of printable ASCII
// including space (0x20..0x7e). Empty is allowed. Used for free-form
// status messages such as task ExitStatus ("CRITICAL: disk full").
func validText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

// validVolid reports whether s is a plausible PVE volume ID: at most
// maxVolidBytes of [A-Za-z0-9_.:/-] (storage:content/name).
func validVolid(s string) bool {
	if len(s) == 0 || len(s) > maxVolidBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case b == '-' || b == '_' || b == '.' || b == ':' || b == '/':
		default:
			return false
		}
	}
	return true
}

// validatePath reports whether p is a safe API path: 1..maxPathBytes of
// printable ASCII starting with '/'.
func validatePath(p string) error {
	if len(p) == 0 || len(p) > maxPathBytes || p[0] != '/' {
		return errors.New("pveapi: invalid path")
	}
	for i := 0; i < len(p); i++ {
		if b := p[i]; b < 0x21 || b > 0x7e {
			return errors.New("pveapi: invalid path")
		}
	}
	return nil
}
