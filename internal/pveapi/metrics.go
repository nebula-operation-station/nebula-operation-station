// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed, read-only client for the Proxmox VE API
// (ADR 0006). It performs status and RRD metric reads only and never
// calls mutation endpoints. It holds no credentials: the HTTP client,
// the base URL and the auth header supplier are injected by the caller.
//
// Every PVE response is untrusted input: bodies are size-limited,
// decoded against explicit schemas and range-validated. Headers and
// bodies are never logged and never appear in error messages. An
// unavailable endpoint (network failure, timeout, HTTP error status)
// is reported as an error and is distinct from an empty successful
// response.
package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// TODO(pvecontract): replace the local normalized types with
// internal/pvecontract once P1-02 (contracts, branch
// agent/p102-pve-contracts) lands on main; keep the normalization rules.

// Sentinel errors. Callers branch on these with errors.Is.
var (
	// ErrBadParam marks a rejected request parameter (node name, vmid,
	// guest kind, timeframe). No HTTP request is sent.
	ErrBadParam = errors.New("pveapi: invalid request parameter")
	// ErrUnavailable marks a failed PVE request: network error,
	// per-call timeout, or a non-200 HTTP status. It is distinct from
	// an empty successful response (which is not an error).
	ErrUnavailable = errors.New("pveapi: endpoint unavailable")
	// ErrInvalidRange marks a PVE response whose value is outside its
	// valid domain (for example a CPU fraction above 1 or negative
	// byte counts). The response is rejected, not partially used.
	ErrInvalidRange = errors.New("pveapi: response value out of range")
	// ErrTooLarge marks a response body exceeding the configured size
	// limit.
	ErrTooLarge = errors.New("pveapi: response too large")
)

// GuestKind identifies the guest type segment of a PVE API path.
type GuestKind string

// The two guest types with status/RRD endpoints.
const (
	KindQEMU GuestKind = "qemu"
	KindLXC  GuestKind = "lxc"
)

// Timeframe selects the resolution of an RRD read. PVE serves the
// AVERAGE rrd sets: hour gives one-minute points, day five-minute points.
type Timeframe string

// The timeframes this client supports (ADR 0006 P1-21).
const (
	TimeframeHour Timeframe = "hour"
	TimeframeDay  Timeframe = "day"
)

// AuthHeaderSupplier returns the name and value of the HTTP header that
// authenticates a PVE API request (for example "Authorization" with a
// PVEAPIToken value). The value is a secret: implementations and callers
// must never log it or put it into errors.
type AuthHeaderSupplier func(ctx context.Context) (name, value string, err error)

// MetricsClient is a typed, read-only client for the PVE status and RRD
// metric endpoints. It is safe for concurrent use.
type MetricsClient struct {
	base    string
	http    *http.Client
	auth    AuthHeaderSupplier
	maxBody int64
	timeout time.Duration
}

// Option configures a MetricsClient.
type Option func(*MetricsClient)

// defaultMaxBody is 1 MiB: a day of node RRD points (288 five-minute
// samples) is far below this, while it still bounds untrusted input.
const defaultMaxBody int64 = 1 << 20

// defaultTimeout bounds every single PVE call.
const defaultTimeout = 10 * time.Second

// WithMaxResponseBytes sets the maximum accepted response body size.
// Values below 1 KiB are rejected by the constructor.
func WithMaxResponseBytes(n int64) Option {
	return func(c *MetricsClient) { c.maxBody = n }
}

// WithPerCallTimeout sets the per-call timeout. Values below 1 ms are
// rejected by the constructor.
func WithPerCallTimeout(d time.Duration) Option {
	return func(c *MetricsClient) { c.timeout = d }
}

// NewMetricsClient builds a MetricsClient. base is the PVE API root,
// for example "https://pve.example.lan:8006/api2/json". It must be an
// absolute http(s) URL without user info: credentials never follow API
// URLs (ADR 0006). hc must not be nil.
func NewMetricsClient(base string, hc *http.Client, auth AuthHeaderSupplier, opts ...Option) (*MetricsClient, error) {
	if hc == nil {
		return nil, fmt.Errorf("%w: nil http client", ErrBadParam)
	}
	if auth == nil {
		return nil, fmt.Errorf("%w: nil auth header supplier", ErrBadParam)
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("%w: base URL: %v", ErrBadParam, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: base URL scheme %q", ErrBadParam, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: base URL has no host", ErrBadParam)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: base URL must not carry user info", ErrBadParam)
	}
	c := &MetricsClient{
		base:    strings.TrimRight(base, "/"),
		http:    hc,
		auth:    auth,
		maxBody: defaultMaxBody,
		timeout: defaultTimeout,
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.maxBody < 1024 {
		return nil, fmt.Errorf("%w: max response bytes %d below 1 KiB", ErrBadParam, c.maxBody)
	}
	if c.timeout < time.Millisecond {
		return nil, fmt.Errorf("%w: per-call timeout %s below 1 ms", ErrBadParam, c.timeout)
	}
	return c, nil
}

// nodeRe accepts PVE node names (hostnames) and rejects anything that
// could escape the /nodes/{node} path segment.
var nodeRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$`)

func validNode(node string) bool {
	return nodeRe.MatchString(node)
}

func (k GuestKind) valid() bool {
	return k == KindQEMU || k == KindLXC
}

func (t Timeframe) valid() bool {
	return t == TimeframeHour || t == TimeframeDay
}

// doGet performs one bounded GET against the PVE API. The returned body
// is at most c.maxBody bytes. Errors wrap ErrBadParam (no request sent),
// ErrUnavailable (request failed) or ErrTooLarge (body oversize). Error
// messages never contain headers or response bodies.
func (c *MetricsClient) doGet(ctx context.Context, endpointPath string, query url.Values) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	u, err := url.Parse(c.base)
	if err != nil { // unreachable: base validated in the constructor
		return nil, fmt.Errorf("%w: base URL: %v", ErrBadParam, err)
	}
	u.Path = path.Join(u.Path, endpointPath)
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadParam, endpointPath)
	}
	name, value, err := c.auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, endpointPath)
	}
	if name != "" {
		req.Header.Set(name, value)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// err may name the URL (not a secret) and the transport reason;
		// headers are never part of it.
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, endpointPath)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain and discard: the body is untrusted and never surfaced.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("%w: %s: status %d", ErrUnavailable, endpointPath, resp.StatusCode)
	}

	body, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, c.maxBody))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, fmt.Errorf("%w: %s", ErrTooLarge, endpointPath)
		}
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, endpointPath)
	}
	return body, nil
}

// unmarshalData decodes a PVE {"data": ...} envelope. Malformed bodies
// are untrusted input and are rejected with ErrInvalidRange; the raw
// body never appears in the error.
func unmarshalData[T any](body []byte, endpointPath string) (T, error) {
	var zero T
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return zero, fmt.Errorf("%w: %s", ErrInvalidRange, endpointPath)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return zero, fmt.Errorf("%w: %s: missing data", ErrInvalidRange, endpointPath)
	}
	if err := json.Unmarshal(env.Data, &zero); err != nil {
		return zero, fmt.Errorf("%w: %s", ErrInvalidRange, endpointPath)
	}
	return zero, nil
}

// --- raw response shapes (PVE 8 and 9; unknown fields are ignored) ---

// nodeStatusRaw is the data object of GET /nodes/{node}/status.
type nodeStatusRaw struct {
	CPU       *float64    `json:"cpu"`
	DiskRead  *int64      `json:"diskread"`
	DiskWrite *int64      `json:"diskwrite"`
	Memory    *nodeMemRaw `json:"memory"`
	NetIn     *int64      `json:"netin"`
	NetOut    *int64      `json:"netout"`
	Status    *string     `json:"status"`
	// Note: the node status "disk" object (used/total bytes) is PVE
	// storage allocation, not filesystem usage, so it is deliberately
	// not part of the normalized NodeMetrics (ADR 0006).
}

// nodeMemRaw is the node status memory object (bytes).
type nodeMemRaw struct {
	Used  *int64 `json:"used"`
	Total *int64 `json:"total"`
}

// guestStatusRaw is the data object of
// GET /nodes/{node}/{qemu|lxc}/{vmid}/status/current.
type guestStatusRaw struct {
	CPU       *float64 `json:"cpu"`
	DiskRead  *int64   `json:"diskread"`
	DiskWrite *int64   `json:"diskwrite"`
	Mem       *int64   `json:"mem"`
	MaxMem    *int64   `json:"maxmem"`
	MaxDisk   *int64   `json:"maxdisk"`
	NetIn     *int64   `json:"netin"`
	NetOut    *int64   `json:"netout"`
	Status    *string  `json:"status"`
}

// --- normalized types ---

// NodeMetrics is the normalized current status of a PVE node.
//
// Every metric is a pointer: nil means "PVE did not report it" (missing
// stays missing, it is never filled with zero). CPU is a fraction in
// [0,1]; memory is in bytes; disk and net rates are in bytes per second.
type NodeMetrics struct {
	Node      string
	Status    string // raw PVE status, for example "online"
	CPU       *float64
	MemUsed   *int64
	MemTotal  *int64
	DiskRead  *int64
	DiskWrite *int64
	NetIn     *int64
	NetOut    *int64
}

// GuestMetrics is the normalized current status of a QEMU or LXC guest.
// Missing fields stay nil, as in NodeMetrics.
type GuestMetrics struct {
	Node      string
	Kind      GuestKind
	VMID      int
	Status    string // raw PVE status, for example "running" or "stopped"
	CPU       *float64
	MemUsed   *int64
	MemTotal  *int64
	DiskRead  *int64
	DiskWrite *int64
	NetIn     *int64
	NetOut    *int64
	// DiskAllocated is the guest's configured PVE disk size in bytes
	// (PVE "maxdisk"). It is an ALLOCATION, not filesystem usage: it
	// must never be rendered as a DISK usage percentage or bar.
	// Filesystem utilization is a separate data path (the SSH
	// filesystem.list observation, ADR 0006) and is not part of this
	// type on purpose.
	DiskAllocated *int64
}

// --- range validation ---

// checkCPU validates a CPU fraction: it must be in [0,1].
func checkCPU(endpointPath string, field string, v *float64) error {
	if v == nil {
		return nil
	}
	if *v < 0 || *v > 1 {
		return fmt.Errorf("%w: %s: %s=%g outside [0,1]", ErrInvalidRange, endpointPath, field, *v)
	}
	return nil
}

// checkBytes validates a non-negative byte count or rate.
func checkBytes(endpointPath string, field string, v *int64) error {
	if v == nil {
		return nil
	}
	if *v < 0 {
		return fmt.Errorf("%w: %s: %s=%d negative", ErrInvalidRange, endpointPath, field, *v)
	}
	return nil
}

func checkStatusString(field string, v *string) (string, error) {
	if v == nil {
		return "", nil
	}
	s := *v
	// PVE status strings are short ASCII tokens; bound and validate
	// them before they leave this package.
	if len(s) == 0 || len(s) > 32 {
		return "", fmt.Errorf("%w: %s: invalid length", ErrInvalidRange, field)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "", fmt.Errorf("%w: %s: invalid character %q", ErrInvalidRange, field, c)
		}
	}
	return s, nil
}

// --- status endpoints ---

// NodeStatus reads and normalizes GET /nodes/{node}/status (PVE 8 and 9
// shapes). A failed request returns an error wrapping ErrUnavailable; a
// response with out-of-domain values returns ErrInvalidRange.
func (c *MetricsClient) NodeStatus(ctx context.Context, node string) (NodeMetrics, error) {
	var zero NodeMetrics
	if !validNode(node) {
		return zero, fmt.Errorf("%w: node %q", ErrBadParam, node)
	}
	endpointPath := "/nodes/" + node + "/status"
	body, err := c.doGet(ctx, endpointPath, nil)
	if err != nil {
		return zero, err
	}
	raw, err := unmarshalData[nodeStatusRaw](body, endpointPath)
	if err != nil {
		return zero, err
	}
	if err := checkCPU(endpointPath, "cpu", raw.CPU); err != nil {
		return zero, err
	}
	if raw.Memory != nil {
		if err := checkBytes(endpointPath, "memory.used", raw.Memory.Used); err != nil {
			return zero, err
		}
		if err := checkBytes(endpointPath, "memory.total", raw.Memory.Total); err != nil {
			return zero, err
		}
	}
	for field, v := range map[string]*int64{
		"diskread":  raw.DiskRead,
		"diskwrite": raw.DiskWrite,
		"netin":     raw.NetIn,
		"netout":    raw.NetOut,
	} {
		if err := checkBytes(endpointPath, field, v); err != nil {
			return zero, err
		}
	}
	status, err := checkStatusString("status", raw.Status)
	if err != nil {
		return zero, err
	}
	m := NodeMetrics{Node: node, Status: status, CPU: raw.CPU}
	if raw.Memory != nil {
		m.MemUsed = raw.Memory.Used
		m.MemTotal = raw.Memory.Total
	}
	m.DiskRead = raw.DiskRead
	m.DiskWrite = raw.DiskWrite
	m.NetIn = raw.NetIn
	m.NetOut = raw.NetOut
	return m, nil
}

// GuestStatus reads and normalizes
// GET /nodes/{node}/{qemu|lxc}/{vmid}/status/current (PVE 8 and 9
// shapes). A stopped guest typically reports only "status": all metric
// fields then stay nil (missing), which is not an error.
func (c *MetricsClient) GuestStatus(ctx context.Context, node string, kind GuestKind, vmid int) (GuestMetrics, error) {
	var zero GuestMetrics
	if !validNode(node) {
		return zero, fmt.Errorf("%w: node %q", ErrBadParam, node)
	}
	if !kind.valid() {
		return zero, fmt.Errorf("%w: guest kind %q", ErrBadParam, kind)
	}
	if vmid <= 0 {
		return zero, fmt.Errorf("%w: vmid %d", ErrBadParam, vmid)
	}
	endpointPath := fmt.Sprintf("/nodes/%s/%s/%d/status/current", node, kind, vmid)
	body, err := c.doGet(ctx, endpointPath, nil)
	if err != nil {
		return zero, err
	}
	raw, err := unmarshalData[guestStatusRaw](body, endpointPath)
	if err != nil {
		return zero, err
	}
	if err := checkCPU(endpointPath, "cpu", raw.CPU); err != nil {
		return zero, err
	}
	for field, v := range map[string]*int64{
		"mem":       raw.Mem,
		"maxmem":    raw.MaxMem,
		"maxdisk":   raw.MaxDisk,
		"diskread":  raw.DiskRead,
		"diskwrite": raw.DiskWrite,
		"netin":     raw.NetIn,
		"netout":    raw.NetOut,
	} {
		if err := checkBytes(endpointPath, field, v); err != nil {
			return zero, err
		}
	}
	status, err := checkStatusString("status", raw.Status)
	if err != nil {
		return zero, err
	}
	m := GuestMetrics{
		Node: node, Kind: kind, VMID: vmid,
		Status:        status,
		CPU:           raw.CPU,
		MemUsed:       raw.Mem,
		MemTotal:      raw.MaxMem,
		DiskRead:      raw.DiskRead,
		DiskWrite:     raw.DiskWrite,
		NetIn:         raw.NetIn,
		NetOut:        raw.NetOut,
		DiskAllocated: raw.MaxDisk,
	}
	return m, nil
}

// --- RRD endpoints ---

// nodeRRDPointRaw is one point of GET /nodes/{node}/rrddata.
// PVE node RRD "mem" is a FRACTION of total memory (0..1), unlike guest
// RRD where "mem" is bytes.
type nodeRRDPointRaw struct {
	Time      *int64   `json:"time"`
	CPU       *float64 `json:"cpu"`
	Mem       *float64 `json:"mem"`
	DiskRead  *int64   `json:"diskread"`
	DiskWrite *int64   `json:"diskwrite"`
	NetIn     *int64   `json:"netin"`
	NetOut    *int64   `json:"netout"`
}

// guestRRDPointRaw is one point of
// GET /nodes/{node}/{qemu|lxc}/{vmid}/rrddata. "mem" and "maxmem" are
// bytes.
type guestRRDPointRaw struct {
	Time      *int64   `json:"time"`
	CPU       *float64 `json:"cpu"`
	Mem       *int64   `json:"mem"`
	MaxMem    *int64   `json:"maxmem"`
	DiskRead  *int64   `json:"diskread"`
	DiskWrite *int64   `json:"diskwrite"`
	NetIn     *int64   `json:"netin"`
	NetOut    *int64   `json:"netout"`
}

// RRDPoint is one normalized PVE RRD sample from the AVERAGE sets.
// Missing fields stay nil; a missing point is never filled with zero.
// CPU is a fraction in [0,1]; memory is in bytes; disk and net rates
// are in bytes per second.
type RRDPoint struct {
	Time      time.Time // unix seconds of the sample
	CPU       *float64
	MemUsed   *int64
	MemTotal  *int64
	DiskRead  *int64
	DiskWrite *int64
	NetIn     *int64
	NetOut    *int64
}

func (p nodeRRDPointRaw) validate(endpointPath string, i int) error {
	if p.Time == nil {
		return fmt.Errorf("%w: %s: point[%d] missing time", ErrInvalidRange, endpointPath, i)
	}
	if err := checkCPU(endpointPath, fmt.Sprintf("point[%d].cpu", i), p.CPU); err != nil {
		return err
	}
	if p.Mem != nil && (*p.Mem < 0 || *p.Mem > 1) {
		return fmt.Errorf("%w: %s: point[%d].mem=%g outside [0,1]", ErrInvalidRange, endpointPath, i, *p.Mem)
	}
	for field, v := range map[string]*int64{
		"diskread":  p.DiskRead,
		"diskwrite": p.DiskWrite,
		"netin":     p.NetIn,
		"netout":    p.NetOut,
	} {
		if err := checkBytes(endpointPath, fmt.Sprintf("point[%d].%s", i, field), v); err != nil {
			return err
		}
	}
	return nil
}

func (p guestRRDPointRaw) validate(endpointPath string, i int) error {
	if p.Time == nil {
		return fmt.Errorf("%w: %s: point[%d] missing time", ErrInvalidRange, endpointPath, i)
	}
	if err := checkCPU(endpointPath, fmt.Sprintf("point[%d].cpu", i), p.CPU); err != nil {
		return err
	}
	for field, v := range map[string]*int64{
		"mem":       p.Mem,
		"maxmem":    p.MaxMem,
		"diskread":  p.DiskRead,
		"diskwrite": p.DiskWrite,
		"netin":     p.NetIn,
		"netout":    p.NetOut,
	} {
		if err := checkBytes(endpointPath, fmt.Sprintf("point[%d].%s", i, field), v); err != nil {
			return err
		}
	}
	return nil
}

// NodeRRDData reads and normalizes GET /nodes/{node}/rrddata for the
// given timeframe (hour or day, AVERAGE sets). memTotalBytes is the
// node's total memory in bytes (from NodeStatus); it converts PVE's
// fractional node RRD "mem" values into used bytes. If it is not
// positive, MemUsed stays nil rather than being guessed.
//
// A successful response with no points returns an empty slice, not an
// error (empty is distinct from unavailable).
func (c *MetricsClient) NodeRRDData(ctx context.Context, node string, tf Timeframe, memTotalBytes int64) ([]RRDPoint, error) {
	if !validNode(node) {
		return nil, fmt.Errorf("%w: node %q", ErrBadParam, node)
	}
	if !tf.valid() {
		return nil, fmt.Errorf("%w: timeframe %q", ErrBadParam, tf)
	}
	if memTotalBytes < 0 {
		return nil, fmt.Errorf("%w: memTotalBytes %d", ErrBadParam, memTotalBytes)
	}
	endpointPath := "/nodes/" + node + "/rrddata"
	q := url.Values{"timeframe": {string(tf)}}
	body, err := c.doGet(ctx, endpointPath, q)
	if err != nil {
		return nil, err
	}
	raws, err := unmarshalData[[]nodeRRDPointRaw](body, endpointPath)
	if err != nil {
		return nil, err
	}
	points := make([]RRDPoint, 0, len(raws))
	for i, r := range raws {
		if err := r.validate(endpointPath, i); err != nil {
			return nil, err
		}
		p := RRDPoint{
			CPU:       r.CPU,
			DiskRead:  r.DiskRead,
			DiskWrite: r.DiskWrite,
			NetIn:     r.NetIn,
			NetOut:    r.NetOut,
		}
		if r.Time != nil {
			p.Time = time.Unix(*r.Time, 0).UTC()
		}
		if r.Mem != nil && memTotalBytes > 0 {
			used := int64(*r.Mem * float64(memTotalBytes))
			p.MemUsed = &used
		}
		if memTotalBytes > 0 {
			total := memTotalBytes
			p.MemTotal = &total
		}
		points = append(points, p)
	}
	return points, nil
}

// GuestRRDData reads and normalizes
// GET /nodes/{node}/{qemu|lxc}/{vmid}/rrddata for the given timeframe
// (hour or day, AVERAGE sets). Guest RRD "mem" is already bytes.
//
// A successful response with no points returns an empty slice, not an
// error (empty is distinct from unavailable).
func (c *MetricsClient) GuestRRDData(ctx context.Context, node string, kind GuestKind, vmid int, tf Timeframe) ([]RRDPoint, error) {
	if !validNode(node) {
		return nil, fmt.Errorf("%w: node %q", ErrBadParam, node)
	}
	if !kind.valid() {
		return nil, fmt.Errorf("%w: guest kind %q", ErrBadParam, kind)
	}
	if vmid <= 0 {
		return nil, fmt.Errorf("%w: vmid %d", ErrBadParam, vmid)
	}
	if !tf.valid() {
		return nil, fmt.Errorf("%w: timeframe %q", ErrBadParam, tf)
	}
	endpointPath := fmt.Sprintf("/nodes/%s/%s/%d/rrddata", node, kind, vmid)
	q := url.Values{"timeframe": {string(tf)}}
	body, err := c.doGet(ctx, endpointPath, q)
	if err != nil {
		return nil, err
	}
	raws, err := unmarshalData[[]guestRRDPointRaw](body, endpointPath)
	if err != nil {
		return nil, err
	}
	points := make([]RRDPoint, 0, len(raws))
	for i, r := range raws {
		if err := r.validate(endpointPath, i); err != nil {
			return nil, err
		}
		p := RRDPoint{
			CPU:       r.CPU,
			MemUsed:   r.Mem,
			MemTotal:  r.MaxMem,
			DiskRead:  r.DiskRead,
			DiskWrite: r.DiskWrite,
			NetIn:     r.NetIn,
			NetOut:    r.NetOut,
		}
		if r.Time != nil {
			p.Time = time.Unix(*r.Time, 0).UTC()
		}
		points = append(points, p)
	}
	return points, nil
}
