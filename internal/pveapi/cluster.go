// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed, read-only client for the Proxmox VE API
// (ADR 0006, ticket P1-19). It reads cluster status, HA state and bounded
// per-node task metadata. It exposes no mutation endpoints and no executor
// or server wiring.
//
// Every response is untrusted input: response size limits, UTF-8 checks and
// explicit schemas apply, unknown fields are dropped, and "unavailable"
// (endpoint missing, unreachable, or the service not enabled) is kept
// distinct from "empty" (a valid response with no entries). The client
// never logs request headers or response bodies, and error messages never
// contain response content.
package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits, named next to the code that enforces them (ADR 0006 response
// budget: 1 MiB decoded per response, 1,000 objects per page, 4 KiB per
// text field).
const (
	// DefaultTimeout is the per-call request timeout (ADR 0006: 30 s).
	DefaultTimeout = 30 * time.Second
	// DefaultMaxBody is the maximum decoded response size (ADR 0006: 1 MiB).
	DefaultMaxBody = 1 << 20
	// MaxTaskLimit is the maximum number of task summaries one call returns.
	MaxTaskLimit = 500
	// maxHAObjects bounds HA objects in one response (1,000 objects per
	// page).
	maxHAObjects = 1000
	// maxClusterNodes bounds a plausible cluster node count.
	maxClusterNodes = 1000
	// maxVMID bounds a plausible PVE VMID.
	maxVMID = 999999999
	// maxTextLen is the maximum length of one text field (4 KiB).
	maxTextLen = 4096
	// maxStartUnix bounds a plausible UPID start time (year 2100).
	maxStartUnix = 4102444800
)

// reasonNotFound is the availability reason for an endpoint that does not
// exist on the remote (standalone cluster, HA not enabled, unknown node).
const reasonNotFound = "endpoint not found"

var (
	// ErrMalformed is returned when a response violates its schema, size or
	// text limits. The error never contains response content.
	ErrMalformed = errors.New("pveapi: malformed response")
)

// clusterGet performs one GET against base+path. It returns the raw body, or a
// non-empty reason when the dataset is unavailable (transport failure,
// timeout, 404, non-2xx). It never includes headers or bodies in the
// reason or in a returned error.
func (c *Client) clusterGet(ctx context.Context, path string) ([]byte, string, error) {
	if c.HTTP == nil || c.BaseURL == "" || c.Token == nil {
		return nil, "", errors.New("pveapi: incomplete client")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	token, err := c.Token(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("pveapi: token supplier: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err != nil {
		return nil, "", fmt.Errorf("pveapi: build request: %w", err)
	}
	req.Header.Set("Authorization", token)

	// Copy the injected client so its redirect policy is neither trusted nor
	// mutated. Credentials must never be sent to a redirected destination.
	httpClient := *c.HTTP
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, "request timed out", nil
		}
		return nil, "request failed", nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		if resp.StatusCode == http.StatusNotFound {
			return nil, reasonNotFound, nil
		}
		return nil, fmt.Sprintf("http status %d", resp.StatusCode), nil
	}

	maxBody := c.MaxBody
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, "response read failed", nil
	}
	if int64(len(body)) > maxBody {
		return nil, "", fmt.Errorf("%w: response exceeds %d bytes", ErrMalformed, maxBody)
	}
	return body, "", nil
}

// decodeData decodes the PVE JSON envelope {"data": ...} and returns the
// data value. A null or missing data is malformed.
func decodeData[T any](body []byte) (*T, error) {
	// encoding/json replaces invalid UTF-8, so validate the original bytes.
	if !utf8.Valid(body) {
		return nil, fmt.Errorf("%w: response is not valid utf-8", ErrMalformed)
	}
	var env struct {
		Data *T `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("%w: invalid json", ErrMalformed)
	}
	if env.Data == nil {
		return nil, fmt.Errorf("%w: missing data", ErrMalformed)
	}
	return env.Data, nil
}

// checkText validates one untrusted text field: length and UTF-8.
func checkText(field, v string) (string, error) {
	if len(v) > maxTextLen {
		return "", fmt.Errorf("%w: field %s exceeds %d bytes", ErrMalformed, field, maxTextLen)
	}
	if !utf8.ValidString(v) {
		return "", fmt.Errorf("%w: field %s is not valid utf-8", ErrMalformed, field)
	}
	return v, nil
}

// ClusterStatus is a bounded summary of GET /cluster/status (ADR 0006:
// membership, votes/quorum). A standalone PVE host has no cluster entry:
// only node entries are returned and the result is Available=false, never
// an empty cluster with zero nodes.
type ClusterStatus struct {
	// Available reports whether the remote has a configured cluster.
	Available bool
	// Reason explains an unavailable result.
	Reason string
	// Name is the cluster name.
	Name string
	// Quorum reports whether the cluster currently has quorum.
	Quorum bool
	// NodesOnline is the number of online cluster nodes.
	NodesOnline int
	// NodesTotal is the total number of cluster nodes.
	NodesTotal int
	// Members lists the node entries in response order.
	Members []ClusterMember
}

// ClusterMember is one node entry of GET /cluster/status.
type ClusterMember struct {
	// Name is the node name.
	Name string
	// Online reports whether corosync sees the node online.
	Online bool
}

type clusterStatusEntry struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Nodes   *int   `json:"nodes"`
	Quorate *int   `json:"quorate"`
	Online  *int   `json:"online"`
}

// ClusterStatus reads GET /cluster/status.
func (c *Client) ClusterStatus(ctx context.Context) (ClusterStatus, error) {
	body, reason, err := c.clusterGet(ctx, "/cluster/status")
	if err != nil {
		return ClusterStatus{}, err
	}
	if body == nil {
		if reason == reasonNotFound {
			reason = "standalone host: no cluster configured"
		}
		return ClusterStatus{Reason: reason}, nil
	}
	entries, err := decodeData[[]clusterStatusEntry](body)
	if err != nil {
		return ClusterStatus{}, err
	}
	if len(*entries) > maxClusterNodes+1 {
		return ClusterStatus{}, fmt.Errorf("%w: too many cluster entries", ErrMalformed)
	}
	out := ClusterStatus{}
	for _, e := range *entries {
		if _, err := checkText("id", e.ID); err != nil {
			return ClusterStatus{}, err
		}
		name, err := checkText("name", e.Name)
		if err != nil {
			return ClusterStatus{}, err
		}
		switch e.Type {
		case "cluster":
			if out.Available || e.Nodes == nil || *e.Nodes < 0 || *e.Nodes > maxClusterNodes {
				return ClusterStatus{}, fmt.Errorf("%w: invalid cluster node count or duplicate cluster", ErrMalformed)
			}
			if e.Quorate == nil || (*e.Quorate != 0 && *e.Quorate != 1) {
				return ClusterStatus{}, fmt.Errorf("%w: quorate out of range", ErrMalformed)
			}
			out.Available = true
			out.Name = name
			out.NodesTotal = *e.Nodes
			out.Quorum = *e.Quorate == 1
		case "node":
			if e.Online == nil || (*e.Online != 0 && *e.Online != 1) {
				return ClusterStatus{}, fmt.Errorf("%w: online out of range", ErrMalformed)
			}
			out.NodesOnline += *e.Online
			out.Members = append(out.Members, ClusterMember{Name: name, Online: *e.Online == 1})
		default:
			return ClusterStatus{}, fmt.Errorf("%w: unknown cluster entry type", ErrMalformed)
		}
	}
	if !out.Available {
		return ClusterStatus{Reason: "standalone host: no cluster configured"}, nil
	}
	if out.NodesOnline > out.NodesTotal {
		return ClusterStatus{}, fmt.Errorf("%w: online nodes exceed total", ErrMalformed)
	}
	return out, nil
}

// HAStatus is a bounded summary of the HA manager state: the desired states
// from GET /cluster/ha/resources joined with the observed states from
// GET /cluster/ha/status/current, one entry per SID (ADR 0006: HA resource
// desired/observed states). A remote without HA has no HA endpoints: the
// result is Available=false, never an empty resource list.
type HAStatus struct {
	// Available reports whether the remote runs an HA manager.
	Available bool
	// Reason explains an unavailable result.
	Reason string
	// Resources is the HA state per VMID, in resource-list order.
	Resources []HAResource
}

// HAResource is the HA state of one VMID.
type HAResource struct {
	// VMID is the guest id.
	VMID int
	// Type is "vm" or "ct".
	Type string
	// Managed reports whether the resource is HA-managed.
	Managed bool
	// DesiredState is the configured top-level HA resource state.
	DesiredState string
	// State is the observed HA state, e.g. "started".
	State string
	// StateReason and StateReasonDetail explain the observed state.
	StateReason       string
	StateReasonDetail string
	// Node is the node the guest currently runs on (observed).
	Node string
	// StartAttempts and StartFailures count HA start attempts/failures.
	StartAttempts int
	StartFailures int
	// LastStateChange is when the observed state last changed; zero means
	// unknown.
	LastStateChange time.Time
	// LastStateChangeBy and LastStateChangeNode name the actor and node of
	// the last state change.
	LastStateChangeBy   string
	LastStateChangeNode string
}

type haResourceData struct {
	SID   string `json:"sid"`
	Type  string `json:"type"`
	State string `json:"state"`
}

type haStatusEntry struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	SID   string `json:"sid"`
	State string `json:"state"`
	Node  string `json:"node"`
}

// HAStatus reads GET /cluster/ha/resources and GET /cluster/ha/status/current
// and joins service entries by SID.
func (c *Client) HAStatus(ctx context.Context) (HAStatus, error) {
	resBody, resReason, err := c.clusterGet(ctx, "/cluster/ha/resources")
	if err != nil {
		return HAStatus{}, err
	}
	stBody, stReason, err := c.clusterGet(ctx, "/cluster/ha/status/current")
	if err != nil {
		return HAStatus{}, err
	}
	if resBody == nil || stBody == nil {
		reason := "HA not enabled"
		if resBody == nil && resReason != reasonNotFound {
			reason = resReason
		}
		if stBody == nil && stReason != reasonNotFound {
			reason = stReason
		}
		return HAStatus{Available: false, Reason: reason}, nil
	}

	resources, err := decodeData[[]haResourceData](resBody)
	if err != nil {
		return HAStatus{}, err
	}
	entries, err := decodeData[[]haStatusEntry](stBody)
	if err != nil {
		return HAStatus{}, err
	}
	if len(*resources) > maxHAObjects {
		return HAStatus{}, fmt.Errorf("%w: ha resources exceed %d objects", ErrMalformed, maxHAObjects)
	}
	if len(*entries) > maxHAObjects {
		return HAStatus{}, fmt.Errorf("%w: ha status exceeds %d objects", ErrMalformed, maxHAObjects)
	}

	observed := make(map[string]haStatusEntry, len(*entries))
	for _, e := range *entries {
		for field, value := range map[string]string{"id": e.ID, "type": e.Type, "sid": e.SID, "state": e.State, "node": e.Node} {
			if _, err := checkText(field, value); err != nil {
				return HAStatus{}, err
			}
		}
		if e.Type != "service" {
			continue
		}
		if _, _, err := haSID(e.SID); err != nil {
			return HAStatus{}, err
		}
		if e.ID != "service:"+e.SID {
			return HAStatus{}, fmt.Errorf("%w: inconsistent ha service id", ErrMalformed)
		}
		if _, exists := observed[e.SID]; exists {
			return HAStatus{}, fmt.Errorf("%w: duplicate ha service", ErrMalformed)
		}
		observed[e.SID] = e
	}

	out := HAStatus{Available: true}
	for _, r := range *resources {
		res, err := haResource(r, observed)
		if err != nil {
			return HAStatus{}, err
		}
		out.Resources = append(out.Resources, res)
	}
	return out, nil
}

// haSID validates the service type and VMID without conflating VM and CT IDs.
func haSID(sid string) (string, int, error) {
	if _, err := checkText("sid", sid); err != nil {
		return "", 0, err
	}
	typ, id, ok := strings.Cut(sid, ":")
	if !ok || (typ != "vm" && typ != "ct") || len(id) == 0 {
		return "", 0, fmt.Errorf("%w: invalid ha sid", ErrMalformed)
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return "", 0, fmt.Errorf("%w: invalid ha vmid", ErrMalformed)
		}
	}
	vmID, err := strconv.Atoi(id)
	if err != nil || vmID <= 0 || vmID > maxVMID {
		return "", 0, fmt.Errorf("%w: ha vmid out of range", ErrMalformed)
	}
	return typ, vmID, nil
}

func haResource(r haResourceData, observed map[string]haStatusEntry) (HAResource, error) {
	typ, vmID, err := haSID(r.SID)
	if err != nil {
		return HAResource{}, err
	}
	if r.Type != typ {
		return HAResource{}, fmt.Errorf("%w: inconsistent ha resource type", ErrMalformed)
	}
	state, err := checkText("state", r.State)
	if err != nil {
		return HAResource{}, err
	}
	out := HAResource{VMID: vmID, Type: typ, Managed: true, DesiredState: state}
	if e, ok := observed[r.SID]; ok {
		out.State = e.State
		out.Node = e.Node
	}
	return out, nil
}
