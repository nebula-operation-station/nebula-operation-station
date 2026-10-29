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
//
// TODO(pvecontract): ticket P1-02 (internal/pvecontract) is not on main
// yet. The result and limit types in this package are minimal local
// definitions; once pvecontract lands, move the shared contract types there
// and keep only the HTTP client in this package.
package pveapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	// maxTaskObjects bounds UPIDs in one tasklist response (1,000 objects
	// per page).
	maxTaskObjects = 1000
	// maxHAObjects bounds HA objects in one response (1,000 objects per
	// page).
	maxHAObjects = 1000
	// maxClusterNodes bounds a plausible cluster node count.
	maxClusterNodes = 1000
	// maxVMID bounds a plausible PVE VMID.
	maxVMID = 999999999
	// maxAttempts bounds a plausible HA start attempt/failure counter.
	maxAttempts = 1000000
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

// Client is a typed, read-only Proxmox VE API client. It is safe for
// concurrent use.
type Client struct {
	// HTTP is the transport. Required.
	HTTP *http.Client
	// BaseURL is the PVE API root, e.g.
	// "https://pve.example:8006/api2/json". Required.
	BaseURL string
	// Token supplies the value of the Authorization header for each call
	// (e.g. "PVEAPIToken=user!realm!token"). Required. Its error value must
	// not contain the token.
	Token func(ctx context.Context) (string, error)
	// Timeout bounds each API call. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxBody caps the decoded response size in bytes. Zero means
	// DefaultMaxBody.
	MaxBody int64
}

// do performs one GET against base+path. It returns the raw body, or a
// non-empty reason when the dataset is unavailable (transport failure,
// timeout, 404, non-2xx). It never includes headers or bodies in the
// reason or in a returned error.
func (c *Client) do(ctx context.Context, path string) ([]byte, string, error) {
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

	resp, err := c.HTTP.Do(req)
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

// nonNeg validates an optional non-negative counter.
func nonNeg(field string, v *int) (int, error) {
	if v == nil {
		return 0, nil
	}
	if *v < 0 || *v > maxAttempts {
		return 0, fmt.Errorf("%w: %s out of range", ErrMalformed, field)
	}
	return *v, nil
}

// ClusterStatus is a bounded summary of GET /cluster/status (ADR 0006:
// membership, votes/quorum). A standalone PVE host has no cluster entry:
// the endpoint is absent and the result is Available=false, never an empty
// cluster with zero nodes.
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
}

type clusterStatusData struct {
	Cluster     string `json:"cluster"`
	NodesOnline *int   `json:"nodes_online"`
	NodesTotal  *int   `json:"nodes_total"`
	Quorum      *int   `json:"quorum"`
}

// ClusterStatus reads GET /cluster/status.
func (c *Client) ClusterStatus(ctx context.Context) (ClusterStatus, error) {
	body, reason, err := c.do(ctx, "/cluster/status")
	if err != nil {
		return ClusterStatus{}, err
	}
	if body == nil {
		if reason == reasonNotFound {
			reason = "standalone host: no cluster configured"
		}
		return ClusterStatus{Available: false, Reason: reason}, nil
	}
	d, err := decodeData[clusterStatusData](body)
	if err != nil {
		return ClusterStatus{}, err
	}
	name, err := checkText("cluster", d.Cluster)
	if err != nil {
		return ClusterStatus{}, err
	}
	out := ClusterStatus{Available: true, Name: name}
	if d.NodesOnline != nil {
		if *d.NodesOnline < 0 || *d.NodesOnline > maxClusterNodes {
			return ClusterStatus{}, fmt.Errorf("%w: nodes_online out of range", ErrMalformed)
		}
		out.NodesOnline = *d.NodesOnline
	}
	if d.NodesTotal != nil {
		if *d.NodesTotal < 0 || *d.NodesTotal > maxClusterNodes {
			return ClusterStatus{}, fmt.Errorf("%w: nodes_total out of range", ErrMalformed)
		}
		out.NodesTotal = *d.NodesTotal
	}
	if d.Quorum != nil {
		switch *d.Quorum {
		case 0:
		case 1:
			out.Quorum = true
		default:
			return ClusterStatus{}, fmt.Errorf("%w: quorum out of range", ErrMalformed)
		}
	}
	return out, nil
}

// HAStatus is a bounded summary of the HA manager state: the desired states
// from GET /cluster/ha/resources joined with the observed states from
// GET /cluster/ha/status/current, one entry per VMID (ADR 0006: HA resource
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
	// DesiredState is the configured HA state (resource option "state").
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
	ID                  *int   `json:"id"`
	Type                string `json:"type"`
	Managed             *int   `json:"managed"`
	Node                string `json:"node"`
	StartAttempts       *int   `json:"start-attempts"`
	StartFailures       *int   `json:"start-failures"`
	LastStateChange     *int64 `json:"last-state-change"`
	LastStateChangeBy   string `json:"last-state-change-by"`
	LastStateChangeNode string `json:"last-state-change-node"`
	Options             *struct {
		State string `json:"state"`
	} `json:"options"`
}

type haStatusEntry struct {
	ID                  *int   `json:"id"`
	State               string `json:"state"`
	StateReason         string `json:"state-reason"`
	StateReasonDetail   string `json:"state-reason-detail"`
	Node                string `json:"node"`
	StartAttempts       *int   `json:"start-attempts"`
	StartFailures       *int   `json:"start-failures"`
	LastStateChange     *int64 `json:"last-state-change"`
	LastStateChangeBy   string `json:"last-state-change-by"`
	LastStateChangeNode string `json:"last-state-change-node"`
}

// HAStatus reads GET /cluster/ha/resources and GET /cluster/ha/status/current
// and joins them per VMID.
func (c *Client) HAStatus(ctx context.Context) (HAStatus, error) {
	resBody, resReason, err := c.do(ctx, "/cluster/ha/resources")
	if err != nil {
		return HAStatus{}, err
	}
	stBody, stReason, err := c.do(ctx, "/cluster/ha/status/current")
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

	observed := make(map[int]haStatusEntry, len(*entries))
	for _, e := range *entries {
		id, err := haID("status", e.ID)
		if err != nil {
			return HAStatus{}, err
		}
		observed[id] = e
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

func haID(kind string, id *int) (int, error) {
	if id == nil || *id <= 0 || *id > maxVMID {
		return 0, fmt.Errorf("%w: %s vmid out of range", ErrMalformed, kind)
	}
	return *id, nil
}

func haResource(r haResourceData, observed map[int]haStatusEntry) (HAResource, error) {
	vmID, err := haID("resource", r.ID)
	if err != nil {
		return HAResource{}, err
	}
	typ, err := checkText("type", r.Type)
	if err != nil {
		return HAResource{}, err
	}
	if typ != "vm" && typ != "ct" {
		return HAResource{}, fmt.Errorf("%w: unknown ha resource type", ErrMalformed)
	}
	out := HAResource{VMID: vmID, Type: typ}
	if r.Managed != nil {
		switch *r.Managed {
		case 0:
		case 1:
			out.Managed = true
		default:
			return HAResource{}, fmt.Errorf("%w: managed out of range", ErrMalformed)
		}
	}
	if r.Options != nil {
		if out.DesiredState, err = checkText("options.state", r.Options.State); err != nil {
			return HAResource{}, err
		}
	}
	if out.Node, err = checkText("node", r.Node); err != nil {
		return HAResource{}, err
	}
	if out.StartAttempts, err = nonNeg("start-attempts", r.StartAttempts); err != nil {
		return HAResource{}, err
	}
	if out.StartFailures, err = nonNeg("start-failures", r.StartFailures); err != nil {
		return HAResource{}, err
	}
	if r.LastStateChange != nil {
		out.LastStateChange = time.Unix(*r.LastStateChange, 0).UTC()
	}
	if out.LastStateChangeBy, err = checkText("last-state-change-by", r.LastStateChangeBy); err != nil {
		return HAResource{}, err
	}
	if out.LastStateChangeNode, err = checkText("last-state-change-node", r.LastStateChangeNode); err != nil {
		return HAResource{}, err
	}

	// The observed state from /cluster/ha/status/current wins over the
	// resource copy when both are present.
	if e, ok := observed[vmID]; ok {
		if out.State, err = checkText("state", e.State); err != nil {
			return HAResource{}, err
		}
		if out.StateReason, err = checkText("state-reason", e.StateReason); err != nil {
			return HAResource{}, err
		}
		if out.StateReasonDetail, err = checkText("state-reason-detail", e.StateReasonDetail); err != nil {
			return HAResource{}, err
		}
		if e.Node != "" {
			if out.Node, err = checkText("node", e.Node); err != nil {
				return HAResource{}, err
			}
		}
		if e.StartAttempts != nil {
			if out.StartAttempts, err = nonNeg("start-attempts", e.StartAttempts); err != nil {
				return HAResource{}, err
			}
		}
		if e.StartFailures != nil {
			if out.StartFailures, err = nonNeg("start-failures", e.StartFailures); err != nil {
				return HAResource{}, err
			}
		}
		if e.LastStateChange != nil {
			out.LastStateChange = time.Unix(*e.LastStateChange, 0).UTC()
		}
		if e.LastStateChangeBy != "" {
			if out.LastStateChangeBy, err = checkText("last-state-change-by", e.LastStateChangeBy); err != nil {
				return HAResource{}, err
			}
		}
		if e.LastStateChangeNode != "" {
			if out.LastStateChangeNode, err = checkText("last-state-change-node", e.LastStateChangeNode); err != nil {
				return HAResource{}, err
			}
		}
	}
	return out, nil
}
