// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// GuestKind is the kind of a Proxmox guest.
type GuestKind string

// Guest kinds.
const (
	KindQemu GuestKind = "qemu"
	KindLxc  GuestKind = "lxc"
)

// nodeNamePattern accepts PVE node names and rejects path separators and
// other characters that could alter the request path.
var nodeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func validateNodeName(name string) error {
	if !nodeNamePattern.MatchString(name) {
		return fmt.Errorf("pveapi: invalid node name %q", sanitizeText(name, 64))
	}
	return nil
}

func validateVMID(vmid int) error {
	if vmid <= 0 || vmid >= 1<<31 {
		return fmt.Errorf("pveapi: invalid vmid %d", vmid)
	}
	return nil
}

// Node is one cluster node as reported by /nodes.
type Node struct {
	Name   string
	Status string // "online", "offline", "maintenance"
	Type   string // "pve"
}

// Guest is one QEMU or LXC guest as reported by the node list endpoints.
type Guest struct {
	Node          string
	Kind          GuestKind
	VMID          int
	Name          string
	Status        string // "running", "stopped", "paused", ...
	MaxCPU        int
	MaxMemory     int64 // bytes, 0 = unknown
	UptimeSeconds int64 // 0 = stopped or unknown
	Ctime         *time.Time
	UUID          string
}

// Incarnation carries the VMID-reuse hints (ctime/uuid) of one guest
// observation. NOS compares incarnations across polls to detect that a VMID
// was reused for a different guest; the hints are suggestions only and
// never proof of identity.
type Incarnation struct {
	Ctime *time.Time
	UUID  string
}

// Matches reports whether a and b describe the same guest incarnation.
// known is false when neither side carries a UUID nor a ctime.
func (a Incarnation) Matches(b Incarnation) (same, known bool) {
	if a.UUID != "" || b.UUID != "" {
		return a.UUID != "" && b.UUID != "" && a.UUID == b.UUID, true
	}
	if a.Ctime != nil || b.Ctime != nil {
		return a.Ctime != nil && b.Ctime != nil && a.Ctime.Equal(*b.Ctime), true
	}
	return false, false
}

// ClusterInventory is the result of EnumerateCluster. When Partial is true,
// at least one node could not be enumerated and NodeErrors carries a
// sanitized reason per failed node; Guests then only covers the readable
// nodes and must not be used to tombstone unseen guests.
type ClusterInventory struct {
	Nodes      []Node
	Guests     []Guest
	Partial    bool
	NodeErrors map[string]string
	Truncated  bool
}

// ListNodes returns the cluster nodes.
func (c *Client) ListNodes(ctx context.Context) ([]Node, error) {
	data, err := c.do(ctx, "/nodes")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Node   string `json:"node"`
		Status string `json:"status"`
		Type   string `json:"type"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("pveapi: decode /nodes: %w", err)
	}
	if len(raw) > MaxObjectsPerPage {
		return nil, fmt.Errorf("pveapi: /nodes has %d objects, limit %d", len(raw), MaxObjectsPerPage)
	}
	nodes := make([]Node, 0, len(raw))
	for _, n := range raw {
		if err := validateNodeName(n.Node); err != nil {
			return nil, err
		}
		nodes = append(nodes, Node{
			Name:   n.Node,
			Status: sanitizeText(n.Status, 64),
			Type:   sanitizeText(n.Type, 32),
		})
	}
	return nodes, nil
}

// ListQemu returns the QEMU guests on node.
func (c *Client) ListQemu(ctx context.Context, node string) ([]Guest, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	data, err := c.do(ctx, "/nodes/"+node+"/qemu")
	if err != nil {
		return nil, err
	}
	return parseGuestList(data, node, KindQemu)
}

// ListLxc returns the LXC containers on node.
func (c *Client) ListLxc(ctx context.Context, node string) ([]Guest, error) {
	if err := validateNodeName(node); err != nil {
		return nil, err
	}
	data, err := c.do(ctx, "/nodes/"+node+"/lxc")
	if err != nil {
		return nil, err
	}
	return parseGuestList(data, node, KindLxc)
}

// parseGuestList decodes the /nodes/{node}/qemu and /nodes/{node}/lxc
// status lists. PVE 8 and PVE 9 differ in the extra fields they carry;
// unknown fields are dropped.
func parseGuestList(data json.RawMessage, node string, kind GuestKind) ([]Guest, error) {
	var raw []struct {
		VMID      int64  `json:"vmid"`
		Name      string `json:"name"`
		Status    string `json:"status"`
		MaxCPU    int    `json:"maxcpu"`
		MaxMemory int64  `json:"maxmemory"`
		Uptime    int64  `json:"uptime"`
		Ctime     *int64 `json:"ctime"`
		UUID      string `json:"uuid"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("pveapi: decode guest list: %w", err)
	}
	if len(raw) > MaxObjectsPerPage {
		return nil, fmt.Errorf("pveapi: guest list has %d objects, limit %d", len(raw), MaxObjectsPerPage)
	}
	guests := make([]Guest, 0, len(raw))
	for _, g := range raw {
		if err := validateVMID(int(g.VMID)); err != nil {
			return nil, err
		}
		if g.MaxCPU < 0 || g.MaxMemory < 0 || g.Uptime < 0 {
			return nil, fmt.Errorf("pveapi: guest %d: negative resource value", g.VMID)
		}
		gu := Guest{
			Node:          node,
			Kind:          kind,
			VMID:          int(g.VMID),
			Name:          sanitizeText(g.Name, 255),
			Status:        sanitizeText(g.Status, 64),
			MaxCPU:        g.MaxCPU,
			MaxMemory:     g.MaxMemory,
			UptimeSeconds: g.Uptime,
			UUID:          sanitizeText(g.UUID, 64),
		}
		if g.Ctime != nil {
			t := time.Unix(*g.Ctime, 0)
			gu.Ctime = &t
		}
		guests = append(guests, gu)
	}
	return guests, nil
}

// EnumerateCluster lists all nodes and the QEMU/LXC guests on each. A node
// that cannot be enumerated (for example offline) does not fail the call:
// the result is marked Partial and NodeErrors carries a sanitized reason.
// Guests beyond MaxGuestsPerRemote are dropped and Truncated is set.
func (c *Client) EnumerateCluster(ctx context.Context) (ClusterInventory, error) {
	nodes, err := c.ListNodes(ctx)
	if err != nil {
		return ClusterInventory{}, err
	}
	inv := ClusterInventory{
		Nodes:      nodes,
		NodeErrors: make(map[string]string, len(nodes)),
	}
	for _, n := range nodes {
		q, qerr := c.ListQemu(ctx, n.Name)
		l, lerr := c.ListLxc(ctx, n.Name)
		if qerr == nil {
			inv.Guests = append(inv.Guests, q...)
		}
		if lerr == nil {
			inv.Guests = append(inv.Guests, l...)
		}
		if qerr != nil || lerr != nil {
			inv.Partial = true
			inv.NodeErrors[n.Name] = errReason(qerr, lerr)
		}
		if len(inv.Guests) >= MaxGuestsPerRemote {
			inv.Guests = inv.Guests[:MaxGuestsPerRemote]
			inv.Truncated = true
			break
		}
	}
	return inv, nil
}

// errReason returns the sanitized text of the first non-nil error.
func errReason(errs ...error) string {
	for _, e := range errs {
		if e != nil {
			return sanitizeText(e.Error(), 256)
		}
	}
	return ""
}
