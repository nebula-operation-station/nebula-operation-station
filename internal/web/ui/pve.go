// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pveinventory"
)

// pveStaleThreshold marks a stored observation as stale after three missed
// poll intervals (ADR 0006: 5-minute intervals, stale after three misses).
const pveStaleThreshold = 15 * time.Minute

// pveCallTimeout bounds the store reads made while rendering a PVE page.
const pveCallTimeout = 5 * time.Second

// pveRemoteLimit, pveNodeLimit and pveGuestLimit cap the page queries;
// homelab-sized data fits far below them.
const (
	pveRemoteLimit = 200
	pveNodeLimit   = 200
	pveGuestLimit  = 1000
)

// PVEStore is the read-only part of pveinventory.Store the PVE pages use.
// pveinventory.Store satisfies it.
type PVEStore interface {
	ListRemotes(ctx context.Context, limit int) ([]pveinventory.Remote, error)
	GetRemote(ctx context.Context, remoteID string) (pveinventory.Remote, error)
	ListNodes(ctx context.Context, remoteID string, limit int) ([]pveinventory.Node, error)
	ListGuests(ctx context.Context, remoteID string, f pveinventory.GuestFilter, limit int) ([]pveinventory.Guest, error)
	ListDatasetStatus(ctx context.Context, remoteID string) ([]pveinventory.DatasetStatus, error)
}

// PVEEndpoint is one approved HTTPS endpoint of a PVE remote, from the
// remote record (never host-provided).
type PVEEndpoint struct {
	// Host is the endpoint host name or IP.
	Host string
	// Port is the HTTPS port.
	Port int
}

// PVERemoteMeta is the registry-side metadata of one PVE remote: the
// approved endpoints, the current trust pin and the registry state.
type PVERemoteMeta struct {
	// RemoteID identifies the remote in the inventory store.
	RemoteID string
	// Name is the display name.
	Name string
	// Kind is "cluster" or "standalone".
	Kind string
	// Endpoints are the approved HTTPS endpoints.
	Endpoints []PVEEndpoint
	// TrustPin is the current TLS trust pin (hex).
	TrustPin string
	// TrustGeneration is the trust pin generation.
	TrustGeneration uint64
	// State is the registry state ("active", "blocked", ...).
	State string
}

// PVERemoteMetaFunc returns the registry metadata of all PVE remotes. Nil
// hides deep links; an error is logged and treated as "no metadata" (the
// pages still render, without links).
type PVERemoteMetaFunc func(ctx context.Context) ([]PVERemoteMeta, error)

// pveRemoteRow is one row of the PVE remote list page.
type pveRemoteRow struct {
	// RemoteID is the stable identifier (used for the detail URL).
	RemoteID string
	// Name is the display name, rendered as text.
	Name string
	// Kind is "cluster" or "standalone".
	Kind string
	// Nodes lists the stored node names, comma separated.
	Nodes string
	// PinText is the trust pin or "unknown".
	PinText string
	// StateText is the registry state or "unknown".
	StateText string
	// Label is the staleness label: "", "stale" or "unknown".
	Label string
	// LastObservedAt is the last stored observation time.
	LastObservedAt time.Time
	// Age is a short relative age of LastObservedAt.
	Age string
	// Source is the collector that made the last observation.
	Source string
	// DetailURL links to the remote's detail page.
	DetailURL string
	// Link is the deep link to the PVE web UI, or "" when no approved
	// endpoint applies.
	Link string
}

// pveListData is the data of the PVE remote list page.
type pveListData struct {
	// Unavailable is true when the stored inventory could not be read.
	Unavailable bool
	// Rows are the remotes, in remote ID order.
	Rows []pveRemoteRow
}

// pveNodeRow is one node row of the detail page.
type pveNodeRow struct {
	// Node is the node name, rendered as text.
	Node string
	// Status is the stored node status.
	Status string
	// PVEVersion is the stored PVE version, if observed.
	PVEVersion string
	// KernelVersion is the stored kernel version, if observed.
	KernelVersion string
	// Label is the staleness/availability label.
	Label string
	// ObservedAt is the stored observation time.
	ObservedAt time.Time
	// Age is a short relative age of ObservedAt.
	Age string
	// Link is the deep link to the node in the PVE web UI, or "".
	Link string
}

// pveGuestRow is one guest row of the detail page.
type pveGuestRow struct {
	// VMIDText is the guest VMID.
	VMIDText string
	// Kind is "qemu" or "lxc".
	Kind string
	// Name is the guest name, rendered as text.
	Name string
	// Node is the node the guest runs on, rendered as text.
	Node string
	// Status is the stored guest status.
	Status string
	// Label is the staleness/availability label.
	Label string
	// ObservedAt is the stored observation time.
	ObservedAt time.Time
	// Age is a short relative age of ObservedAt.
	Age string
	// Link is the deep link to the guest in the PVE web UI, or "".
	Link string
}

// pveDatasetRow is one dataset-status row of the detail page.
type pveDatasetRow struct {
	// Dataset is the dataset name ("nodes", "guests", ...).
	Dataset string
	// State is the stored availability state.
	State string
	// ObservedAt is the stored observation time.
	ObservedAt time.Time
	// Age is a short relative age of ObservedAt.
	Age string
	// Source is the collector of the last observation.
	Source string
	// Reason explains an unavailable dataset.
	Reason string
}

// pveDetailData is the data of a PVE remote's detail page.
type pveDetailData struct {
	// Name is the display name, rendered as text.
	Name string
	// Kind is "cluster" or "standalone".
	Kind string
	// StateText is the registry state or "unknown".
	StateText string
	// Label is the staleness label: "", "stale" or "unknown".
	Label string
	// PinText is the trust pin or "unknown".
	PinText string
	// Link is the deep link to the PVE web UI, or "".
	Link string
	// LastObservedAt is the last stored observation time.
	LastObservedAt time.Time
	// Age is a short relative age of LastObservedAt.
	Age string
	// Source is the collector that made the last observation.
	Source string
	// Nodes lists the stored nodes.
	Nodes []pveNodeRow
	// Guests lists the stored guests.
	Guests []pveGuestRow
	// Datasets lists the dataset availability states.
	Datasets []pveDatasetRow
}

var pveHostPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// pveEndpointValid reports whether an endpoint may be used in a deep link:
// a resolvable-looking host (IP or DNS name) and a real TCP port.
func pveEndpointValid(ep PVEEndpoint) bool {
	if ep.Port < 1 || ep.Port > 65535 || ep.Host == "" {
		return false
	}
	if net.ParseIP(ep.Host) != nil {
		return true
	}
	return pveHostPattern.MatchString(ep.Host)
}

// pveEndpointFor picks the approved endpoint for a node: the root link
// (node == "") and a standalone's node use the remote's first endpoint,
// a cluster's node must match an endpoint host (case-insensitively).
func pveEndpointFor(kind string, endpoints []PVEEndpoint, node string) (PVEEndpoint, bool) {
	if len(endpoints) == 0 {
		return PVEEndpoint{}, false
	}
	if node == "" || kind == "standalone" {
		return endpoints[0], true
	}
	for _, ep := range endpoints {
		if strings.EqualFold(ep.Host, node) {
			return ep, true
		}
	}
	return PVEEndpoint{}, false
}

// pveDeepLink builds an HTTPS link into the PVE web UI from approved
// endpoint metadata and percent-encoded identifiers only — never a
// host-provided URL (ADR 0006, "One-click access"). It returns "" when no
// valid approved endpoint applies.
func pveDeepLink(kind string, endpoints []PVEEndpoint, node string, extra ...string) string {
	ep, ok := pveEndpointFor(kind, endpoints, node)
	if !ok || !pveEndpointValid(ep) {
		return ""
	}
	parts := make([]string, 0, 1+len(extra))
	if node != "" {
		parts = append(parts, "nodes", url.PathEscape(node))
	}
	for _, e := range extra {
		parts = append(parts, url.PathEscape(e))
	}
	host := ep.Host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	s := "https://" + host + ":" + strconv.Itoa(ep.Port)
	if len(parts) == 0 {
		return s + "/"
	}
	return s + "/" + strings.Join(parts, "/")
}

// pveRemoteLabel is the staleness label of a stored remote: "unknown" when
// no observation ever arrived, "stale" when the last observation is older
// than three poll intervals, otherwise "".
func pveRemoteLabel(rm pveinventory.Remote, now time.Time) string {
	if rm.LastSource == "" {
		return "unknown"
	}
	if now.Sub(rm.LastObservedAt) > pveStaleThreshold {
		return "stale"
	}
	return ""
}

// pveRowLabel is the label of a stored node or guest row: "unknown" when
// never observed, "stale" when older than three poll intervals, otherwise
// the dataset state when it is not "available".
func pveRowLabel(observedAt time.Time, state pveinventory.DatasetState, now time.Time) string {
	switch {
	case observedAt.IsZero():
		return "unknown"
	case now.Sub(observedAt) > pveStaleThreshold:
		return "stale"
	case state != pveinventory.StateAvailable:
		return string(state)
	}
	return ""
}

// pveAge renders a short relative age: "just now", "5m ago", "2h ago",
// "3d ago". A zero time renders "".
func pveAge(now, at time.Time) string {
	if at.IsZero() {
		return ""
	}
	d := now.Sub(at)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// pveMeta maps the registry metadata by remote ID. An error is logged; the
// pages then render without deep links (fail closed).
func (h *Handler) pveMeta(ctx context.Context) map[string]PVERemoteMeta {
	if h.pveRemotes == nil {
		return nil
	}
	metas, err := h.pveRemotes(ctx)
	if err != nil {
		h.log.Error("list PVE remote metadata", "error", err)
		return nil
	}
	out := make(map[string]PVERemoteMeta, len(metas))
	for _, m := range metas {
		out[m.RemoteID] = m
	}
	return out
}

func (h *Handler) handlePVEList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.pve == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pveCallTimeout)
	defer cancel()
	remotes, err := h.pve.ListRemotes(ctx, pveRemoteLimit)
	if err != nil {
		h.log.Error("list PVE remotes", "error", err)
		h.render(w, r, pageData{Title: "PVE remotes", Active: "pve", Content: "pve",
			PVEList: &pveListData{Unavailable: true}})
		return
	}
	metas := h.pveMeta(ctx)
	now := time.Now()
	rows := make([]pveRemoteRow, 0, len(remotes))
	for _, rm := range remotes {
		meta := metas[rm.RemoteID]
		nodeNames := "—"
		if nodes, err := h.pve.ListNodes(ctx, rm.RemoteID, pveNodeLimit); err == nil && len(nodes) > 0 {
			names := make([]string, 0, len(nodes))
			for _, n := range nodes {
				names = append(names, n.Node)
			}
			nodeNames = strings.Join(names, ", ")
		}
		// The registry name is approved metadata; the stored name is
		// collector-provided and only a fallback.
		name := rm.Name
		if meta.Name != "" {
			name = meta.Name
		}
		pin := "—"
		if meta.TrustPin != "" {
			pin = meta.TrustPin
		}
		state := "—"
		if meta.State != "" {
			state = meta.State
		}
		rows = append(rows, pveRemoteRow{
			RemoteID:       rm.RemoteID,
			Name:           name,
			Kind:           rm.Kind,
			Nodes:          nodeNames,
			PinText:        pin,
			StateText:      state,
			Label:          pveRemoteLabel(rm, now),
			LastObservedAt: rm.LastObservedAt,
			Age:            pveAge(now, rm.LastObservedAt),
			Source:         rm.LastSource,
			DetailURL:      "/pve/" + url.PathEscape(rm.RemoteID),
			Link:           pveDeepLink(rm.Kind, meta.Endpoints, ""),
		})
	}
	h.render(w, r, pageData{Title: "PVE remotes", Active: "pve", Content: "pve", PVEList: &pveListData{Rows: rows}})
}

func (h *Handler) handlePVEDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.pve == nil {
		http.NotFound(w, r)
		return
	}
	id := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), pveCallTimeout)
	defer cancel()
	rm, err := h.pve.GetRemote(ctx, id)
	if err != nil {
		if errors.Is(err, pveinventory.ErrRemoteNotFound) {
			http.NotFound(w, r)
			return
		}
		h.log.Error("get PVE remote", "remote", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	meta := h.pveMeta(ctx)[id]
	now := time.Now()

	// The registry name is approved metadata; the stored name is
	// collector-provided and only a fallback.
	name := rm.Name
	if meta.Name != "" {
		name = meta.Name
	}
	d := &pveDetailData{
		Name:           name,
		Kind:           rm.Kind,
		Label:          pveRemoteLabel(rm, now),
		PinText:        "—",
		StateText:      "—",
		LastObservedAt: rm.LastObservedAt,
		Age:            pveAge(now, rm.LastObservedAt),
		Source:         rm.LastSource,
		Link:           pveDeepLink(rm.Kind, meta.Endpoints, ""),
	}
	if meta.TrustPin != "" {
		d.PinText = meta.TrustPin
	}
	if meta.State != "" {
		d.StateText = meta.State
	}

	if nodes, err := h.pve.ListNodes(ctx, id, pveNodeLimit); err != nil {
		h.log.Error("list PVE nodes", "remote", id, "error", err)
	} else {
		for _, n := range nodes {
			d.Nodes = append(d.Nodes, pveNodeRow{
				Node:          n.Node,
				Status:        n.Status,
				PVEVersion:    n.PVEVersion,
				KernelVersion: n.KernelVersion,
				Label:         pveRowLabel(n.ObservedAt, n.State, now),
				ObservedAt:    n.ObservedAt,
				Age:           pveAge(now, n.ObservedAt),
				Link:          pveDeepLink(rm.Kind, meta.Endpoints, n.Node),
			})
		}
	}
	if guests, err := h.pve.ListGuests(ctx, id, pveinventory.GuestFilter{}, pveGuestLimit); err != nil {
		h.log.Error("list PVE guests", "remote", id, "error", err)
	} else {
		for _, g := range guests {
			d.Guests = append(d.Guests, pveGuestRow{
				VMIDText:   strconv.FormatUint(g.VMID, 10),
				Kind:       g.Kind,
				Name:       g.Name,
				Node:       g.Node,
				Status:     g.Status,
				Label:      pveRowLabel(g.ObservedAt, g.State, now),
				ObservedAt: g.ObservedAt,
				Age:        pveAge(now, g.ObservedAt),
				Link:       pveDeepLink(rm.Kind, meta.Endpoints, g.Node, g.Kind, strconv.FormatUint(g.VMID, 10)),
			})
		}
	}
	if datasets, err := h.pve.ListDatasetStatus(ctx, id); err != nil {
		h.log.Error("list PVE dataset status", "remote", id, "error", err)
	} else {
		for _, ds := range datasets {
			d.Datasets = append(d.Datasets, pveDatasetRow{
				Dataset:    ds.Dataset,
				State:      string(ds.State),
				ObservedAt: ds.ObservedAt,
				Age:        pveAge(now, ds.ObservedAt),
				Source:     ds.Source,
				Reason:     ds.Reason,
			})
		}
	}
	h.render(w, r, pageData{Title: "PVE remote " + rm.Name, Active: "pve", Content: "pve_detail", PVEDetail: d})
}
