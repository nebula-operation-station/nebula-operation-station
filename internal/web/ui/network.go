// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
)

// Network pages (spec 12, M9-1): networks with their addresses, and
// network assets. Address status is computed by internal/ipam; a free
// address is only ever a suggestion.

// NetworkStore keeps networks and assets (internal/ipam.Store).
type NetworkStore interface {
	Networks(ctx context.Context) ([]ipam.Network, error)
	Network(ctx context.Context, id string) (ipam.Network, error)
	SaveNetwork(ctx context.Context, n ipam.Network) error
	DeleteNetwork(ctx context.Context, id string) error
	Status(ctx context.Context, networkID string) ([]ipam.AddressView, bool, error)
	StatusMany(ctx context.Context, nets []ipam.Network) (map[string][]ipam.AddressView, map[string]bool, error)
	Suggest(ctx context.Context, networkID, pool string, count int) ([]netip.Addr, error)
	SetEntry(ctx context.Context, user string, ad netip.Addr, kind, note string) error
	ClearEntry(ctx context.Context, ad netip.Addr) error
	Assets(ctx context.Context) ([]ipam.Asset, error)
	Asset(ctx context.Context, id string) (ipam.Asset, error)
	SaveAsset(ctx context.Context, a ipam.Asset) error
	DeleteAsset(ctx context.Context, id string) error
	LinkHost(ctx context.Context, assetID, hostID string) error
}

type networkRow struct {
	ID, Name, Prefix, Gateway, Counts string
	VLAN                              int
}

type assetRow struct {
	ID, Name, Kind, Hostname, MAC, Addresses, HostID string
}

type addressCell struct {
	Address, Label, Status, Why, Claims string
}

type poolView struct {
	Name, First, Last string
}

type networkDetail struct {
	ID, Name, Prefix, Gateway, Notes string
	VLAN                             int
	Pools                            []poolView
	// Grid is every address (small networks); Listed is false when only
	// claimed addresses are shown.
	Grid    []addressCell
	Listed  bool
	Claimed []addressCell
	Suggest []string
}

type assetDetail struct {
	assetRow
	Notes string
	// CanEnroll links "add to managed hosts" (an inventory is configured
	// and the asset is not linked yet).
	CanEnroll bool
}

type networkData struct {
	Networks []networkRow
	Assets   []assetRow
	Kinds    []ipam.Kind
	Network  *networkDetail
	Asset    *assetDetail
	// DiscoveryEnabled links the discovery page.
	DiscoveryEnabled bool
	// NetDraft and AssetDraft are JSON for the edit forms ("" for new).
	NetDraft, AssetDraft string
}

func (h *Handler) handleNetworkPage(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		h.render(w, r, pageData{Title: "Network", Active: "network", Content: "empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	data := &networkData{Kinds: ipam.Kinds, DiscoveryEnabled: h.discovery != nil}
	nets, err := h.network.Networks(ctx)
	if err != nil {
		h.log.Error("list networks", "error", err)
		http.Error(w, "network data unavailable", http.StatusInternalServerError)
		return
	}
	views, listed, err := h.network.StatusMany(ctx, nets)
	if err != nil {
		h.log.Error("network status", "error", err)
	}
	for _, n := range nets {
		row := networkRow{ID: n.ID, Name: n.Name, Prefix: n.Prefix.String(), VLAN: n.VLAN, Gateway: addrText(n.Gateway)}
		if views != nil {
			row.Counts = statusCounts(views[n.ID], listed[n.ID])
		}
		data.Networks = append(data.Networks, row)
	}
	assets, err := h.network.Assets(ctx)
	if err != nil {
		h.log.Error("list assets", "error", err)
		http.Error(w, "network data unavailable", http.StatusInternalServerError)
		return
	}
	for _, a := range assets {
		data.Assets = append(data.Assets, viewAsset(a))
	}
	h.render(w, r, pageData{Title: "Network", Active: "network", Content: "network", Scripts: []string{"webauthn.js", "network.js"}, Network: data})
}

func (h *Handler) handleNetworkDetail(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	n, err := h.network.Network(ctx, r.PathValue("id"))
	if errors.Is(err, ipam.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get network", "error", err)
		http.Error(w, "network data unavailable", http.StatusInternalServerError)
		return
	}
	views, listed, err := h.network.Status(ctx, n.ID)
	if err != nil {
		h.log.Error("network status", "error", err)
		http.Error(w, "network data unavailable", http.StatusInternalServerError)
		return
	}
	d := &networkDetail{ID: n.ID, Name: n.Name, Prefix: n.Prefix.String(), Gateway: addrText(n.Gateway), Notes: n.Notes, VLAN: n.VLAN, Listed: listed}
	for _, p := range n.Pools {
		d.Pools = append(d.Pools, poolView{Name: p.Name, First: p.First.String(), Last: p.Last.String()})
	}
	for _, v := range views {
		c := viewAddress(v)
		if listed {
			d.Grid = append(d.Grid, c)
		}
		if v.Status != ipam.Free {
			d.Claimed = append(d.Claimed, c)
		}
	}
	pool := r.URL.Query().Get("pool")
	if sug, err := h.network.Suggest(ctx, n.ID, pool, 5); err == nil {
		for _, a := range sug {
			d.Suggest = append(d.Suggest, a.String())
		}
	}
	h.render(w, r, pageData{Title: "Network " + n.Name, Active: "network", Content: "network_detail", Scripts: []string{"webauthn.js", "network.js"},
		Network: &networkData{Network: d, NetDraft: networkDraft(n)}})
}

func (h *Handler) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	a, err := h.network.Asset(ctx, r.PathValue("id"))
	if errors.Is(err, ipam.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.log.Error("get asset", "error", err)
		http.Error(w, "network data unavailable", http.StatusInternalServerError)
		return
	}
	d := &assetDetail{assetRow: viewAsset(a), Notes: a.Notes, CanEnroll: h.inventory != nil && a.HostID == ""}
	h.render(w, r, pageData{Title: "Asset " + a.Name, Active: "network", Content: "asset", Scripts: []string{"webauthn.js", "network.js"},
		Network: &networkData{Asset: d, Kinds: ipam.Kinds, AssetDraft: assetDraft(a)}})
}

// --- JSON endpoints ---

type poolRequest struct {
	Name  string `json:"name"`
	First string `json:"first"`
	Last  string `json:"last"`
}

type networkRequest struct {
	ID      string        `json:"id"`
	Name    string        `json:"name"`
	Prefix  string        `json:"prefix"`
	VLAN    int           `json:"vlan"`
	Gateway string        `json:"gateway"`
	Notes   string        `json:"notes"`
	Pools   []poolRequest `json:"pools"`
}

type assetRequest struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Hostname  string   `json:"hostname"`
	MAC       string   `json:"mac"`
	Notes     string   `json:"notes"`
	Addresses []string `json:"addresses"`
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func (in networkRequest) network() (ipam.Network, string) {
	p, err := netip.ParsePrefix(strings.TrimSpace(in.Prefix))
	if err != nil {
		return ipam.Network{}, "the network must be a prefix such as 192.168.10.0/24"
	}
	n := ipam.Network{ID: in.ID, Name: in.Name, Prefix: p, VLAN: in.VLAN, Notes: in.Notes}
	if strings.TrimSpace(in.Gateway) != "" {
		g, ok := parseAddr(in.Gateway)
		if !ok {
			return ipam.Network{}, "the gateway is not an IP address"
		}
		n.Gateway = g
	}
	if len(in.Pools) > ipam.MaxPools {
		return ipam.Network{}, "too many pools"
	}
	for _, pr := range in.Pools {
		f, ok1 := parseAddr(pr.First)
		l, ok2 := parseAddr(pr.Last)
		if !ok1 || !ok2 {
			return ipam.Network{}, "a pool needs a first and a last IP address"
		}
		n.Pools = append(n.Pools, ipam.Pool{Name: pr.Name, First: f, Last: l})
	}
	return n, ""
}

func (in assetRequest) asset() (ipam.Asset, string) {
	a := ipam.Asset{ID: in.ID, Name: in.Name, Kind: ipam.Kind(in.Kind), Hostname: strings.ToLower(strings.TrimSpace(in.Hostname)),
		MAC: in.MAC, Notes: in.Notes}
	if len(in.Addresses) > ipam.MaxAddresses {
		return ipam.Asset{}, "too many addresses"
	}
	for _, s := range in.Addresses {
		ad, ok := parseAddr(s)
		if !ok {
			return ipam.Asset{}, "an address is not an IP address"
		}
		a.Addresses = append(a.Addresses, ad)
	}
	return a, ""
}

// answerIPAMError maps a store error: validation text is shown, not found
// is 404, anything else is logged.
func (h *Handler) answerIPAMError(w http.ResponseWriter, op string, err error) {
	var ve *ipam.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSONError(w, http.StatusBadRequest, ve.Reason)
	case errors.Is(err, ipam.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "not found")
	default:
		h.log.Error(op, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "network data unavailable")
	}
}

func (h *Handler) handleNetworkSave(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	var in networkRequest
	if !readOpsJSON(w, r, &in) {
		return
	}
	n, msg := in.network()
	if msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.network.SaveNetwork(ctx, n); err != nil {
		h.answerIPAMError(w, "save network", err)
		return
	}
	h.log.Info("audit", "kind", "network_saved", "network", n.ID, "prefix", n.Prefix.String(), "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]string{"id": n.ID})
}

func (h *Handler) handleNetworkDelete(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.network.DeleteNetwork(ctx, in.ID); err != nil {
		h.answerIPAMError(w, "delete network", err)
		return
	}
	h.log.Info("audit", "kind", "network_deleted", "network", in.ID, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleIPEntry(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Address string `json:"address"`
		Kind    string `json:"kind"` // reserved, excluded or "" to clear
		Note    string `json:"note"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ad, ok := parseAddr(in.Address)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "the address is not an IP address")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	var err error
	if in.Kind == "" {
		err = h.network.ClearEntry(ctx, ad)
	} else {
		err = h.network.SetEntry(ctx, webUser(r), ad, in.Kind, in.Note)
	}
	if err != nil {
		h.answerIPAMError(w, "ip entry", err)
		return
	}
	kind := in.Kind
	if kind == "" {
		kind = "cleared"
	}
	h.log.Info("audit", "kind", "ip_entry", "address", ad.String(), "entry", kind, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleAssetSave(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	var in assetRequest
	if !readOpsJSON(w, r, &in) {
		return
	}
	a, msg := in.asset()
	if msg != "" {
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.network.SaveAsset(ctx, a); err != nil {
		h.answerIPAMError(w, "save asset", err)
		return
	}
	h.log.Info("audit", "kind", "asset_saved", "asset", a.ID, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]string{"id": a.ID})
}

func (h *Handler) handleAssetDelete(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if err := h.network.DeleteAsset(ctx, in.ID); err != nil {
		h.answerIPAMError(w, "delete asset", err)
		return
	}
	h.log.Info("audit", "kind", "asset_deleted", "asset", in.ID, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAssetLink links an asset to the managed host it became (after
// "add to managed hosts" created the host). The host must exist.
func (h *Handler) handleAssetLink(w http.ResponseWriter, r *http.Request) {
	if h.network == nil || h.inventory == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		Asset string `json:"asset"`
		Host  string `json:"host"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	if in.Host != "" {
		if _, err := h.inventory.Get(ctx, in.Host); err != nil {
			if errors.Is(err, inventory.ErrHostNotFound) {
				writeJSONError(w, http.StatusNotFound, "host not found")
				return
			}
			h.log.Error("get host", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "inventory unavailable")
			return
		}
	}
	if err := h.network.LinkHost(ctx, in.Asset, in.Host); err != nil {
		h.answerIPAMError(w, "link asset", err)
		return
	}
	h.log.Info("audit", "kind", "asset_linked", "asset", in.Asset, "host", in.Host, "user", webUser(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// assetPrefill returns the inventory form prefill for "add to managed
// hosts" (JSON for a data attribute), or "" when the asset is unknown or
// already linked.
func (h *Handler) assetPrefill(ctx context.Context, id string) string {
	if h.network == nil || id == "" {
		return ""
	}
	a, err := h.network.Asset(ctx, id)
	if err != nil || a.HostID != "" {
		return ""
	}
	endpoints := []string{}
	for _, ad := range a.Addresses {
		if ad.Is6() {
			endpoints = append(endpoints, "["+ad.String()+"]:22")
		} else {
			endpoints = append(endpoints, ad.String())
		}
	}
	if len(endpoints) == 0 && a.Hostname != "" {
		endpoints = append(endpoints, a.Hostname)
	}
	js, err := json.Marshal(map[string]any{"asset": a.ID, "id": a.ID, "display_name": a.Name, "endpoints": endpoints})
	if err != nil {
		return ""
	}
	return string(js)
}

// --- views ---

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func viewAsset(a ipam.Asset) assetRow {
	var ads []string
	for _, ad := range a.Addresses {
		ads = append(ads, ad.String())
	}
	return assetRow{ID: a.ID, Name: a.Name, Kind: string(a.Kind), Hostname: a.Hostname, MAC: a.MAC, Addresses: strings.Join(ads, ", "), HostID: a.HostID}
}

func viewAddress(v ipam.AddressView) addressCell {
	c := addressCell{Address: v.Address.String(), Status: string(v.Status), Why: v.Why}
	if v.Address.Is4() {
		b := v.Address.As4()
		c.Label = strconv.Itoa(int(b[3]))
	} else {
		c.Label = v.Address.String()
	}
	var claims []string
	for _, a := range v.Assets {
		claims = append(claims, "asset "+a)
	}
	for _, h := range v.Hosts {
		claims = append(claims, "host "+h)
	}
	if v.Entry != nil {
		claims = append(claims, v.Entry.Kind+" by "+v.Entry.By)
	}
	if v.Seen != nil {
		s := "seen " + v.Seen.At.UTC().Format("2006-01-02")
		if v.Seen.MAC != "" {
			s += " with MAC " + v.Seen.MAC
		}
		claims = append(claims, s)
	}
	c.Claims = strings.Join(claims, "; ")
	return c
}

func statusCounts(views []ipam.AddressView, listed bool) string {
	n := map[ipam.Status]int{}
	for _, v := range views {
		n[v.Status]++
	}
	var parts []string
	for _, s := range []ipam.Status{ipam.Assigned, ipam.Reserved, ipam.Discovered, ipam.Conflict, ipam.Free} {
		if s == ipam.Free && !listed {
			continue
		}
		if n[s] > 0 {
			parts = append(parts, strconv.Itoa(n[s])+" "+strings.ToLower(string(s)))
		}
	}
	if !listed {
		parts = append(parts, "too large to list")
	}
	return strings.Join(parts, ", ")
}

func networkDraft(n ipam.Network) string {
	in := networkRequest{ID: n.ID, Name: n.Name, Prefix: n.Prefix.String(), VLAN: n.VLAN, Gateway: addrText(n.Gateway), Notes: n.Notes, Pools: []poolRequest{}}
	for _, p := range n.Pools {
		in.Pools = append(in.Pools, poolRequest{Name: p.Name, First: p.First.String(), Last: p.Last.String()})
	}
	js, _ := json.Marshal(in)
	return string(js)
}

func assetDraft(a ipam.Asset) string {
	in := assetRequest{ID: a.ID, Name: a.Name, Kind: string(a.Kind), Hostname: a.Hostname, MAC: a.MAC, Notes: a.Notes, Addresses: []string{}}
	for _, ad := range a.Addresses {
		in.Addresses = append(in.Addresses, ad.String())
	}
	js, _ := json.Marshal(in)
	return string(js)
}
