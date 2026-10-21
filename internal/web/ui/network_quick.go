// SPDX-License-Identifier: AGPL-3.0-or-later
package ui

// The "Quick" network view: one screen to scan a network, see the devices and
// the networks at a glance. The full IPAM view stays available as "Expert".
//
// Everything that comes from a managed host or a scan is untrusted: it is
// rendered as text only, through html/template. The quick scan reuses the
// existing discovery Submit path, so its limits (target inside a known
// network, at most a /16, one queued scan) apply unchanged.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/discovery"
	"github.com/nebula-operation-station/nebula-operation-station/internal/discoveryjob"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
)

// networkModeCookie remembers the chosen network view (quick/expert).
const networkModeCookie = "nebula_network_mode"

// The two network views. Quick is the default.
const (
	networkModeQuick  = "quick"
	networkModeExpert = "expert"
)

// defaultScanCIDR is the fallback when neither a configured network nor a
// private server address is available.
const defaultScanCIDR = "192.168.1.0/24"

// validNetworkMode reports whether m is an accepted network view.
func validNetworkMode(m string) bool {
	return m == networkModeQuick || m == networkModeExpert
}

// networkModeCookie builds the nebula_network_mode cookie with the same
// security attributes as the theme cookie.
func (h *Handler) networkModeCookie(value string, r *http.Request) *http.Cookie {
	return &http.Cookie{
		Name:     networkModeCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.themeSecure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   themeCookieMaxAge,
	}
}

// networkModeFromRequest resolves the network view: the ?mode= parameter wins
// (and is remembered in a cookie), then the cookie, then quick. The second
// result is true when the caller should set the cookie to the returned mode.
func (h *Handler) networkModeFromRequest(r *http.Request) (string, bool) {
	if m := r.URL.Query().Get("mode"); validNetworkMode(m) {
		return m, true
	}
	if c, err := r.Cookie(networkModeCookie); err == nil && validNetworkMode(c.Value) {
		return c.Value, false
	}
	return networkModeQuick, false
}

// scanPrefillCIDR picks the CIDR shown in the quick-scan input: the first
// configured network's prefix, or the /24 of the given server address. It never
// uses host data.
func scanPrefillCIDR(nets []ipam.Network, serverIP netip.Addr) string {
	if len(nets) > 0 {
		return nets[0].Prefix.String()
	}
	if serverIP.IsValid() && serverIP.Is4() {
		b4 := serverIP.As4()
		b4[3] = 0 // clear the host octet: the /24 that contains the address
		return netip.PrefixFrom(netip.AddrFrom4(b4), 24).String()
	}
	return defaultScanCIDR
}

// serverPrivateIPv4 returns the first private IPv4 of the server's own
// interfaces (10/8, 172.16/12, 192.168/16), or an invalid address.
func serverPrivateIPv4() netip.Addr {
	ifaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			pn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := pn.IP.To4()
			if ip == nil || !isPrivateIPv4(ip) {
				continue
			}
			return netip.AddrFrom4([4]byte(ip))
		}
	}
	return netip.Addr{}
}

// isPrivateIPv4 reports whether ip (4 bytes) is in a private range.
func isPrivateIPv4(ip net.IP) bool {
	if ip[0] == 10 {
		return true
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}
	return ip[0] == 192 && ip[1] == 168
}

// deviceRow is one row of the merged "Devices" list: a saved asset or a
// discovery sighting that is not an asset yet.
type deviceRow struct {
	Address  string
	Name     string // asset name, or the scan's hostname, or the address
	Hostname string // for "Save as device"
	MAC      string
	Vendor   string
	SSH      string // "yes", "no" or "" (not scanned)
	Managed  string // managed host ID, for the badge and its link
	AssetID  string // "" when the row is not a saved asset yet
	// CanSave shows "Save as device" (a sighting not yet an asset).
	CanSave bool
	// CanEnroll shows "Add as managed host" (a saved asset, not linked yet).
	CanEnroll bool
}

// networkQuickData is the data of the quick network view.
type networkQuickData struct {
	Mode string
	// ScanCIDR prefills the "Scan a network" input.
	ScanCIDR string
	// ScanEnabled is true when nebula-discovery can queue a scan.
	ScanEnabled bool
	// ScanNote explains, in one sentence, how to enable discovery. Shown only
	// when ScanEnabled is false.
	ScanNote string
	// Devices is the merged list of assets and the latest discovery results.
	Devices []deviceRow
	// Networks are the compact rows with a usage bar.
	Networks []quickNetworkRow
}

// quickNetworkRow is one network in the quick "Networks" card.
type quickNetworkRow struct {
	ID, Name, Prefix, Counts string
	VLAN                     int
	// BarClass is the usage bar class (bar-0 .. bar-100) or "" when the
	// network is too large to list.
	BarClass string
}

// buildNetworkQuick assembles the quick view. It returns an error only when
// the network data itself is unavailable (matching the expert view).
func (h *Handler) buildNetworkQuick(ctx context.Context, mode string) (*networkQuickData, error) {
	data := &networkQuickData{
		Mode:        mode,
		ScanEnabled: h.discovery != nil && h.discovery.Available(),
	}
	if !data.ScanEnabled {
		data.ScanNote = "Discovery is not enabled on this machine; install the nmap package and the discovery spool to scan, as described in the handbook."
	}
	nets, err := h.network.Networks(ctx)
	if err != nil {
		return nil, err
	}
	data.ScanCIDR = scanPrefillCIDR(nets, h.serverIP())
	views, listed, err := h.network.StatusMany(ctx, nets)
	if err != nil {
		h.log.Error("network status", "error", err)
	}
	for _, n := range nets {
		row := quickNetworkRow{ID: n.ID, Name: n.Name, Prefix: n.Prefix.String(), VLAN: n.VLAN}
		if views != nil {
			row.Counts = statusCounts(views[n.ID], listed[n.ID])
			row.BarClass = usageBarClass(views[n.ID], listed[n.ID])
		}
		data.Networks = append(data.Networks, row)
	}
	assets, err := h.network.Assets(ctx)
	if err != nil {
		return nil, err
	}
	data.Devices = mergeDevices(assets, h.latestDiscoveryRows(ctx))
	return data, nil
}

// latestDiscoveryRows returns the rows of the most recent finished discovery
// job, or nil when discovery is unavailable or no job has finished yet.
func (h *Handler) latestDiscoveryRows(ctx context.Context) []discovery.Row {
	if h.discovery == nil || !h.discovery.Available() {
		return nil
	}
	jobs, err := h.discovery.Jobs(ctx, 50)
	if err != nil {
		return nil
	}
	for _, j := range jobs {
		if j.State != discovery.StateDone {
			continue
		}
		if _, rows, err := h.discovery.Job(ctx, j.ID); err != nil {
			return nil
		} else {
			return rows
		}
	}
	return nil
}

// mergeDevices combines saved assets with the latest discovery results into one
// list, sorted by address. Assets always appear; a discovery row appears when
// it is not already an asset (matched by asset or by a known address).
func mergeDevices(assets []ipam.Asset, rows []discovery.Row) []deviceRow {
	byAddr := make(map[string]struct{}, len(assets))
	out := make([]deviceRow, 0, len(assets)+len(rows))
	for _, a := range assets {
		name := a.Name
		if name == "" {
			name = a.Hostname
		}
		if name == "" && len(a.Addresses) > 0 {
			name = a.Addresses[0].String()
		}
		out = append(out, deviceRow{
			Address: firstAddr(a.Addresses), Name: name, Hostname: a.Hostname, MAC: a.MAC,
			Managed: a.HostID, AssetID: a.ID, CanEnroll: a.HostID == "",
		})
		for _, ad := range a.Addresses {
			byAddr[strings.ToLower(ad.String())] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(rows))
	for _, r := range rows {
		key := strings.ToLower(r.Address)
		if r.MatchAsset != "" {
			continue // already an asset
		}
		if _, known := byAddr[key]; known {
			continue // same address as a saved asset
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		name := r.Hostname
		if name == "" {
			name = r.Address
		}
		out = append(out, deviceRow{
			Address: r.Address, Name: name, Hostname: r.Hostname, MAC: r.MAC, Vendor: r.Vendor,
			SSH: sshState(r.Ports), Managed: r.MatchHost, CanSave: true,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address == out[j].Address {
			return out[i].Name < out[j].Name
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// sshState reports whether port 22/tcp is open in the scanned ports.
func sshState(ports []discoveryjob.Port) string {
	for _, p := range ports {
		if p.Port == 22 && p.Protocol == "tcp" && p.State == "open" {
			return "yes"
		}
	}
	return "no"
}

// firstAddr returns the string form of the first address, or "".
func firstAddr(ads []netip.Addr) string {
	if len(ads) == 0 {
		return ""
	}
	return ads[0].String()
}

// usageBarClass maps the used/total address ratio to a CSS class in 10% steps
// (bar-0 .. bar-100). It uses the same address views as the counts text, so the
// bar and the numbers always agree. It returns "" when the network is too large
// to list (no per-address data).
func usageBarClass(views []ipam.AddressView, listed bool) string {
	if !listed {
		return ""
	}
	total := len(views)
	if total == 0 {
		return "bar-0"
	}
	free := 0
	for _, v := range views {
		if v.Status == ipam.Free {
			free++
		}
	}
	used := total - free
	pct := used * 100 / total
	step := (pct + 5) / 10 // round to the nearest 10%
	if step > 10 {
		step = 10
	}
	return fmt.Sprintf("bar-%d", step*10)
}

// handleNetworkScan is the "Scan" button of the quick view. It creates the
// network for the CIDR when it does not exist yet (name = prefix) and, when
// discovery is enabled, queues a port scan through the existing discovery path.
// It answers JSON: {"network": id, "job": id-or-empty}.
func (h *Handler) handleNetworkScan(w http.ResponseWriter, r *http.Request) {
	if h.network == nil {
		http.NotFound(w, r)
		return
	}
	var in struct {
		CIDR string `json:"cidr"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(in.CIDR))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "the network must be a prefix such as 192.168.10.0/24")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	user := webUser(r)

	nets, err := h.network.Networks(ctx)
	if err != nil {
		h.answerIPAMError(w, "list networks", err)
		return
	}
	netID, found := "", false
	for _, n := range nets {
		if n.Prefix == prefix {
			netID, found = n.ID, true
			break
		}
	}
	if !found {
		netID = uniqueNetworkID(nets, networkIDForPrefix(prefix))
		n := ipam.Network{ID: netID, Name: prefix.String(), Prefix: prefix}
		if err := h.network.SaveNetwork(ctx, n); err != nil {
			h.answerIPAMError(w, "create network", err)
			return
		}
		h.log.Info("audit", "kind", "network_saved", "network", netID, "prefix", prefix.String(), "origin", "quick_scan", "user", user)
	}

	if h.discovery == nil || !h.discovery.Available() {
		writeJSON(w, http.StatusOK, map[string]any{"network": netID, "job": ""})
		return
	}
	// The quick scan is a port scan for SSH, so the Devices card can show open
	// SSH. It goes through the same Submit path as the discovery page, so its
	// limits (target inside a known network, at most a /16, one queued scan)
	// apply unchanged.
	req := discovery.Request{Mode: discoveryjob.ModePorts, Targets: []string{prefix.String()}, Ports: "22"}
	j, err := h.discovery.Submit(ctx, user, req)
	if err != nil {
		h.answerDiscoveryError(w, "submit discovery", err)
		return
	}
	h.log.Info("audit", "kind", "discovery_queued", "job", j.ID, "targets", j.Targets, "scan", j.Description, "origin", "quick_scan", "user", user)
	writeJSON(w, http.StatusOK, map[string]any{"network": netID, "job": j.ID})
}

// networkIDForPrefix builds a valid network ID from a prefix (lowercase, only
// letters, digits, . _ -). "192.168.10.0/24" becomes "192.168.10.0.24".
func networkIDForPrefix(prefix netip.Prefix) string {
	s := strings.ToLower(strings.NewReplacer("/", ".", ":", ".", " ", "_").Replace(prefix.String()))
	for len(s) > 0 && !isIDStart(s[0]) {
		s = s[1:]
	}
	if len(s) > 63 {
		s = s[:63]
	}
	if s == "" {
		s = "net"
	}
	return s
}

// isIDStart reports whether c may start a network ID.
func isIDStart(c byte) bool {
	return c >= '0' && c <= '9'
}

// uniqueNetworkID returns id, or id with a numeric suffix, so it does not
// collide with an existing network ID.
func uniqueNetworkID(nets []ipam.Network, id string) string {
	taken := make(map[string]struct{}, len(nets))
	for _, n := range nets {
		taken[n.ID] = struct{}{}
	}
	if _, ok := taken[id]; !ok {
		return id
	}
	for i := 2; ; i++ {
		cand := fmt.Sprintf("%s-%d", id, i)
		if len(cand) > 63 {
			cand = id[:63-len(fmt.Sprintf("-%d", i))] + fmt.Sprintf("-%d", i)
		}
		if _, ok := taken[cand]; !ok {
			return cand
		}
	}
}
