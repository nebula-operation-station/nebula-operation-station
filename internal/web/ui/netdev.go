// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// Network device pages (ADR 0010, ND-19 part 1): a read-only list and
// detail view of the stored device inventory (internal/netdevinventory).
//
// Every string the pages show from the store is device text: it was
// validated by netdevcontract but is otherwise attacker-controlled. It is
// rendered as text only (html/template escaping), with Unicode format and
// control characters (bidi overrides and the like) replaced by U+FFFD and
// long values shortened (netdevText). Deep links to a device's own web UI
// are built from the registry's approved endpoints only, never from
// device-reported addresses, and are plain links that open without opener
// and referrer; nothing is embedded or framed. The pages use the layout and
// static assets only, so the strict CSP of internal/web/middleware applies
// unchanged.

// netdevCallTimeout bounds the store and registry reads made while
// rendering a network device page.
const netdevCallTimeout = 5 * time.Second

// netdevDeviceLimit caps the devices on the list page; a homelab has far
// fewer.
const netdevDeviceLimit = 500

// netdevMACPageSize is the number of MAC table entries per detail page.
const netdevMACPageSize = 200

// netdevMACMaxPages is the last MAC table page that can exist: the store
// keeps at most netdevcontract.MaxMACEntriesPerDevice entries.
const netdevMACMaxPages = (netdevcontract.MaxMACEntriesPerDevice + netdevMACPageSize - 1) / netdevMACPageSize

// netdevMACPageDigits bounds the length of the mac_page query value.
const netdevMACPageDigits = 4

// netdevTextMaxBytes is the longest device text shown in full; longer text
// is cut at a rune boundary and ends in an ellipsis.
const netdevTextMaxBytes = 256

// The netdev*Max limits cap the rows of each detail list (ports, VLANs, LLDP
// neighbors, zones, interfaces) at the contract limits, so a store that
// returned more could not blow up a page.
const (
	netdevPortsMax      = netdevcontract.MaxInterfacesPerDevice
	netdevVLANsMax      = netdevcontract.MaxVLANsPerDevice
	netdevLLDPMax       = netdevcontract.MaxLLDPNeighborsPerDevice
	netdevZonesMax      = netdevcontract.MaxZones
	netdevFwIfacesMax   = netdevcontract.MaxFirewallInterfaces
	netdevAddrsMax      = netdevcontract.MaxManagementAddresses
	netdevAllowedVLANsN = 32
)

// NetDevStore is the read-only part of the network device inventory the
// pages use. The row readers return the rows of the current dataset of a
// read, or an error matching netdevinventory.ErrDatasetNotFound when none
// is stored; GetDevice returns netdevinventory.ErrDeviceNotFound for an
// unknown device. Every returned string is untrusted device text.
type NetDevStore interface {
	// ListDevices returns at most limit devices in device ID order.
	ListDevices(ctx context.Context, limit int) ([]netdevinventory.Device, error)
	// GetDevice returns one device.
	GetDevice(ctx context.Context, deviceID string) (netdevinventory.Device, error)
	// GetDataset returns the status of the current dataset of a read.
	GetDataset(ctx context.Context, deviceID string, read netdevinventory.Read) (netdevinventory.Dataset, error)
	// Facts returns the current device facts.
	Facts(ctx context.Context, deviceID string) (netdevcontract.Facts, error)
	// VLANs returns the current VLAN list (CBS).
	VLANs(ctx context.Context, deviceID string) ([]netdevcontract.VLAN, error)
	// Ports returns the current switch ports (CBS).
	Ports(ctx context.Context, deviceID string) ([]netdevcontract.Port, error)
	// MACEntries returns at most limit MAC table entries from offset, in
	// stored order, and the total number of entries (CBS).
	MACEntries(ctx context.Context, deviceID string, offset, limit int) ([]netdevcontract.MACEntry, int, error)
	// LLDPNeighbors returns the current LLDP neighbors (CBS).
	LLDPNeighbors(ctx context.Context, deviceID string) ([]netdevcontract.LLDPNeighbor, error)
	// FirewallPolicy returns the current firewall policy (PAN-OS).
	FirewallPolicy(ctx context.Context, deviceID string) (netdevcontract.FirewallPolicy, error)
}

// NetDevRegistryEntry is the executor registry's approved metadata of one
// network device (never device-provided).
type NetDevRegistryEntry struct {
	// DeviceID identifies the device in the inventory store.
	DeviceID string
	// Name is the admin-given display name.
	Name string
	// Family is the device family.
	Family netdevcontract.Family
	// Endpoints are the approved management endpoints, in dial order.
	Endpoints []netdevcontract.Endpoint
	// WebUIScheme is the scheme of a CBS switch's web UI on its first
	// endpoint: "https", "http", or "" for no deep link. PAN-OS devices
	// ignore it: their web UI is always HTTPS on the API endpoint.
	WebUIScheme string
	// TrustGeneration is the registry's current trust generation.
	TrustGeneration uint64
}

// NetDevRegistryFunc returns the registry metadata of all network
// devices. An error is logged and treated as "no metadata": the pages
// render without deep links and with the stored labels.
type NetDevRegistryFunc func(ctx context.Context) ([]NetDevRegistryEntry, error)

// NetDevAdminFunc reports whether the logged-in web user has the admin
// role. An error denies access.
type NetDevAdminFunc func(ctx context.Context, user string) (bool, error)

// NetDevOptions configure the network device pages.
type NetDevOptions struct {
	// Store reads the stored device inventory. Required.
	Store NetDevStore
	// Registry returns the approved device metadata. Nil hides deep links.
	Registry NetDevRegistryFunc
	// IsAdmin is the admin role check. Required: without it the pages
	// would have no access check of their own.
	IsAdmin NetDevAdminFunc
}

// NetDevPages serves GET /netdev and GET /netdev/{id}.
type NetDevPages struct {
	h     *Handler
	o     NetDevOptions
	pages map[string]*template.Template
}

// netdevPageFiles maps the netdev content names to their template files.
var netdevPageFiles = map[string]string{
	"netdev":        "netdev.html",
	"netdev_detail": "netdev_detail.html",
}

// NetDevPages returns the network device pages rendered in this
// handler's layout. Store and IsAdmin are required.
func (h *Handler) NetDevPages(o NetDevOptions) (*NetDevPages, error) {
	if o.Store == nil {
		return nil, errors.New("ui: network device pages need a store")
	}
	if o.IsAdmin == nil {
		return nil, errors.New("ui: network device pages need an admin check")
	}
	pages := make(map[string]*template.Template, len(netdevPageFiles))
	for name, file := range netdevPageFiles {
		set, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "layout.html", file)
		if err != nil {
			return nil, fmt.Errorf("ui: parse template %s: %w", name, err)
		}
		pages[name] = set
	}
	return &NetDevPages{h: h, o: o, pages: pages}, nil
}

// Register adds the network device routes to mux. The routes take every
// method so that a non-GET request is answered 405 here instead of
// falling through to a catch-all pattern.
func (p *NetDevPages) Register(mux *http.ServeMux) {
	mux.HandleFunc("/netdev", p.handleList)
	mux.HandleFunc("/netdev/{id}", p.handleDetail)
}

// netdevPageData is the layout data plus the netdev page data. The
// embedded pageData gives the layout every field it uses.
type netdevPageData struct {
	pageData
	// NetDevList is the data of the device list page.
	NetDevList *netdevListData
	// NetDevDetail is the data of a device's detail page.
	NetDevDetail *netdevDetailData
}

// netdevBadge is one staleness badge.
type netdevBadge struct {
	// Text is the badge text.
	Text string
	// State is the state alone ("fresh", "partial", "stale", "never
	// read", "unknown"), for the detail page's dataset table.
	State string
	// Class is the badge modifier class ("ok", "warning", "unknown").
	Class string
}

// netdevDatasetRow is one dataset of a device.
type netdevDatasetRow struct {
	// Read is the dataset name.
	Read string
	// Badge is the state badge.
	Badge netdevBadge
	// ObservedAt is the stored observation time; zero if never read.
	ObservedAt time.Time
	// Age is a short relative age of ObservedAt.
	Age string
	// Rows is the number of rows the read contained.
	Rows int
}

// netdevRow is one row of the list page.
type netdevRow struct {
	DetailURL       string
	Label           string
	Family          string
	Endpoint        string
	TrustGeneration uint64
	// TrustNote flags a registry trust generation other than the stored
	// one (the device was re-pinned since the last stored read).
	TrustNote string
	LastSeen  time.Time
	Age       string
	// Stale is set when the device itself is stale.
	Stale    bool
	Datasets []netdevDatasetRow
	Link     string
}

// netdevListData is the data of the list page.
type netdevListData struct {
	Unavailable bool
	Rows        []netdevRow
}

// netdevPortRow is one switch port.
type netdevPortRow struct {
	Name, Admin, Oper, Speed, Mode, VLANs, Description string
}

// netdevVLANRow is one VLAN.
type netdevVLANRow struct {
	ID   uint16
	Name string
}

// netdevMACRow is one MAC table entry.
type netdevMACRow struct {
	VLAN            uint16
	MAC, Port, Type string
}

// netdevLLDPRow is one LLDP neighbor.
type netdevLLDPRow struct {
	LocalPort, ChassisID, PortID, SystemName, ManagementAddress, Capabilities string
}

// netdevZoneRow is one PAN-OS zone.
type netdevZoneRow struct {
	Name, Interfaces string
}

// netdevFwIfaceRow is one PAN-OS interface.
type netdevFwIfaceRow struct {
	Name, VLAN, Addresses, Zone string
}

// netdevMACPage is the paging state of the MAC table.
type netdevMACPage struct {
	Page, Pages, Total int
	PrevURL, NextURL   string
}

// netdevPolicySummary is the PAN-OS policy summary.
type netdevPolicySummary struct {
	SecurityRules, NATRules, Objects int
}

// netdevDetailData is the data of a device's detail page.
type netdevDetailData struct {
	Label           string
	DeviceID        string
	Family          string
	IsCBS, IsPANOS  bool
	Endpoint        string
	TrustGeneration uint64
	TrustNote       string
	LastSeen        time.Time
	Age             string
	Stale           bool
	Link            string
	Datasets        []netdevDatasetRow

	// Facts.
	HasFacts                         bool
	Model, Version, Serial, Hostname string
	ManagementAddresses              string

	Ports       []netdevPortRow
	VLANs       []netdevVLANRow
	MACs        []netdevMACRow
	MACPage     netdevMACPage
	LLDP        []netdevLLDPRow
	HasPolicy   bool
	Policy      netdevPolicySummary
	Zones       []netdevZoneRow
	FwIfaces    []netdevFwIfaceRow
	Unavailable []string
}

// netdevReads lists the reads of a family in display order.
func netdevReads(f netdevcontract.Family) []netdevinventory.Read {
	switch f {
	case netdevcontract.FamilyCBS:
		return []netdevinventory.Read{netdevinventory.ReadFacts, netdevinventory.ReadPorts, netdevinventory.ReadVLANs,
			netdevinventory.ReadMACTable, netdevinventory.ReadLLDPNeighbors}
	case netdevcontract.FamilyPANOS:
		return []netdevinventory.Read{netdevinventory.ReadFacts, netdevinventory.ReadFirewallPolicy, netdevinventory.ReadHitCounts}
	}
	return []netdevinventory.Read{netdevinventory.ReadFacts}
}

// netdevText makes device text safe to show as one line: Unicode control
// and format characters (bidi overrides, zero-width joiners, newlines) and
// invalid UTF-8 become U+FFFD, and text over netdevTextMaxBytes is cut at a
// rune boundary and ends in "…". HTML escaping is left to html/template.
func netdevText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= netdevTextMaxBytes {
			// More runes follow: mark the cut.
			b.WriteString("…")
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
	}
	return b.String()
}

// netdevJoin shows a list of device text values, comma separated.
func netdevJoin(vs []string) string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, netdevText(v))
	}
	return netdevText(strings.Join(out, ", "))
}

// netdevDatasetBadge maps a dataset state to its badge.
func netdevDatasetBadge(read netdevinventory.Read, state netdevinventory.DatasetState, found bool) netdevBadge {
	b := netdevBadge{State: "unknown", Class: "unknown"}
	switch {
	case !found:
		b.State = "never read"
	case state == netdevinventory.StateFresh:
		b.State, b.Class = "fresh", "ok"
	case state == netdevinventory.StatePartial:
		b.State, b.Class = "partial", "warning"
	case state == netdevinventory.StateStale:
		b.State, b.Class = "stale", "warning"
	}
	b.Text = string(read) + ": " + b.State
	return b
}

// datasets reads the dataset states of a device. A store error is logged
// and shown as "unknown".
func (p *NetDevPages) datasets(ctx context.Context, d netdevinventory.Device, now time.Time) []netdevDatasetRow {
	reads := netdevReads(d.Family)
	rows := make([]netdevDatasetRow, 0, len(reads))
	for _, read := range reads {
		ds, err := p.o.Store.GetDataset(ctx, d.DeviceID, read)
		switch {
		case errors.Is(err, netdevinventory.ErrDatasetNotFound):
			rows = append(rows, netdevDatasetRow{Read: string(read), Badge: netdevDatasetBadge(read, "", false)})
		case err != nil:
			p.h.log.Error("get network device dataset", "device", d.DeviceID, "read", string(read), "error", err)
			rows = append(rows, netdevDatasetRow{Read: string(read), Badge: netdevDatasetBadge(read, "", true)})
		default:
			rows = append(rows, netdevDatasetRow{
				Read:       string(read),
				Badge:      netdevDatasetBadge(read, ds.State, true),
				ObservedAt: ds.ObservedAt,
				Age:        pveAge(now, ds.ObservedAt),
				Rows:       ds.RowCount,
			})
		}
	}
	return rows
}

// registry maps the registry metadata by device ID. An error is logged;
// the pages then render without deep links (fail closed).
func (p *NetDevPages) registry(ctx context.Context) map[string]NetDevRegistryEntry {
	if p.o.Registry == nil {
		return nil
	}
	entries, err := p.o.Registry(ctx)
	if err != nil {
		p.h.log.Error("list network device registry", "error", err)
		return nil
	}
	out := make(map[string]NetDevRegistryEntry, len(entries))
	for _, e := range entries {
		out[e.DeviceID] = e
	}
	return out
}

// netdevEndpointText shows an approved endpoint as address:port.
func netdevEndpointText(eps []netdevcontract.Endpoint) string {
	if len(eps) == 0 || !netdevcontract.ValidEndpointAddress(eps[0].Address) {
		return "—"
	}
	a, err := netip.ParseAddr(eps[0].Address)
	if err != nil {
		return "—"
	}
	return netip.AddrPortFrom(a, eps[0].Port).String()
}

// netdevDeepLink builds the link to a device's web UI from the registry
// entry only: the first approved endpoint, which must be a valid private
// IP literal, over HTTPS for PAN-OS (on the API port) and over the
// registry's WebUIScheme for CBS (on the scheme's default port; the
// endpoint port is SSH). Anything else gives "": no link. The registry
// entry must belong to the stored device's family.
func netdevDeepLink(e NetDevRegistryEntry, family netdevcontract.Family) string {
	if e.Family != family || len(e.Endpoints) == 0 {
		return ""
	}
	ep := e.Endpoints[0]
	if !netdevcontract.ValidEndpointAddress(ep.Address) {
		return ""
	}
	a, err := netip.ParseAddr(ep.Address)
	if err != nil {
		return ""
	}
	host := a.String()
	if a.Is6() {
		host = "[" + host + "]"
	}
	var scheme string
	switch family {
	case netdevcontract.FamilyPANOS:
		scheme = "https"
		if ep.Port != 0 && ep.Port != 443 {
			host += ":" + strconv.Itoa(int(ep.Port))
		}
	case netdevcontract.FamilyCBS:
		switch e.WebUIScheme {
		case "https", "http":
			scheme = e.WebUIScheme
		default:
			return ""
		}
	default:
		return ""
	}
	return (&url.URL{Scheme: scheme, Host: host, Path: "/"}).String()
}

// netdevTrustNote flags a registry trust generation other than the stored
// one.
func netdevTrustNote(e NetDevRegistryEntry, ok bool, stored uint64) string {
	if !ok || e.TrustGeneration == stored {
		return ""
	}
	return fmt.Sprintf("re-pinned: registry generation %d, stored data from generation %d", e.TrustGeneration, stored)
}

// netdevLabel picks the shown name: the registry name (approved
// metadata), else the stored label (device text), else the device ID.
func netdevLabel(e NetDevRegistryEntry, d netdevinventory.Device) string {
	switch {
	case e.Name != "":
		return netdevText(e.Name)
	case d.Label != "":
		return netdevText(d.Label)
	}
	return d.DeviceID
}

// authorize answers 403 unless the request carries a web session of an
// admin. It reports whether the handler may continue.
func (p *NetDevPages) authorize(w http.ResponseWriter, r *http.Request) bool {
	s, ok := auth.SessionFrom(r.Context())
	if !ok || s.UserName == "" {
		http.Error(w, "forbidden: network device pages need the admin role", http.StatusForbidden)
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), netdevCallTimeout)
	defer cancel()
	admin, err := p.o.IsAdmin(ctx, s.UserName)
	if err != nil {
		p.h.log.Error("network device pages: admin check", "error", err)
		admin = false
	}
	if !admin {
		http.Error(w, "forbidden: network device pages need the admin role", http.StatusForbidden)
		return false
	}
	return true
}

// methodOK answers 405 for anything but GET and HEAD.
func netdevMethodOK(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (p *NetDevPages) handleList(w http.ResponseWriter, r *http.Request) {
	if !netdevMethodOK(w, r) || !p.authorize(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), netdevCallTimeout)
	defer cancel()
	devices, err := p.o.Store.ListDevices(ctx, netdevDeviceLimit)
	if err != nil {
		p.h.log.Error("list network devices", "error", err)
		p.render(w, r, netdevPageData{pageData: pageData{Title: "Network devices", Active: "netdev", Content: "netdev"},
			NetDevList: &netdevListData{Unavailable: true}})
		return
	}
	reg := p.registry(ctx)
	now := p.h.clockNow()
	rows := make([]netdevRow, 0, len(devices))
	for _, d := range devices {
		if !netdevcontract.ValidDeviceID(d.DeviceID) {
			continue
		}
		e, ok := reg[d.DeviceID]
		rows = append(rows, netdevRow{
			DetailURL:       "/netdev/" + url.PathEscape(d.DeviceID),
			Label:           netdevLabel(e, d),
			Family:          string(d.Family),
			Endpoint:        netdevEndpointText(e.Endpoints),
			TrustGeneration: d.TrustGeneration,
			TrustNote:       netdevTrustNote(e, ok, d.TrustGeneration),
			LastSeen:        d.LastSeen,
			Age:             pveAge(now, d.LastSeen),
			Stale:           d.State == netdevinventory.DeviceStale,
			Datasets:        p.datasets(ctx, d, now),
			Link:            netdevDeepLink(e, d.Family),
		})
	}
	p.render(w, r, netdevPageData{pageData: pageData{Title: "Network devices", Active: "netdev", Content: "netdev"},
		NetDevList: &netdevListData{Rows: rows}})
}

// netdevParseMACPage parses the mac_page query value: absent or empty is
// page 1, otherwise one value of 1 to netdevMACPageDigits ASCII digits,
// at least 1.
func netdevParseMACPage(q url.Values) (int, bool) {
	vs, ok := q["mac_page"]
	if !ok {
		return 1, true
	}
	if len(vs) != 1 {
		return 0, false
	}
	v := vs[0]
	if v == "" {
		return 1, true
	}
	if len(v) > netdevMACPageDigits {
		return 0, false
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 {
		return 0, false
	}
	return n, true
}

func (p *NetDevPages) handleDetail(w http.ResponseWriter, r *http.Request) {
	if !netdevMethodOK(w, r) || !p.authorize(w, r) {
		return
	}
	id := r.PathValue("id")
	if !netdevcontract.ValidDeviceID(id) {
		http.NotFound(w, r)
		return
	}
	macPage, ok := netdevParseMACPage(r.URL.Query())
	if !ok {
		http.Error(w, "bad request: mac_page must be a page number", http.StatusBadRequest)
		return
	}
	if macPage > netdevMACMaxPages {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), netdevCallTimeout)
	defer cancel()
	d, err := p.o.Store.GetDevice(ctx, id)
	if err != nil {
		if errors.Is(err, netdevinventory.ErrDeviceNotFound) {
			http.NotFound(w, r)
			return
		}
		p.h.log.Error("get network device", "device", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	e, inReg := p.registry(ctx)[id]
	now := p.h.clockNow()
	v := &netdevDetailData{
		Label:           netdevLabel(e, d),
		DeviceID:        d.DeviceID,
		Family:          string(d.Family),
		IsCBS:           d.Family == netdevcontract.FamilyCBS,
		IsPANOS:         d.Family == netdevcontract.FamilyPANOS,
		Endpoint:        netdevEndpointText(e.Endpoints),
		TrustGeneration: d.TrustGeneration,
		TrustNote:       netdevTrustNote(e, inReg, d.TrustGeneration),
		LastSeen:        d.LastSeen,
		Age:             pveAge(now, d.LastSeen),
		Stale:           d.State == netdevinventory.DeviceStale,
		Link:            netdevDeepLink(e, d.Family),
		Datasets:        p.datasets(ctx, d, now),
	}
	// rowErr records a failing read: "not read yet" is normal, anything
	// else is logged and listed as unavailable.
	rowErr := func(what string, err error) {
		if !errors.Is(err, netdevinventory.ErrDatasetNotFound) {
			p.h.log.Error("read network device dataset", "device", id, "dataset", what, "error", err)
			v.Unavailable = append(v.Unavailable, what)
		}
	}
	if f, err := p.o.Store.Facts(ctx, id); err != nil {
		rowErr("facts", err)
	} else {
		v.HasFacts = true
		v.Model = netdevText(f.Model)
		v.Version = netdevText(f.FirmwareVersion)
		v.Serial = netdevText(f.Serial)
		v.Hostname = netdevText(f.Hostname)
		v.ManagementAddresses = netdevJoin(f.ManagementAddresses[:min(len(f.ManagementAddresses), netdevAddrsMax)])
	}
	switch d.Family {
	case netdevcontract.FamilyCBS:
		if !p.cbsDetail(ctx, w, r, id, macPage, v, rowErr) {
			return
		}
	case netdevcontract.FamilyPANOS:
		if pol, err := p.o.Store.FirewallPolicy(ctx, id); err != nil {
			rowErr("firewall policy", err)
		} else {
			v.HasPolicy = true
			v.Policy = netdevPolicySummary{
				SecurityRules: len(pol.SecurityRules),
				NATRules:      len(pol.NATRules),
				Objects:       len(pol.Addresses) + len(pol.AddressGroups) + len(pol.Services) + len(pol.ServiceGroups),
			}
			for _, z := range pol.Zones[:min(len(pol.Zones), netdevZonesMax)] {
				v.Zones = append(v.Zones, netdevZoneRow{Name: netdevText(z.Name), Interfaces: netdevJoin(z.Interfaces)})
			}
			for _, fi := range pol.Interfaces[:min(len(pol.Interfaces), netdevFwIfacesMax)] {
				row := netdevFwIfaceRow{Name: netdevText(fi.Name), Addresses: netdevJoin(fi.Addresses), Zone: netdevText(fi.Zone)}
				if fi.VLANTag != nil {
					row.VLAN = strconv.Itoa(int(*fi.VLANTag))
				}
				v.FwIfaces = append(v.FwIfaces, row)
			}
		}
	}
	p.render(w, r, netdevPageData{pageData: pageData{Title: "Network device " + v.Label, Active: "netdev", Content: "netdev_detail"},
		NetDevDetail: v})
}

// cbsDetail fills the switch sections. It reports false when it already
// answered the request (a MAC page past the last one).
func (p *NetDevPages) cbsDetail(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, macPage int,
	v *netdevDetailData, rowErr func(string, error)) bool {
	if ports, err := p.o.Store.Ports(ctx, id); err != nil {
		rowErr("ports", err)
	} else {
		for _, pt := range ports[:min(len(ports), netdevPortsMax)] {
			v.Ports = append(v.Ports, netdevPortView(pt))
		}
	}
	if vlans, err := p.o.Store.VLANs(ctx, id); err != nil {
		rowErr("VLANs", err)
	} else {
		for _, vl := range vlans[:min(len(vlans), netdevVLANsMax)] {
			v.VLANs = append(v.VLANs, netdevVLANRow{ID: vl.ID, Name: netdevText(vl.Name)})
		}
	}
	offset := (macPage - 1) * netdevMACPageSize
	macs, total, err := p.o.Store.MACEntries(ctx, id, offset, netdevMACPageSize)
	switch {
	case err != nil:
		rowErr("MAC table", err)
		if macPage > 1 {
			http.NotFound(w, r)
			return false
		}
	default:
		total = max(0, min(total, netdevcontract.MaxMACEntriesPerDevice))
		pages := max(1, (total+netdevMACPageSize-1)/netdevMACPageSize)
		if macPage > pages {
			http.NotFound(w, r)
			return false
		}
		for _, m := range macs[:min(len(macs), netdevMACPageSize)] {
			v.MACs = append(v.MACs, netdevMACRow{VLAN: m.VLAN, MAC: netdevText(m.MAC), Port: netdevText(m.Port), Type: netdevText(string(m.Type))})
		}
		base := "/netdev/" + url.PathEscape(id) + "?mac_page="
		v.MACPage = netdevMACPage{Page: macPage, Pages: pages, Total: total}
		if macPage > 1 {
			v.MACPage.PrevURL = base + strconv.Itoa(macPage-1) + "#mac"
		}
		if macPage < pages {
			v.MACPage.NextURL = base + strconv.Itoa(macPage+1) + "#mac"
		}
	}
	if nbs, err := p.o.Store.LLDPNeighbors(ctx, id); err != nil {
		rowErr("LLDP neighbors", err)
	} else {
		for _, n := range nbs[:min(len(nbs), netdevLLDPMax)] {
			caps := make([]string, 0, len(n.Capabilities))
			for _, c := range n.Capabilities {
				caps = append(caps, string(c))
			}
			v.LLDP = append(v.LLDP, netdevLLDPRow{
				LocalPort:         netdevText(n.LocalPort),
				ChassisID:         netdevText(n.ChassisID),
				PortID:            netdevText(n.PortID),
				SystemName:        netdevText(n.SystemName),
				ManagementAddress: netdevText(n.ManagementAddress),
				Capabilities:      netdevJoin(caps),
			})
		}
	}
	return true
}

// netdevPortView renders one switch port.
func netdevPortView(pt netdevcontract.Port) netdevPortRow {
	row := netdevPortRow{
		Name:        netdevText(pt.Name),
		Admin:       netdevText(string(pt.AdminState)),
		Oper:        netdevText(string(pt.OperState)),
		Mode:        netdevText(string(pt.Mode)),
		Description: netdevText(pt.Description),
		Speed:       "—",
	}
	if pt.SpeedMbps != nil {
		row.Speed = strconv.FormatUint(*pt.SpeedMbps, 10) + " Mb/s"
	}
	var vlans []string
	if pt.AccessVLAN != nil {
		vlans = append(vlans, "access "+strconv.Itoa(int(*pt.AccessVLAN)))
	}
	if pt.NativeVLAN != nil {
		vlans = append(vlans, "native "+strconv.Itoa(int(*pt.NativeVLAN)))
	}
	if n := len(pt.AllowedVLANs); n > 0 {
		ids := make([]string, 0, min(n, netdevAllowedVLANsN))
		for _, id := range pt.AllowedVLANs[:min(n, netdevAllowedVLANsN)] {
			ids = append(ids, strconv.Itoa(int(id)))
		}
		s := "allowed " + strings.Join(ids, ",")
		if n > netdevAllowedVLANsN {
			s += fmt.Sprintf(" (+%d more)", n-netdevAllowedVLANsN)
		}
		vlans = append(vlans, s)
	}
	row.VLANs = strings.Join(vlans, "; ")
	return row
}

// render fills the layout fields the way Handler.render does and renders
// a netdev page into a buffer first, so an execution error answers 500
// without a partial page.
func (p *NetDevPages) render(w http.ResponseWriter, r *http.Request, data netdevPageData) {
	h := p.h
	if data.Theme == "" {
		data.Theme = themeFromRequest(r)
	}
	data.NavCollapsed = navStateFromRequest(r) == navCollapsed
	data.PVENav = h.pve != nil
	data.DeployEnabled = h.deploy != nil && h.pve != nil && h.pveRemotes != nil
	if h.builtinTrust != nil {
		data.BuiltinTrust = h.builtinTrust.get(r.Context())
	}
	set, ok := p.pages[data.Content]
	if !ok {
		http.Error(w, "internal error: unknown page", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := set.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("render page", "page", data.Content, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.log.Debug("write page", "page", data.Content, "error", err)
	}
}
