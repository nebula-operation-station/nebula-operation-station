// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// PAN-OS firewall view (ADR 0010 D4, ND-20): a read-only, admin-only page
// with the stored security rules in rulebase order, NAT rules in order,
// address and service objects with the number of rules that use them, and
// rule hit counts.
//
// The page reads only from the inventory store. Every device string is
// untrusted and rendered as text through netdevText and html/template. The
// unused-rule hint is an observation labelled with its window (zero hits
// for at least netdevUnusedMinObserved since the counter reset), never a
// change proposal: the page has no form and no button. Shadowed rules are
// not computed (ADR 0010: not in phase 1). The page uses the layout and
// static assets only, so the strict CSP of internal/web/middleware applies
// unchanged.

// netdevUnusedMinObserved is the shortest hit-count observation window
// for which a rule without hits gets the unused-rule hint.
const netdevUnusedMinObserved = 30 * 24 * time.Hour

// netdevUsageMaxSteps bounds the group expansion work of the object usage
// counts for one page; a policy that needs more shows no counts instead
// of keeping the server busy.
const netdevUsageMaxSteps = 2_000_000

// The netdevFw*Max limits cap the rows of each list of the firewall view
// at the contract limits, so a store that returned more could not blow up
// the page.
const (
	netdevFwRulesMax     = netdevcontract.MaxSecurityRules
	netdevFwNATMax       = netdevcontract.MaxNATRules
	netdevFwAddrsMax     = netdevcontract.MaxAddressObjects
	netdevFwAddrGrpMax   = netdevcontract.MaxAddressGroups
	netdevFwSvcsMax      = netdevcontract.MaxServiceObjects
	netdevFwSvcGrpMax    = netdevcontract.MaxServiceGroups
	netdevFwHitCountsMax = netdevcontract.MaxHitCountEntries
)

// NetDevFirewallStore is the read-only store of the firewall view: the
// network device store plus the stored rule hit counts. HitCounts returns
// an error matching netdevinventory.ErrDatasetNotFound when none are
// stored. ConfigChangedNotDisplayed reports drift outside the allowlist:
// the raw_digest of the running config changed while its redacted text
// did not (ADR 0010 D4). Every returned string is untrusted device text.
type NetDevFirewallStore interface {
	NetDevStore
	// HitCounts returns the current rule hit counts (PAN-OS).
	HitCounts(ctx context.Context, deviceID string) ([]netdevcontract.HitCount, error)
	// ConfigChangedNotDisplayed reports whether the newest running config
	// version differs from the one before it only outside the redacted
	// text.
	ConfigChangedNotDisplayed(ctx context.Context, deviceID string) (bool, error)
}

// NetDevFirewallOptions configure the firewall view.
type NetDevFirewallOptions struct {
	// Store reads the stored device inventory. Required.
	Store NetDevFirewallStore
	// Registry returns the approved device metadata (display name). Nil
	// shows the stored label.
	Registry NetDevRegistryFunc
	// IsAdmin is the admin role check. Required.
	IsAdmin NetDevAdminFunc
}

// NetDevFirewallPage serves GET /netdev/{id}/firewall.
type NetDevFirewallPage struct {
	base  *NetDevPages
	store NetDevFirewallStore
	page  *template.Template
}

// NetDevFirewallPage returns the PAN-OS firewall view rendered in this
// handler's layout. Store and IsAdmin are required.
func (h *Handler) NetDevFirewallPage(o NetDevFirewallOptions) (*NetDevFirewallPage, error) {
	if o.Store == nil {
		return nil, errors.New("ui: firewall view needs a store")
	}
	if o.IsAdmin == nil {
		return nil, errors.New("ui: firewall view needs an admin check")
	}
	set, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "layout.html", "netdev_firewall.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse template netdev_firewall: %w", err)
	}
	base := &NetDevPages{h: h, o: NetDevOptions{Store: o.Store, Registry: o.Registry, IsAdmin: o.IsAdmin}}
	return &NetDevFirewallPage{base: base, store: o.Store, page: set}, nil
}

// Register adds the firewall view route to mux. It takes every method so
// that a non-GET request is answered 405 here.
func (p *NetDevFirewallPage) Register(mux *http.ServeMux) {
	mux.HandleFunc("/netdev/{id}/firewall", p.handle)
}

// netdevFirewallPageData is the layout data plus the firewall view data.
type netdevFirewallPageData struct {
	pageData
	// NetDevFirewall is the data of the firewall view.
	NetDevFirewall *netdevFirewallData
}

// netdevFwRuleRow is one security rule.
type netdevFwRuleRow struct {
	Pos                                       int
	Name, From, To, Source, Destination       string
	Application, Service, Action, Description string
	Disabled                                  bool
	// HasCount is set when the stored hit counts hold this rule.
	HasCount          bool
	Hits              uint64
	FirstHit, LastHit time.Time
	ResetAt           time.Time
	// Unused is the unused-rule hint ("no hits in N days"), or "".
	Unused string
}

// netdevFwNATRow is one NAT rule.
type netdevFwNATRow struct {
	Pos                                 int
	Name, From, To, Source, Destination string
	Service, SourceTranslation          string
	DestinationTranslation, Description string
	Disabled                            bool
}

// netdevFwObjectRow is one address or service object or group.
type netdevFwObjectRow struct {
	Kind, Name, Value, Description string
	// Used is the usage text ("used by N rules"); "" when usage was not
	// computed.
	Used string
}

// netdevFirewallData is the data of the firewall view.
type netdevFirewallData struct {
	Label     string
	DeviceID  string
	DetailURL string
	Stale     bool
	Datasets  []netdevDatasetRow

	HasPolicy bool
	// NotDisplayed is set on drift outside the allowlist: the running
	// config's raw_digest changed while its redacted text did not, so the
	// change is in elements this view does not display.
	NotDisplayed bool
	// ReadIncomplete is set when the stored policy read is partial:
	// elements were cut or dropped and are missing from this view.
	ReadIncomplete bool
	Rules          []netdevFwRuleRow
	NAT            []netdevFwNATRow
	Objects        []netdevFwObjectRow
	// UsageSkipped is set when the policy was too large to count usage.
	UsageSkipped bool
	// DynamicGroups is set when an address group has a dynamic filter,
	// whose tag-matched members are not resolved in the usage counts.
	DynamicGroups bool

	HasHitCounts bool
	// HitsIncomplete is set when the stored hit counts are partial.
	HitsIncomplete bool
	HitsObservedAt time.Time

	Unavailable []string
}

func (p *NetDevFirewallPage) handle(w http.ResponseWriter, r *http.Request) {
	if !netdevMethodOK(w, r) || !p.base.authorize(w, r) {
		return
	}
	id := r.PathValue("id")
	if !netdevcontract.ValidDeviceID(id) {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), netdevCallTimeout)
	defer cancel()
	log := p.base.h.log
	d, err := p.store.GetDevice(ctx, id)
	if err != nil {
		if errors.Is(err, netdevinventory.ErrDeviceNotFound) {
			http.NotFound(w, r)
			return
		}
		log.Error("get network device", "device", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if d.Family != netdevcontract.FamilyPANOS {
		http.NotFound(w, r)
		return
	}
	e := p.base.registry(ctx)[id]
	now := p.base.h.clockNow()
	v := &netdevFirewallData{
		Label:     netdevLabel(e, d),
		DeviceID:  d.DeviceID,
		DetailURL: "/netdev/" + url.PathEscape(d.DeviceID),
		Stale:     d.State == netdevinventory.DeviceStale,
		Datasets:  p.base.datasets(ctx, d, now),
	}
	rowErr := func(what string, err error) {
		if !errors.Is(err, netdevinventory.ErrDatasetNotFound) {
			log.Error("read network device dataset", "device", id, "dataset", what, "error", err)
			v.Unavailable = append(v.Unavailable, what)
		}
	}
	// Drift outside the allowlist: raw_digest changed, redacted text not.
	if changed, err := p.store.ConfigChangedNotDisplayed(ctx, id); err != nil {
		rowErr("config versions", err)
	} else {
		v.NotDisplayed = changed
	}
	// Dataset states: a partial policy read means elements are missing.
	if ds, err := p.store.GetDataset(ctx, id, netdevinventory.ReadFirewallPolicy); err != nil {
		rowErr("firewall policy state", err)
	} else {
		v.ReadIncomplete = ds.Incomplete || ds.State == netdevinventory.StatePartial
	}
	var hitsDS netdevinventory.Dataset
	hitsDSOK := false
	if ds, err := p.store.GetDataset(ctx, id, netdevinventory.ReadHitCounts); err != nil {
		rowErr("hit count state", err)
	} else {
		hitsDS, hitsDSOK = ds, true
		v.HitsIncomplete = ds.Incomplete || ds.State == netdevinventory.StatePartial
		v.HitsObservedAt = ds.ObservedAt
	}
	var hits map[string]netdevcontract.HitCount
	if hs, err := p.store.HitCounts(ctx, id); err != nil {
		rowErr("hit counts", err)
	} else if hitsDSOK {
		v.HasHitCounts = true
		hits = make(map[string]netdevcontract.HitCount, len(hs))
		for _, hc := range hs[:min(len(hs), netdevFwHitCountsMax)] {
			if _, dup := hits[hc.RuleName]; !dup {
				hits[hc.RuleName] = hc
			}
		}
	}
	pol, err := p.store.FirewallPolicy(ctx, id)
	if err != nil {
		rowErr("firewall policy", err)
	} else {
		v.HasPolicy = true
		netdevFirewallFill(v, pol, hits, hitsDS.ObservedAt)
	}
	p.render(w, r, netdevFirewallPageData{
		pageData:       pageData{Title: "Firewall " + v.Label, Active: "netdev", Content: "netdev_firewall"},
		NetDevFirewall: v,
	})
}

// netdevFirewallFill fills the rule, NAT and object rows from a stored
// policy and the hit counts observed at hitsAt.
func netdevFirewallFill(v *netdevFirewallData, pol netdevcontract.FirewallPolicy, hits map[string]netdevcontract.HitCount, hitsAt time.Time) {
	for i, r := range pol.SecurityRules[:min(len(pol.SecurityRules), netdevFwRulesMax)] {
		row := netdevFwRuleRow{
			Pos:         i + 1,
			Name:        netdevText(r.Name),
			From:        netdevJoin(r.From),
			To:          netdevJoin(r.To),
			Source:      netdevJoin(r.Source),
			Destination: netdevJoin(r.Destination),
			Application: netdevJoin(r.Application),
			Service:     netdevJoin(r.Service),
			Action:      netdevText(string(r.Action)),
			Description: netdevText(r.Description),
			Disabled:    r.Disabled,
		}
		if hc, ok := hits[r.Name]; ok {
			row.HasCount = true
			row.Hits = hc.Hits
			row.FirstHit = netdevTimeOf(hc.FirstHit)
			row.LastHit = netdevTimeOf(hc.LastHit)
			row.ResetAt = netdevTimeOf(hc.ResetAt)
			if !r.Disabled {
				row.Unused = netdevUnusedHint(hc, hitsAt)
			}
		}
		v.Rules = append(v.Rules, row)
	}
	for i, r := range pol.NATRules[:min(len(pol.NATRules), netdevFwNATMax)] {
		v.NAT = append(v.NAT, netdevFwNATRow{
			Pos:                    i + 1,
			Name:                   netdevText(r.Name),
			From:                   netdevJoin(r.From),
			To:                     netdevJoin(r.To),
			Source:                 netdevJoin(r.Source),
			Destination:            netdevJoin(r.Destination),
			Service:                netdevText(r.Service),
			SourceTranslation:      netdevText(r.SourceTranslation),
			DestinationTranslation: netdevText(r.DestinationTranslation),
			Description:            netdevText(r.Description),
			Disabled:               r.Disabled,
		})
	}
	addrUse, svcUse, ok := netdevObjectUsage(pol)
	v.UsageSkipped = !ok
	used := func(m map[string]int, name string) string {
		if !ok {
			return ""
		}
		if n := m[name]; n != 1 {
			return "used by " + strconv.Itoa(n) + " rules"
		}
		return "used by 1 rule"
	}
	for _, a := range pol.Addresses[:min(len(pol.Addresses), netdevFwAddrsMax)] {
		v.Objects = append(v.Objects, netdevFwObjectRow{Kind: "address", Name: netdevText(a.Name),
			Value: netdevText(string(a.Type) + " " + a.Value), Description: netdevText(a.Description), Used: used(addrUse, a.Name)})
	}
	for _, g := range pol.AddressGroups[:min(len(pol.AddressGroups), netdevFwAddrGrpMax)] {
		val := netdevJoin(g.Static)
		if g.DynamicFilter != "" {
			v.DynamicGroups = true
			val = netdevText("dynamic: " + g.DynamicFilter)
		}
		v.Objects = append(v.Objects, netdevFwObjectRow{Kind: "address group", Name: netdevText(g.Name),
			Value: val, Description: netdevText(g.Description), Used: used(addrUse, g.Name)})
	}
	for _, s := range pol.Services[:min(len(pol.Services), netdevFwSvcsMax)] {
		val := s.Protocol + " " + s.Port
		if s.SourcePort != "" {
			val += " from " + s.SourcePort
		}
		v.Objects = append(v.Objects, netdevFwObjectRow{Kind: "service", Name: netdevText(s.Name),
			Value: netdevText(val), Description: netdevText(s.Description), Used: used(svcUse, s.Name)})
	}
	for _, g := range pol.ServiceGroups[:min(len(pol.ServiceGroups), netdevFwSvcGrpMax)] {
		v.Objects = append(v.Objects, netdevFwObjectRow{Kind: "service group", Name: netdevText(g.Name),
			Value: netdevJoin(g.Static), Description: netdevText(g.Description), Used: used(svcUse, g.Name)})
	}
}

// netdevTimeOf returns *t or the zero time.
func netdevTimeOf(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// netdevUnusedHint returns "no hits in N days" for a rule without hits
// whose counter was reset at least netdevUnusedMinObserved before the
// hit counts were observed (hitsAt). Without a reset time the observation
// window is unknown and there is no hint; so is any hit, a reported hit
// time, or a reset time after the observation.
func netdevUnusedHint(hc netdevcontract.HitCount, hitsAt time.Time) string {
	if hc.Hits != 0 || hc.FirstHit != nil || hc.LastHit != nil || hc.ResetAt == nil || hitsAt.IsZero() {
		return ""
	}
	window := hitsAt.Sub(*hc.ResetAt)
	if window < netdevUnusedMinObserved {
		return ""
	}
	return fmt.Sprintf("no hits in %d days", int(window/(24*time.Hour)))
}

// netdevObjectUsage counts, per address and per service object or group
// name, the security and NAT rules that use it directly or through
// (nested) static groups. Each rule counts at most once per name. Group
// expansion stops at netdevcontract.MaxGroupNestingDepth and on cycles: a
// name is expanded again only when reached at a shallower depth than
// before, so a group first met at the depth limit is still expanded when
// the rule also reaches it closer to the top. Dynamic address group
// members are not resolved. ok is false when the
// work exceeded netdevUsageMaxSteps.
func netdevObjectUsage(pol netdevcontract.FirewallPolicy) (addr, svc map[string]int, ok bool) {
	addrGroups := make(map[string][]string, len(pol.AddressGroups))
	for _, g := range pol.AddressGroups {
		if _, dup := addrGroups[g.Name]; !dup {
			addrGroups[g.Name] = g.Static
		}
	}
	svcGroups := make(map[string][]string, len(pol.ServiceGroups))
	for _, g := range pol.ServiceGroups {
		if _, dup := svcGroups[g.Name]; !dup {
			svcGroups[g.Name] = g.Static
		}
	}
	addr, svc = map[string]int{}, map[string]int{}
	steps := 0
	count := func(m map[string]int, groups map[string][]string, lists ...[]string) bool {
		type item struct {
			name  string
			depth int
		}
		// best is the shallowest depth each name was reached at.
		best := map[string]int{}
		var stack []item
		for _, l := range lists {
			for _, n := range l {
				stack = append(stack, item{n, 0})
			}
		}
		for len(stack) > 0 {
			if steps++; steps > netdevUsageMaxSteps {
				return false
			}
			it := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if d, seen := best[it.name]; seen && d <= it.depth {
				continue
			}
			best[it.name] = it.depth
			if members, isGroup := groups[it.name]; isGroup && it.depth < netdevcontract.MaxGroupNestingDepth {
				for _, mb := range members {
					stack = append(stack, item{mb, it.depth + 1})
				}
			}
		}
		for n := range best {
			m[n]++
		}
		return true
	}
	for _, r := range pol.SecurityRules[:min(len(pol.SecurityRules), netdevFwRulesMax)] {
		if !count(addr, addrGroups, r.Source, r.Destination) || !count(svc, svcGroups, r.Service) {
			return nil, nil, false
		}
	}
	for _, r := range pol.NATRules[:min(len(pol.NATRules), netdevFwNATMax)] {
		var services []string
		if r.Service != "" {
			services = []string{r.Service}
		}
		if !count(addr, addrGroups, r.Source, r.Destination) || !count(svc, svcGroups, services) {
			return nil, nil, false
		}
	}
	return addr, svc, true
}

// render renders the firewall view like NetDevPages.render: into a buffer
// first, so an execution error answers 500 without a partial page.
func (p *NetDevFirewallPage) render(w http.ResponseWriter, r *http.Request, data netdevFirewallPageData) {
	h := p.base.h
	if data.Theme == "" {
		data.Theme = themeFromRequest(r)
	}
	data.NavCollapsed = navStateFromRequest(r) == navCollapsed
	data.PVENav = h.pve != nil
	data.DeployEnabled = h.deploy != nil && h.pve != nil && h.pveRemotes != nil
	if h.builtinTrust != nil {
		data.BuiltinTrust = h.builtinTrust.get(r.Context())
	}
	var buf bytes.Buffer
	if err := p.page.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("render page", "page", data.Content, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.log.Debug("write page", "page", data.Content, "error", err)
	}
}
