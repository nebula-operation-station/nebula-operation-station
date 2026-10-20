// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Global search (spec 12, M9-3) over hosts, assets, addresses, networks,
// executions, runbooks and modules. It only reads; quick actions are links
// to the pages that do the work, so anything that runs still goes through
// the operation planner and the normal approval path.

const (
	maxQuery      = 100
	maxPerKind    = 20
	searchTimeout = operationsCallTimeout
)

type quickAction struct {
	Label, URL string
}

type searchResult struct {
	Kind, Title, Detail, URL string
	Actions                  []quickAction
}

type searchData struct {
	Query   string
	Results []searchResult
	// Truncated names the kinds that had more matches than shown.
	Truncated []string
	TooLong   bool
}

// maxAddressStatus bounds the address status lookups of one search.
const maxAddressStatus = 4

func esc(s string) string { return url.PathEscape(s) }

// matcher is a case-insensitive substring test.
type matcher string

func (m matcher) any(fields ...string) bool {
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), string(m)) {
			return true
		}
	}
	return false
}

type collector struct {
	data   *searchData
	counts map[string]int
}

func (c *collector) add(r searchResult) {
	c.counts[r.Kind]++
	if c.counts[r.Kind] == maxPerKind+1 {
		c.data.Truncated = append(c.data.Truncated, r.Kind)
	}
	if c.counts[r.Kind] <= maxPerKind {
		c.data.Results = append(c.data.Results, r)
	}
}

func (h *Handler) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	d := &searchData{Query: q}
	data := pageData{Title: "Search", Content: "search", Search: d}
	if q == "" {
		h.render(w, data)
		return
	}
	if len(q) > maxQuery || !utf8.ValidString(q) {
		d.TooLong = true
		h.render(w, data)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), searchTimeout)
	defer cancel()
	c := &collector{data: d, counts: map[string]int{}}
	m := matcher(strings.ToLower(q))
	addr, addrErr := netip.ParseAddr(q)
	isAddr := addrErr == nil && addr.Zone() == ""
	if isAddr {
		addr = addr.Unmap()
	}
	prefix, prefixErr := netip.ParsePrefix(q)
	isPrefix := prefixErr == nil

	if h.hosts != nil {
		hosts, err := h.hosts(ctx)
		if err != nil {
			h.log.Error("search hosts", "error", err)
		}
		for _, x := range hosts {
			var eps []string
			hit := m.any(x.ID, x.DisplayName)
			for _, e := range x.Endpoints {
				eps = append(eps, e.Address)
				if ea, err := netip.ParseAddr(strings.Trim(e.Address, "[]")); err == nil && (isAddr && ea.Unmap() == addr || isPrefix && prefix.Contains(ea.Unmap())) {
					hit = true
				} else if m.any(e.Address) {
					hit = true
				}
			}
			for k, v := range x.Tags {
				if m.any(k + "=" + v) {
					hit = true
				}
			}
			for _, g := range x.Groups {
				if m.any(g) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			name := x.DisplayName
			if name == "" {
				name = x.ID
			}
			c.add(searchResult{Kind: "Host", Title: name + " (" + x.ID + ")", Detail: strings.Join(eps, ", "), URL: "/hosts/" + esc(x.ID),
				Actions: []quickAction{{"Plan an operation", "/operations/new?host=" + url.QueryEscape(x.ID)}, {"Inventory", "/inventory"}}})
		}
	}

	if h.network != nil {
		assets, err := h.network.Assets(ctx)
		if err != nil {
			h.log.Error("search assets", "error", err)
		}
		for _, a := range assets {
			hit := m.any(a.ID, a.Name, a.Hostname, a.MAC, a.Notes, string(a.Kind))
			var ads []string
			for _, ad := range a.Addresses {
				ads = append(ads, ad.String())
				if isAddr && ad == addr || isPrefix && prefix.Contains(ad) || m.any(ad.String()) {
					hit = true
				}
			}
			if !hit {
				continue
			}
			res := searchResult{Kind: "Asset", Title: a.Name + " (" + a.ID + ")", Detail: strings.TrimSpace(string(a.Kind) + " " + strings.Join(ads, ", ")),
				URL: "/network/a/" + esc(a.ID)}
			if a.HostID != "" {
				res.Actions = append(res.Actions, quickAction{"Managed host " + a.HostID, "/hosts/" + esc(a.HostID)})
			} else if h.inventory != nil {
				res.Actions = append(res.Actions, quickAction{"Add to managed hosts", "/inventory?asset=" + url.QueryEscape(a.ID)})
			}
			c.add(res)
		}
		nets, err := h.network.Networks(ctx)
		if err != nil {
			h.log.Error("search networks", "error", err)
		}
		statusCalls := 0
		for _, n := range nets {
			hit := m.any(n.ID, n.Name, n.Prefix.String(), n.Notes) || isAddr && n.Prefix.Contains(addr) || isPrefix && n.Prefix.Overlaps(prefix)
			if n.VLAN != 0 && (q == strconv.Itoa(n.VLAN) || strings.EqualFold(q, "vlan "+strconv.Itoa(n.VLAN)) || strings.EqualFold(q, "vlan"+strconv.Itoa(n.VLAN))) {
				hit = true
			}
			if !hit {
				continue
			}
			detail := n.Prefix.String()
			if n.VLAN != 0 {
				detail += ", VLAN " + strconv.Itoa(n.VLAN)
			}
			c.add(searchResult{Kind: "Network", Title: n.Name + " (" + n.ID + ")", Detail: detail, URL: "/network/n/" + esc(n.ID)})
			// The address itself, with its status in this network.
			// Status reloads every claim, so a search shows the address
			// status for at most maxAddressStatus containing networks
			// (review m93, finding 1); the network rows link to the rest.
			if isAddr && n.Prefix.Contains(addr) && statusCalls < maxAddressStatus {
				statusCalls++
				if views, _, err := h.network.Status(ctx, n.ID); err == nil {
					st, why := "UNKNOWN", ""
					for _, v := range views {
						if v.Address == addr {
							st, why = string(v.Status), v.Why
						}
					}
					if why != "" {
						st += ": " + why
					}
					c.add(searchResult{Kind: "Address", Title: addr.String(), Detail: st + " in " + n.Prefix.String(), URL: "/network/n/" + esc(n.ID)})
				}
			}
		}
	}

	if h.operations != nil && len(q) >= 4 {
		if list, err := h.operations.List(ctx, 500); err != nil {
			h.log.Error("search executions", "error", err)
		} else {
			lq := strings.ToLower(q)
			for _, e := range list {
				if strings.HasPrefix(e.ID, lq) || m.any(e.ActionID) && len(q) >= 3 {
					c.add(searchResult{Kind: "Execution", Title: e.ID, Detail: e.ActionID + ", " + e.State + ", " + e.CreatedAt.UTC().Format(timeFormat),
						URL: "/operations/" + esc(e.ID)})
				}
			}
		}
	}

	if h.runbooks != nil {
		if list, err := h.runbooks.Latest(ctx); err != nil {
			h.log.Error("search runbooks", "error", err)
		} else {
			for _, v := range list {
				if m.any(v.Slug, v.Title, v.Description, v.ActionID()) {
					c.add(searchResult{Kind: "Runbook", Title: v.Title + " (" + v.Slug + ")", Detail: "version " + strconv.Itoa(v.Version) + ", " + v.Risk,
						URL: "/runbooks/" + esc(v.Slug), Actions: []quickAction{{"Plan", "/operations/new?action=" + url.QueryEscape(v.ActionID())}}})
				}
			}
		}
	}

	if h.modules != nil {
		if list, err := h.modules.Latest(ctx); err != nil {
			h.log.Error("search modules", "error", err)
		} else {
			for _, v := range list {
				if m.any(v.Lock.Name, v.Lock.Title, v.Lock.Description) {
					c.add(searchResult{Kind: "Module", Title: v.Lock.Title + " (" + v.Lock.Name + ")", Detail: "version " + v.Lock.Version + ", " + v.State,
						URL: "/modules/" + esc(v.Lock.Name)})
				}
			}
		}
	}
	h.render(w, data)
}
