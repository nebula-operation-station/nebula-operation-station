// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// A host's page: header card plus server-rendered tabs (overview,
// updates, containers, services, operations, modules, settings). Every
// tab shows the stored data with its age; a Refresh button creates the
// corresponding read-only operation through the existing operation
// create path. Module tabs (M7-6, spec 10 declarative UI): every tab,
// card and label comes from a module's signed or unsigned metadata and
// is rendered as text by the core's template; values come from the
// latest successful result of the card's action on the host (untrusted
// host output, shown as text). Modules provide no HTML, links or
// scripts.

type moduleFieldView struct{ Label, Value string }

type moduleCardView struct {
	Title, ActionID, When string
	Fields                []moduleFieldView
}

type moduleTabView struct {
	Module, Version, Title, State string
	Cards                         []moduleCardView
}

// hostTab is one tab of the host page.
type hostTab struct {
	ID    string
	Title string
}

// hostTabs is the fixed tab order of the host page.
var hostTabs = []hostTab{
	{"overview", "Overview"},
	{"updates", "Updates"},
	{"containers", "Containers"},
	{"services", "Services"},
	{"operations", "Operations"},
	{"modules", "Modules"},
	{"settings", "Settings"},
}

// hostTabIDs are the valid ?tab= values.
var hostTabIDs = func() map[string]bool {
	m := make(map[string]bool, len(hostTabs))
	for _, t := range hostTabs {
		m[t.ID] = true
	}
	return m
}()

type packageRow struct {
	Name, From, To, Arch string
	Security, Kernel     bool
}

type containerRow struct {
	Name, Image, State, Status, Ports, Project string
	StateClass                                 string
	Update                                     bool
}

type unitRow struct {
	Name, Active, Sub, Description string
	Failed                         bool
}

type hostOpRow struct {
	ID, Action, State, StateClass string
	Created                       time.Time
	FinishedSet                   bool
	Finished                      time.Time
}

type hostSettingsView struct {
	DisplayName, Environment, Criticality string
	EndpointsText, TagsText               string
	Environments, Criticalities           []string
}

type hostPageData struct {
	ID   string
	Tabs []hostTab
	Tab  string

	// Header.
	Found          bool
	DisplayName    string
	Environment    string
	Criticality    string
	StateLabel     string
	StateClass     string
	StateReason    string
	Endpoints      []string
	KeyStatus      string
	KeyShort       string
	KeyFingerprint string
	RepinHref      string
	LastSeenSet    bool
	LastSeen       time.Time

	// Overview.
	Facts             []moduleFieldView
	AsOf              time.Time
	Reboot            bool
	UpdatesSecurity   int
	UpdatesTotal      int
	ContainersRunning int
	ContainersTotal   int
	ContainersKnown   bool
	FailedServices    int

	// Updates.
	Packages    []packageRow
	UpdatesAsOf time.Time

	// Containers.
	Containers     []containerRow
	ContainersAsOf time.Time

	// Services.
	Units        []unitRow
	ServicesAsOf time.Time

	// Operations.
	Ops []hostOpRow

	// Modules (M7-6, spec 10 declarative UI).
	ModuleTabs []moduleTabView

	// Settings.
	Settings *hostSettingsView
	Warn     string

	// Quick actions (job ui5).
	QuickActions []quickActionView
	PinSettings  *pinSettingsView
}

// hostTabLimit bounds the operations tab.
const hostTabLimit = 50

// maxFieldValue bounds one module field value (plainLine cuts at it).
const maxFieldValue = 200

// handleHost renders the host page with its tabs.
func (h *Handler) handleHost(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canonical.ValidHostID(id) {
		http.NotFound(w, r)
		return
	}
	tab := r.URL.Query().Get("tab")
	if !hostTabIDs[tab] {
		tab = "overview"
	}
	data := pageData{Title: "Host " + id, Active: "inventory", Content: "host",
		Host:    &hostPageData{ID: id, Tab: tab, Tabs: hostTabs},
		Scripts: []string{"webauthn.js", "runop.js", "host.js", "formpost.js"}}
	data.Host.Warn = r.URL.Query().Get("warn")
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	hp := data.Host
	// The page renders for any valid host ID (as before): the module
	// views are independent of the inventory, and a stale link to a
	// deleted host still shows the stored data.
	if h.hosts != nil {
		hosts, err := h.hosts(ctx)
		if err != nil {
			h.log.Error("list inventory hosts", "error", err)
		} else {
			for i := range hosts {
				if hosts[i].ID == id {
					h.fillHost(ctx, &hosts[i], hp)
					break
				}
			}
		}
	}
	if h.modules != nil && h.lastResult != nil {
		hp.ModuleTabs = h.moduleTabs(ctx, id)
	}
	h.hostQuickActions(ctx, id, hp)
	h.hostPinSettings(ctx, id, hp)
	h.render(w, r, data)
}

// fillHost fills the host page data from the inventory record and the
// stored execution results (all untrusted host output, rendered as text
// only).
func (h *Handler) fillHost(ctx context.Context, host *inventory.Host, hp *hostPageData) {
	id := host.ID
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	b := h.batchData(ctx)
	v := viewHost(*host, pins, pinsUnavailable, b, time.Now())
	hp.Found = true
	hp.DisplayName = v.DisplayName
	hp.Environment = v.Environment
	hp.Criticality = v.Criticality
	hp.StateLabel = v.StateLabel
	hp.StateClass = v.StateClass
	hp.StateReason = v.StateReason
	hp.Endpoints = v.Endpoints
	hp.KeyStatus = v.KeyStatus
	hp.KeyShort = v.KeyShort
	hp.KeyFingerprint = v.KeyFingerprint
	hp.LastSeenSet = v.LastSeenSet
	hp.LastSeen = v.LastSeen
	if v.KeyStatus == "blocked" && h.repin != nil {
		hp.RepinHref = "/dashboard?repin=" + urlEscape(id)
	}
	// Summary numbers (overview tiles and header).
	hp.UpdatesSecurity, hp.UpdatesTotal = v.UpdatesSecurity, v.UpdatesTotal
	hp.Reboot = v.Reboot
	hp.ContainersRunning, hp.ContainersTotal, hp.ContainersKnown = v.ContainersRunning, v.ContainersTotal, v.ContainersKnown
	hp.FailedServices = v.FailedServices
	// Overview: the facts of the latest core.facts.
	if row, ok := b.facts[id]; ok {
		for _, f := range executions.DecodeFacts(row.Result) {
			hp.Facts = append(hp.Facts, moduleFieldView{Label: f.Name, Value: f.Value})
		}
		hp.AsOf = row.FinishedAt
	}
	// Updates: the parsed package.list_updates, security first.
	if u, ok := b.updates[id]; ok {
		// The inventory batch has only the counts; the package list is
		// read for this one host.
		if full, err := h.operations.Updates(ctx, id); err == nil {
			u = full
		} else if !errors.Is(err, executions.ErrNoUpdates) {
			h.log.Error("host updates", "host", id, "error", err)
		}
		for _, p := range u.Packages {
			hp.Packages = append(hp.Packages, packageRow{Name: p.Name, From: p.From, To: p.To, Arch: p.Arch,
				Security: p.Security, Kernel: p.Kernel})
		}
		sort.Slice(hp.Packages, func(i, j int) bool {
			if hp.Packages[i].Security != hp.Packages[j].Security {
				return hp.Packages[i].Security
			}
			return hp.Packages[i].Name < hp.Packages[j].Name
		})
		hp.UpdatesAsOf = u.ObservedAt
	}
	// Containers: the latest docker.list merged with the latest
	// docker.check_updates (an update badge per image).
	if row, ok := b.docker[id]; ok {
		if l, err := dockerhost.ParseList(row.Result); err == nil {
			up := map[string]bool{}
			if urow, ok := b.dockerUp[id]; ok {
				if u, err := dockerhost.ParseImageUpdates(urow.Result); err == nil {
					for _, iu := range u.Images {
						up[iu.Image] = true
					}
				}
			}
			for _, c := range l.Containers {
				hp.Containers = append(hp.Containers, containerRow{
					Name: c.Name, Image: c.Image, State: c.State, Status: c.Status,
					Ports: c.Ports, Project: c.Project,
					StateClass: containerStateClass(c.State), Update: up[c.Image],
				})
			}
			sort.Slice(hp.Containers, func(i, j int) bool {
				return hp.Containers[i].Name < hp.Containers[j].Name
			})
			hp.ContainersAsOf = row.FinishedAt
		}
	}
	// Services: the latest service.list, failed units first.
	if row, ok := b.services[id]; ok {
		if units, err := osdebian.ParseUnits(row.Result); err == nil {
			for _, u := range units {
				hp.Units = append(hp.Units, unitRow{Name: u.Name, Active: u.Active, Sub: u.Sub,
					Description: u.Description, Failed: u.Active == "failed"})
			}
			sort.Slice(hp.Units, func(i, j int) bool {
				if hp.Units[i].Failed != hp.Units[j].Failed {
					return hp.Units[i].Failed
				}
				return hp.Units[i].Name < hp.Units[j].Name
			})
			hp.ServicesAsOf = row.FinishedAt
		}
	}
	// Operations: the newest executions that targeted the host.
	if h.operations != nil {
		sums, err := h.operations.ListHost(ctx, id, hostTabLimit)
		if err != nil {
			h.log.Error("list host executions", "error", err)
		}
		for _, s := range sums {
			hp.Ops = append(hp.Ops, hostOpRow{ID: s.ID, Action: s.ActionID, State: s.State,
				StateClass: execStateClass(s.State), Created: s.CreatedAt,
				Finished: s.FinishedAt, FinishedSet: !s.FinishedAt.IsZero()})
		}
	}
	// Settings: the edit form data (only with a configured store).
	if h.inventory != nil {
		hp.Settings = &hostSettingsView{
			DisplayName:   host.DisplayName,
			Environment:   string(host.Environment),
			Criticality:   string(host.Criticality),
			EndpointsText: hostEndpointsText(*host),
			TagsText:      hostTagsText(*host),
			Environments:  []string{string(inventory.EnvDev), string(inventory.EnvQA), string(inventory.EnvProd)},
			Criticalities: []string{string(inventory.CriticalityLow), string(inventory.CriticalityMedium),
				string(inventory.CriticalityHigh), string(inventory.CriticalityCritical)},
		}
	}
}

// moduleTabs builds the declarative module tabs of a host. The module
// UI security rules are unchanged: every tab, card and label is module
// text and every value host output, rendered as text only.
func (h *Handler) moduleTabs(ctx context.Context, id string) []moduleTabView {
	var tabs []moduleTabView
	mods, err := h.modules.Latest(ctx)
	if err != nil {
		h.log.Error("list modules", "error", err)
	}
	for _, v := range mods {
		if v.Lock.UI == nil || v.Lock.UI.HostTab == nil {
			continue
		}
		t := v.Lock.UI.HostTab
		tab := moduleTabView{Module: v.Lock.Name, Version: v.Lock.Version, Title: t.Title, State: v.State}
		for _, c := range t.Cards {
			cv := moduleCardView{Title: c.Title, ActionID: v.Lock.ActionID(c.Action), When: "never run on this host"}
			res, at, ok, err := h.lastResult(ctx, cv.ActionID, id)
			if err != nil {
				h.log.Error("last result", "error", err)
			}
			var obj map[string]any
			if ok {
				obj = resultObject(res) // parsed once per card
			}
			for _, f := range c.Fields {
				val := "—"
				if obj != nil {
					val = fieldValue(obj, f.Path)
				}
				cv.Fields = append(cv.Fields, moduleFieldView{Label: f.Label, Value: val})
			}
			if ok {
				cv.When = "as of " + at.UTC().Format("2006-01-02 15:04 MST")
			}
			tab.Cards = append(tab.Cards, cv)
		}
		tabs = append(tabs, tab)
	}
	return tabs
}

// hostEndpointsText is the form text of a host's endpoints (one per
// line, "address:port" — exactly what the form and
// sshtransport.ParseEndpoint accept).
func hostEndpointsText(host inventory.Host) string {
	var lines []string
	for _, e := range host.Endpoints {
		lines = append(lines, endpointText(e.Address, e.Port))
	}
	return strings.Join(lines, "\n")
}

// hostTagsText is the form text of a host's tags (one key=value per
// line, in key order).
func hostTagsText(host inventory.Host) string {
	if len(host.Tags) == 0 {
		return ""
	}
	keys := make([]string, 0, len(host.Tags))
	for k := range host.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		lines = append(lines, k+"="+host.Tags[k])
	}
	return strings.Join(lines, "\n")
}

// endpointText is the form text of one endpoint (the default port is
// left off, as the form accepts "address" and "address:port").
func endpointText(address string, port int) string {
	if port == 0 {
		port = defaultSSHPort
	}
	return strings.TrimSuffix(net.JoinHostPort(address, strconv.Itoa(port)), ":22")
}

// containerStateClass is the badge class of a container state.
func containerStateClass(state string) string {
	switch state {
	case "running":
		return "badge--ok"
	case "exited", "dead":
		return "badge--critical"
	case "paused", "restarting", "removing":
		return "badge--warning"
	default:
		return "badge--unknown"
	}
}

// containerHealthClass is the badge class of a docker health state:
// healthy green, unhealthy red, starting yellow.
func containerHealthClass(health string) string {
	switch health {
	case "healthy":
		return "badge--ok"
	case "unhealthy":
		return "badge--critical"
	case "starting":
		return "badge--warning"
	default:
		return "badge--unknown"
	}
}

// execStateClass is the badge class of an execution state.
func execStateClass(state string) string {
	switch state {
	case "succeeded":
		return "badge--ok"
	case "failed", "aborted":
		return "badge--critical"
	case "pending", "approved", "running":
		return "badge--pending"
	case "expired":
		// Muted, not in progress (issue #71): an expired operation is
		// done waiting and must not make the host look busy.
		return "badge--expired"
	default:
		return "badge--unknown"
	}
}

// refreshActions maps a host tab to the read-only actions that refresh
// it ("Refresh all" on the overview tab reads everything the tabs show).
func refreshActions(tab string) []string {
	switch tab {
	case "overview":
		return []string{"core.facts", "package.list_updates", "docker.list", "service.list"}
	case "updates":
		return []string{"package.list_updates"}
	case "containers":
		return []string{"docker.list", "docker.check_updates"}
	case "services":
		return []string{"service.list"}
	default:
		return nil
	}
}

// handleHostRefresh creates the read-only refresh operations of a host
// tab through the existing operation create path (CreateStaged) and
// redirects to the first operation page, where approval happens as
// today; when the executor approved everything right away it goes back
// to the host page.
func (h *Handler) handleHostRefresh(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil || h.operations == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.PathValue("id")
	if !canonical.ValidHostID(id) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	tab := r.PostFormValue("tab")
	actions := refreshActions(tab)
	if len(actions) == 0 {
		http.Error(w, "unknown tab", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	created := make([]executions.Created, 0, len(actions))
	for _, a := range actions {
		c, err := h.operations.CreateStaged(ctx, webUser(r), a, []string{id}, map[string]string{}, executions.Plan{})
		if err != nil {
			h.log.Error("refresh host", "host", id, "action", a, "error", err)
			http.Redirect(w, r, "/hosts/"+urlEscape(id)+"?tab="+urlEscape(tab)+"&warn="+urlEscape("The refresh could not be created."),
				http.StatusSeeOther)
			return
		}
		created = append(created, c)
	}
	for _, c := range created {
		if c.State == "pending" {
			http.Redirect(w, r, "/operations/"+urlEscape(c.ID), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/hosts/"+urlEscape(id)+"?tab="+urlEscape(tab), http.StatusSeeOther)
}

// resultObject returns the "result" object of a runbook-v1 result
// document, or nil.
func resultObject(result []byte) map[string]any {
	var doc struct {
		Result map[string]any `json:"result"`
	}
	if json.Unmarshal(result, &doc) != nil {
		return nil
	}
	return doc.Result
}

// fieldValue reads path from a result object and returns it as one line
// of plain text.
func fieldValue(obj map[string]any, path string) string {
	var cur any = obj
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "—"
		}
		if cur, ok = m[seg]; !ok {
			return "—"
		}
	}
	var s string
	switch v := cur.(type) {
	case nil:
		return "—"
	case string:
		s = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "—"
		}
		s = string(b)
	}
	return plainLine(s)
}

// plainLine replaces control and invisible formatting characters and cuts
// the text at maxFieldValue bytes on a character boundary.
func plainLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2008' || r == '\u2009' || r == utf8.RuneError {
			r = '\uFFFD'
		}
		if b.Len()+utf8.RuneLen(r) > maxFieldValue {
			b.WriteString("\u2026")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// LastResultFunc returns the latest successful result of an action on a
// host (executions.Service.LastResult).
type LastResultFunc func(ctx context.Context, actionID, host string) ([]byte, time.Time, bool, error)
