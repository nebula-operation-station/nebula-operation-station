// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

// The "Endpoints" section of the host page (job ep01): the primary
// endpoint (priority 0) and its alternates in priority order, with forms
// to add an alternate, move one endpoint and remove one. The forms post
// to the Origin-checked settings route (POST /hosts/{id}/settings) with
// an endpoint_op field, like the other host forms (formpost.js).
//
// Endpoints of one host share the host's single pinned host key
// (internal/sshtransport pins per host, not per address): an endpoint
// that presents another key stops the run (hard stop, no failover), so
// endpoint edits never touch the pin. Every change writes one audit line
// with the endpoint order before and after.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
)

// maxPortText bounds the port field ("65535").
const maxPortText = 5

// hostEndpointStore edits one endpoint of a host. inventory.Store
// satisfies it; an InventoryStore without it shows the endpoint list
// without the edit forms.
type hostEndpointStore interface {
	AddEndpoint(ctx context.Context, hostID string, e inventory.Endpoint) (inventory.EndpointChange, error)
	MoveEndpoint(ctx context.Context, hostID string, e inventory.Endpoint, to int) (inventory.EndpointChange, error)
	RemoveEndpoint(ctx context.Context, hostID string, e inventory.Endpoint) (inventory.EndpointChange, error)
}

// endpointRow is one row of the Endpoints section.
type endpointRow struct {
	Label   string // "Primary" or "Alternate n"
	Text    string // address:port as shown
	Address string
	Port    int
	Up      int // position after "move up"
	Down    int // position after "move down"
	First   bool
	Last    bool
}

// endpointsView is the Endpoints section of the settings tab.
type endpointsView struct {
	Rows     []endpointRow
	Editable bool // the store supports endpoint edits
	CanAdd   bool // fewer than inventory.MaxEditableEndpoints endpoints
	Max      int
}

// hostEndpointsView builds the Endpoints section from the stored order.
func (h *Handler) hostEndpointsView(host inventory.Host) *endpointsView {
	_, editable := h.inventory.(hostEndpointStore)
	v := &endpointsView{Editable: editable, Max: inventory.MaxEditableEndpoints,
		CanAdd: editable && len(host.Endpoints) < inventory.MaxEditableEndpoints}
	for i, e := range host.Endpoints {
		label := "Primary"
		if i > 0 {
			label = "Alternate " + strconv.Itoa(i)
		}
		port := e.Port
		if port == 0 {
			port = defaultSSHPort
		}
		v.Rows = append(v.Rows, endpointRow{Label: label, Text: inventory.EndpointKey(e), Address: e.Address,
			Port: port, Up: i - 1, Down: i + 1, First: i == 0, Last: i == len(host.Endpoints)-1})
	}
	return v
}

// endpointListText is the audit form of an endpoint list: the endpoint
// keys in priority order, separated by spaces.
func endpointListText(eps []inventory.Endpoint) string {
	keys := make([]string, len(eps))
	for i, e := range eps {
		keys[i] = inventory.EndpointKey(e)
	}
	return strings.Join(keys, " ")
}

// auditEndpoints writes the audit line of an endpoint change.
func (h *Handler) auditEndpoints(r *http.Request, kind, hostID, endpoint string, ch inventory.EndpointChange) {
	h.log.Info("audit", "kind", kind, "host", hostID, "user", webUser(r), "endpoint", endpoint,
		"before", endpointListText(ch.Before), "after", endpointListText(ch.After))
}

// parseEndpointFields reads the address and port fields of an endpoint
// form. An empty port means the default SSH port; brackets around an
// IPv6 address are accepted. ok is false for a malformed port.
func parseEndpointFields(r *http.Request) (e inventory.Endpoint, ok bool) {
	addr := strings.TrimSpace(r.PostFormValue("address"))
	if len(addr) > 2 && addr[0] == '[' && addr[len(addr)-1] == ']' {
		addr = addr[1 : len(addr)-1]
	}
	e = inventory.Endpoint{Address: addr}
	p := strings.TrimSpace(r.PostFormValue("port"))
	if p == "" {
		return e, true
	}
	n, err := strconv.Atoi(p)
	if len(p) > maxPortText || err != nil || strings.TrimLeft(p, "0123456789") != "" || n < 1 || n > 65535 {
		return inventory.Endpoint{}, false
	}
	e.Port = n
	return e, true
}

// endpointErrorText is the form-facing text of an endpoint edit error.
// Input problems describe the input (rendered as text); store failures
// are fixed text and logged.
func (h *Handler) endpointErrorText(hostID string, err error) string {
	var verr *inventory.ValidationError
	switch {
	case errors.Is(err, inventory.ErrEndpointExists):
		return "This endpoint is already configured for the host."
	case errors.Is(err, inventory.ErrTooManyEndpoints):
		return "A host has at most " + strconv.Itoa(inventory.MaxEditableEndpoints) + " endpoints."
	case errors.Is(err, inventory.ErrLastEndpoint):
		return "The last endpoint of a host cannot be removed."
	case errors.Is(err, inventory.ErrEndpointNotFound):
		return "The endpoint was not found; reload the page."
	case errors.Is(err, inventory.ErrHostNotFound):
		return "The host was not found."
	case errors.Is(err, inventory.ErrInvalidEndpoint):
		_, detail, ok := strings.Cut(err.Error(), inventory.ErrInvalidEndpoint.Error()+": ")
		if !ok {
			detail = "malformed"
		}
		return "Invalid endpoint: " + detail
	case errors.As(err, &verr):
		return verr.Error()
	}
	h.log.Error("edit host endpoints", "host", hostID, "error", err)
	return "The inventory could not be reached."
}

// endpointUsedElsewhere returns the ID of another host that already has
// the endpoint e, or "".
func (h *Handler) endpointUsedElsewhere(ctx context.Context, hostID string, e inventory.Endpoint) (string, error) {
	if h.hosts == nil {
		return "", nil
	}
	all, err := h.hosts(ctx)
	if err != nil {
		return "", err
	}
	key := inventory.EndpointKey(e)
	for _, other := range all {
		if other.ID == hostID {
			continue
		}
		for _, oe := range other.Endpoints {
			if inventory.EndpointKey(oe) == key {
				return other.ID, nil
			}
		}
	}
	return "", nil
}

// handleHostEndpointEdit runs one endpoint edit of the host in the path
// (endpoint_op add, move or remove) and goes back to the settings tab,
// with a warning when the edit was refused. The form is already parsed.
func (h *Handler) handleHostEndpointEdit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !canonical.ValidHostID(id) {
		http.NotFound(w, r)
		return
	}
	back := "/hosts/" + urlEscape(id) + "?tab=settings"
	warn := func(msg string) {
		http.Redirect(w, r, back+"&warn="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	store, ok := h.inventory.(hostEndpointStore)
	if !ok {
		warn("Endpoints cannot be edited with this inventory.")
		return
	}
	op := r.PostFormValue("endpoint_op")
	if op != "add" && op != "move" && op != "remove" {
		warn("unknown endpoint action")
		return
	}
	e, ok := parseEndpointFields(r)
	if !ok {
		warn("The port must be a number from 1 to 65535.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()

	var (
		ch   inventory.EndpointChange
		kind string
		err  error
	)
	switch op {
	case "add":
		// An endpoint of another host would present that host's key and
		// block this one (key mismatch is a hard stop); refuse it here.
		if n, nerr := inventory.NormalizeEndpoint(e); nerr == nil {
			other, herr := h.endpointUsedElsewhere(ctx, id, n)
			if herr != nil {
				h.log.Error("list inventory hosts", "error", herr)
				warn("The inventory could not be reached.")
				return
			}
			if other != "" {
				warn("The endpoint " + inventory.EndpointKey(n) + " is already used by host " + other + ".")
				return
			}
		}
		kind = "host_endpoint_added"
		ch, err = store.AddEndpoint(ctx, id, e)
		if err == nil && len(ch.After) > 0 {
			e = ch.After[len(ch.After)-1]
		}
	case "move":
		to, aerr := strconv.Atoi(r.PostFormValue("to"))
		if aerr != nil {
			warn("Invalid endpoint: the position is not a number.")
			return
		}
		kind = "host_endpoint_moved"
		ch, err = store.MoveEndpoint(ctx, id, e, to)
	case "remove":
		kind = "host_endpoint_removed"
		ch, err = store.RemoveEndpoint(ctx, id, e)
	}
	if err != nil {
		warn(h.endpointErrorText(id, err))
		return
	}
	h.auditEndpoints(r, kind, id, inventory.EndpointKey(e), ch)
	http.Redirect(w, r, back, http.StatusSeeOther)
}
