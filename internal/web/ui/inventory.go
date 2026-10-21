// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// hostView is one row of the inventory table, pre-formatted for display.
// Every field is untrusted host data, rendered as text only.
type hostView struct {
	// ID is the host ID.
	ID string
	// DisplayName is the host's display name.
	DisplayName string
	// Environment is DEV, QA or PROD.
	Environment string
	// Criticality is LOW, MEDIUM, HIGH or CRITICAL.
	Criticality string
	// Endpoints are "address:port" strings in stored order.
	Endpoints []string
	// OS is the PRETTY_NAME from the latest core.facts, "" if never read.
	OS string
	// State is the ops state (READY, WARNING, UNREACHABLE, UNKNOWN),
	// StateLabel its display text, StateClass the badge CSS class and
	// StateReason the short reason line.
	State       string
	StateLabel  string
	StateClass  string
	StateReason string
	// StateFilter is the ?state= value that selects rows in this state.
	StateFilter string
	// KeyStatus is "pinned", "blocked", "not enrolled" or "unavailable".
	KeyStatus string
	// KeyType and KeyFingerprint are the pinned key's type and full
	// fingerprint; KeyShort is the fingerprint tail for the cell.
	KeyType        string
	KeyFingerprint string
	KeyShort       string
	// Updates are the counts of the latest package.list_updates.
	UpdatesSecurity int
	UpdatesTotal    int
	Reboot          bool
	// Containers are the counts of the latest docker.list.
	ContainersRunning int
	ContainersTotal   int
	ContainersKnown   bool
	// ContainerUpdates is the count of the latest docker.check_updates.
	ContainerUpdates int
	// FailedServices is the count of failed units of the latest
	// service.list.
	FailedServices int
	// LastSeen is the newest finished execution on the host.
	LastSeen    time.Time
	LastSeenSet bool
	// Search is the lowercased text the client-side filter matches.
	Search string
}

// batchData holds the per-host reads the inventory pages need, fetched
// with a constant number of queries (one per action, not one per host).
type batchData struct {
	facts    map[string]executions.LastResultRow
	updates  map[string]executions.HostUpdates
	docker   map[string]executions.LastResultRow
	dockerUp map[string]executions.LastResultRow
	services map[string]executions.LastResultRow
	states   map[string]executions.OpsState
	lastSeen map[string]time.Time
}

// batchData fetches the batch reads. Every failure is logged and leaves
// the affected column empty; the page still renders.
func (h *Handler) batchData(ctx context.Context) batchData {
	var b batchData
	if h.operations == nil {
		return b
	}
	if u, err := h.operations.AllUpdates(ctx); err != nil {
		h.log.Error("list host updates", "error", err)
	} else {
		b.updates = u
	}
	if s, err := h.operations.AllOpsStates(ctx); err != nil {
		h.log.Error("list ops states", "error", err)
	} else {
		b.states = s
	}
	if r, err := h.operations.LastResults(ctx, "core.facts"); err != nil {
		h.log.Error("list last facts", "error", err)
	} else {
		b.facts = r
	}
	if r, err := h.operations.LastResults(ctx, "docker.list"); err != nil {
		h.log.Error("list last docker lists", "error", err)
	} else {
		b.docker = r
	}
	if r, err := h.operations.LastResults(ctx, "docker.check_updates"); err != nil {
		h.log.Error("list last docker update checks", "error", err)
	} else {
		b.dockerUp = r
	}
	if r, err := h.operations.LastResults(ctx, "service.list"); err != nil {
		h.log.Error("list last service lists", "error", err)
	} else {
		b.services = r
	}
	if t, err := h.operations.LastSeenAll(ctx); err != nil {
		h.log.Error("list last seen", "error", err)
	} else {
		b.lastSeen = t
	}
	return b
}

// hostKeyPins maps a host ID to its SSH key pin. The second return value
// is true when the executor's pins could not be read. The executor pins
// one key per host; if a host ever has several pins, the blocked one
// wins, since it is the state that refuses connections.
func (h *Handler) hostKeyPins(ctx context.Context) (map[string]*pb.HostKeyPin, bool) {
	if h.hostKeys == nil {
		return nil, true
	}
	pins, err := h.hostKeys(ctx)
	if err != nil {
		// The column shows a fixed "unknown" state; the error detail
		// goes to the log only.
		h.log.Error("list host key pins", "error", err)
		return nil, true
	}
	byHost := make(map[string]*pb.HostKeyPin, len(pins))
	for _, pin := range pins {
		if pin == nil {
			continue
		}
		id := pin.GetHostId()
		if cur, ok := byHost[id]; !ok || (pin.GetBlocked() && !cur.GetBlocked()) {
			byHost[id] = pin
		}
	}
	return byHost, false
}

// shortFingerprint is the tail of a fingerprint for the table cell; the
// full value stays in the title attribute.
func shortFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if len(fp) > 12 {
		return "…" + fp[len(fp)-12:]
	}
	return fp
}

// stateBadge is the display text, CSS class and ?state= filter value of
// an ops state. A blocked pin shows as Critical, a host without a pin as
// "Not enrolled".
func stateBadge(state, keyStatus string) (label, class, filter string) {
	switch {
	case keyStatus == "blocked":
		return "Critical", "badge--critical", "critical"
	case keyStatus == "not enrolled":
		return "Not enrolled", "badge--unknown", "not_enrolled"
	case state == executions.StateReady:
		return "OK", "badge--ok", "ok"
	case state == executions.StateWarning:
		return "Warning", "badge--warning", "warning"
	case state == executions.StateUnreachable:
		return "Critical", "badge--critical", "critical"
	default:
		return "Unknown", "badge--unknown", "unknown"
	}
}

// viewHost formats one inventory host for the table. The facts, update
// lists and container lists are untrusted host output: they are parsed
// by the bounded parsers and rendered as text only.
func viewHost(host inventory.Host, pins map[string]*pb.HostKeyPin, pinsUnavailable bool, b batchData) hostView {
	v := hostView{
		ID:          host.ID,
		DisplayName: host.DisplayName,
		Environment: string(host.Environment),
		Criticality: string(host.Criticality),
		KeyStatus:   "not enrolled",
	}
	for _, e := range host.Endpoints {
		port := e.Port
		if port == 0 {
			port = defaultSSHPort
		}
		// JoinHostPort brackets IPv6 addresses ("[fd00::1]:22").
		v.Endpoints = append(v.Endpoints, net.JoinHostPort(e.Address, strconv.Itoa(port)))
	}
	if row, ok := b.facts[host.ID]; ok {
		for _, f := range executions.DecodeFacts(row.Result) {
			if f.Name == "Operating system" {
				v.OS = f.Value
				break
			}
		}
	}
	if pinsUnavailable {
		v.KeyStatus = "unavailable"
	} else if pin, ok := pins[host.ID]; ok {
		if pin.GetBlocked() {
			v.KeyStatus = "blocked"
		} else {
			v.KeyStatus = "pinned"
			v.KeyType = pin.GetKeyType()
			v.KeyFingerprint = pin.GetFingerprint()
			v.KeyShort = shortFingerprint(pin.GetFingerprint())
		}
	}
	keyStatusText := "not enrolled"
	switch v.KeyStatus {
	case "pinned":
		keyStatusText = "pinned " + v.KeyType + " " + v.KeyFingerprint
	case "blocked":
		keyStatusText = "BLOCKED (host key mismatch)"
	case "unavailable":
		keyStatusText = "executor unavailable"
	}
	st, reason := opsStateView(b.states[host.ID], keyStatusText)
	v.State, v.StateReason = st, reason
	v.StateLabel, v.StateClass, v.StateFilter = stateBadge(st, v.KeyStatus)
	if u, ok := b.updates[host.ID]; ok {
		v.UpdatesSecurity, v.UpdatesTotal, v.Reboot = u.Security, u.Total, u.RebootRequired
	}
	if row, ok := b.docker[host.ID]; ok {
		if l, err := dockerhost.ParseList(row.Result); err == nil {
			v.ContainersKnown = true
			for _, c := range l.Containers {
				v.ContainersTotal++
				if c.Running() {
					v.ContainersRunning++
				}
			}
		}
	}
	if row, ok := b.dockerUp[host.ID]; ok {
		if u, err := dockerhost.ParseImageUpdates(row.Result); err == nil {
			v.ContainerUpdates = u.Updates
		}
	}
	if row, ok := b.services[host.ID]; ok {
		if units, err := osdebian.ParseUnits(row.Result); err == nil {
			for _, u := range units {
				if u.Active == "failed" {
					v.FailedServices++
				}
			}
		}
	}
	if at, ok := b.lastSeen[host.ID]; ok {
		v.LastSeen, v.LastSeenSet = at, true
	}
	var sb strings.Builder
	sb.WriteString(strings.ToLower(host.ID))
	sb.WriteByte(' ')
	sb.WriteString(strings.ToLower(host.DisplayName))
	sb.WriteByte(' ')
	sb.WriteString(strings.ToLower(v.OS))
	for _, e := range v.Endpoints {
		sb.WriteByte(' ')
		sb.WriteString(strings.ToLower(e))
	}
	v.Search = sb.String()
	return v
}

// inventoryRowMatches reports whether a row passes the server-side
// filters (?state=, ?env=, ?updates=1, ?reboot=1, ?containers=1,
// ?services=1). Empty filters select everything.
func inventoryRowMatches(v hostView, state, env string, updates, reboot, containers, services bool) bool {
	if state != "" && v.StateFilter != state {
		return false
	}
	if env != "" && v.Environment != env {
		return false
	}
	if updates && v.UpdatesTotal == 0 {
		return false
	}
	if reboot && !v.Reboot {
		return false
	}
	if containers && v.ContainerUpdates == 0 {
		return false
	}
	if services && v.FailedServices == 0 {
		return false
	}
	return true
}

// handleInventory renders the inventory list (GET) and adds a host from
// the add form (POST, with or without JavaScript).
func (h *Handler) handleInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.handleHostFormCreate(w, r)
		return
	}
	h.renderInventory(w, r, false, "", false)
}

// handleInventoryNew renders the inventory with the add-host dialog
// open: the form is reachable without JavaScript.
func (h *Handler) handleInventoryNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.renderInventory(w, r, true, "", false)
}

// renderInventory renders the inventory list. dialogOpen shows the
// add-host dialog (open attribute); errMsg is a form error shown in the
// dialog; confirmDup adds the hidden confirmation field so the form can
// be resubmitted after a duplicate-endpoint warning.
func (h *Handler) renderInventory(w http.ResponseWriter, r *http.Request, dialogOpen bool, errMsg string, confirmDup bool) {
	data := pageData{Title: "Inventory", Active: "inventory", Content: "inventory"}
	if h.inventory != nil {
		data.InventoryEditable = true
		data.EnrollEnabled = h.enroll != nil && h.hosts != nil
		data.Scripts = []string{"webauthn.js", "inventory.js"}
		if id := r.URL.Query().Get("asset"); id != "" {
			ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
			data.InventoryPrefill = h.assetPrefill(ctx, id)
			cancel()
		}
	}
	data.InventoryDialogOpen = dialogOpen
	data.InventoryError = errMsg
	data.InventoryConfirmDuplicate = confirmDup
	if h.hosts == nil {
		h.render(w, r, data)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	hosts, err := h.hosts(ctx)
	if err != nil {
		// The page shows a fixed "Inventory unavailable" message; the
		// error detail (which can contain internal state) goes to the
		// log only.
		h.log.Error("list inventory hosts", "error", err)
		data.InventoryUnavailable = true
		h.render(w, r, data)
		return
	}
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	b := h.batchData(ctx)
	q := r.URL.Query()
	stateF, envF := q.Get("state"), q.Get("env")
	updatesF, rebootF := q.Get("updates") == "1", q.Get("reboot") == "1"
	containersF, servicesF := q.Get("containers") == "1", q.Get("services") == "1"
	filtered := stateF != "" || envF != "" || updatesF || rebootF || containersF || servicesF
	envs := map[string]bool{}
	for _, host := range hosts {
		envs[string(host.Environment)] = true
	}
	for _, host := range hosts {
		v := viewHost(host, pins, pinsUnavailable, b)
		if filtered && !inventoryRowMatches(v, stateF, envF, updatesF, rebootF, containersF, servicesF) {
			continue
		}
		data.Inventory = append(data.Inventory, v)
	}
	data.InventoryState, data.InventoryEnv = stateF, envF
	for e := range envs {
		data.InventoryEnvs = append(data.InventoryEnvs, e)
	}
	sort.Strings(data.InventoryEnvs)
	h.render(w, r, data)
}

// maxHostBodyBytes limits the JSON body of the host change endpoints.
const maxHostBodyBytes = 64 << 10

// hostRequest is the body of the create and update endpoints. Endpoints
// are strings parsed by sshtransport.ParseEndpoint ("host", "host:port"
// or "[v6]:port").
type hostRequest struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name"`
	Environment string            `json:"environment"`
	Criticality string            `json:"criticality"`
	Endpoints   []string          `json:"endpoints"`
	Tags        map[string]string `json:"tags"`
	// ConfirmDuplicate skips the duplicate-endpoint warning (the
	// "Add anyway" confirmation).
	ConfirmDuplicate bool `json:"confirm_duplicate"`
}

// toHost converts the request into an inventory host, parsing every
// endpoint. The returned error describes the input only.
func (in hostRequest) toHost() (inventory.Host, error) {
	h := inventory.Host{
		ID:          in.ID,
		DisplayName: in.DisplayName,
		Environment: inventory.Environment(in.Environment),
		Criticality: inventory.Criticality(in.Criticality),
		Tags:        in.Tags,
	}
	for _, s := range in.Endpoints {
		e, err := sshtransport.ParseEndpoint(s)
		if err != nil {
			return inventory.Host{}, err
		}
		port := int(e.Port)
		if port == 0 {
			port = 22 // the inventory default; the store stores it explicitly
		}
		h.Endpoints = append(h.Endpoints, inventory.Endpoint{Address: e.Host, Port: port})
	}
	return h, nil
}

// decodeHostRequest reads and validates the JSON body of a create or
// update request. It returns the parsed request and host, or an error
// describing the input (bad JSON, unknown fields, oversized body, bad
// endpoint).
func decodeHostRequest(w http.ResponseWriter, r *http.Request) (hostRequest, inventory.Host, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxHostBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return hostRequest{}, inventory.Host{}, fmt.Errorf("read request body: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var in hostRequest
	if err := dec.Decode(&in); err != nil {
		return hostRequest{}, inventory.Host{}, fmt.Errorf("request body is not valid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return hostRequest{}, inventory.Host{}, errors.New("request body contains data after the JSON object")
	}
	host, err := in.toHost()
	return in, host, err
}

// readHostForm fills the request from the add or edit form (one endpoint
// per line, one key=value tag per line).
func readHostForm(r *http.Request, in *hostRequest) error {
	if err := r.ParseForm(); err != nil {
		return errors.New("the form could not be read")
	}
	in.ID = r.PostFormValue("id")
	in.DisplayName = r.PostFormValue("display_name")
	in.Environment = r.PostFormValue("environment")
	in.Criticality = r.PostFormValue("criticality")
	for _, line := range strings.Split(r.PostFormValue("endpoints"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			in.Endpoints = append(in.Endpoints, line)
		}
	}
	for _, line := range strings.Split(r.PostFormValue("tags"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if in.Tags == nil {
			in.Tags = map[string]string{}
		}
		in.Tags[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	in.ConfirmDuplicate = r.PostFormValue("confirm_duplicate") == "1"
	return nil
}

// tagFingerprintRe matches a whole line that is an SSH host key
// fingerprint (SHA256:… or MD5:…).
var tagFingerprintRe = regexp.MustCompile(`(?i)^(sha256|md5):[0-9a-f]{2}(:[0-9a-f]{2})*$`)

// errTagsFormat is the tag validation error: the value looks like a
// pasted host key or is not key=value labels.
var errTagsFormat = errors.New("Tags are key=value labels; host keys are read and pinned under Enroll hosts")

// validateTagText checks a block of tag lines (one key=value per line).
func validateTagText(text string) error {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if tagFingerprintRe.MatchString(line) || !strings.Contains(line, "=") {
			return errTagsFormat
		}
	}
	return nil
}

// validateTagValue checks one tag value: a multi-line value must be
// key=value labels, and a value that is a whole fingerprint is a pasted
// host key.
func validateTagValue(v string) error {
	if strings.Contains(v, "\n") {
		return validateTagText(v)
	}
	if tagFingerprintRe.MatchString(strings.TrimSpace(v)) {
		return errTagsFormat
	}
	return nil
}

// duplicateEndpointError is the warning that an endpoint is already used
// by another host. It does not block; the form confirms with
// confirm_duplicate.
type duplicateEndpointError struct {
	Endpoint string
	Other    string
}

func (e *duplicateEndpointError) Error() string {
	return "duplicate endpoint: " + e.Endpoint + " is already used by host " + e.Other
}

// checkHostRequest applies the request-level rules before the store is
// touched: tag values must not look like pasted host keys, and an
// endpoint used by another host needs a confirmation.
func (h *Handler) checkHostRequest(ctx context.Context, in hostRequest, host inventory.Host) error {
	for _, v := range host.Tags {
		if err := validateTagValue(v); err != nil {
			return err
		}
	}
	if in.ConfirmDuplicate || h.hosts == nil {
		return nil
	}
	all, err := h.hosts(ctx)
	if err != nil {
		return nil // the warning is best effort; the store checks still apply
	}
	for _, other := range all {
		if other.ID == in.ID {
			continue
		}
		for _, oe := range other.Endpoints {
			for _, ne := range host.Endpoints {
				if oe.Address == ne.Address && oe.Port == ne.Port {
					return &duplicateEndpointError{Endpoint: net.JoinHostPort(oe.Address, strconv.Itoa(oe.Port)), Other: other.ID}
				}
			}
		}
	}
	return nil
}

// answerStoreError maps an inventory store error to a JSON response:
// validation problems (which describe the input) are 400 with the
// problem text, unknown hosts are 404, and everything else is 500 with
// a fixed message — the detail goes to the log only.
func (h *Handler) answerStoreError(w http.ResponseWriter, action, id string, err error) {
	var verr *inventory.ValidationError
	switch {
	case errors.As(err, &verr):
		writeJSONError(w, http.StatusBadRequest, verr.Error())
	case errors.Is(err, inventory.ErrHostNotFound):
		writeJSONError(w, http.StatusNotFound, "host not found")
	case errors.Is(err, inventory.ErrHostExists):
		writeJSONError(w, http.StatusConflict, "a host with this ID already exists")
	default:
		h.log.Error(action, "host", id, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "inventory unavailable")
	}
}

// hostChangeAllowed answers the request itself unless it is a JSON POST
// to a configured inventory. Requiring application/json is defence in
// depth next to the Origin check: no plain HTML form can send it.
func (h *Handler) hostChangeAllowed(w http.ResponseWriter, r *http.Request) bool {
	if h.inventory == nil {
		http.NotFound(w, r)
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); !strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	return true
}

func (h *Handler) handleHostCreate(w http.ResponseWriter, r *http.Request) {
	if !h.hostChangeAllowed(w, r) {
		return
	}
	in, host, err := decodeHostRequest(w, r)
	if err != nil {
		answerDecodeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.checkHostRequest(ctx, in, host); err != nil {
		var dup *duplicateEndpointError
		if errors.As(err, &dup) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": dup.Error(), "duplicate_endpoint": true})
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := h.inventory.Create(ctx, host, inventory.CreateOptions{})
	if err != nil {
		h.answerStoreError(w, "create host", host.ID, err)
		return
	}
	h.audit(r, "host_created", created.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": created.ID})
}

func (h *Handler) handleHostUpdate(w http.ResponseWriter, r *http.Request) {
	if !h.hostChangeAllowed(w, r) {
		return
	}
	in, host, err := decodeHostRequest(w, r)
	if err != nil {
		answerDecodeError(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.checkHostRequest(ctx, in, host); err != nil {
		var dup *duplicateEndpointError
		if errors.As(err, &dup) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": dup.Error(), "duplicate_endpoint": true})
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := h.inventory.Update(ctx, host); err != nil {
		h.answerStoreError(w, "update host", host.ID, err)
		return
	}
	h.audit(r, "host_updated", host.ID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": host.ID})
}

// handleHostFormCreate adds a host from the add form: a plain form POST
// (without JavaScript) or the dialog's JSON POST. A JSON request gets a
// JSON answer; a form request is redirected to the new host's page.
func (h *Handler) handleHostFormCreate(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil {
		http.Error(w, "inventory is not configured", http.StatusServiceUnavailable)
		return
	}
	var in hostRequest
	jsonIn := false
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		jsonIn = true
		var host inventory.Host
		var err error
		in, host, err = decodeHostRequest(w, r)
		if err != nil {
			answerDecodeError(w, err)
			return
		}
		h.finishHostCreate(w, r, in, host, jsonIn)
		return
	}
	if err := readHostForm(r, &in); err != nil {
		h.renderInventory(w, r, true, err.Error(), false)
		return
	}
	host, err := in.toHost()
	if err != nil {
		h.renderInventory(w, r, true, "Invalid endpoint: "+err.Error(), false)
		return
	}
	h.finishHostCreate(w, r, in, host, jsonIn)
}

func (h *Handler) finishHostCreate(w http.ResponseWriter, r *http.Request, in hostRequest, host inventory.Host, jsonIn bool) {
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.checkHostRequest(ctx, in, host); err != nil {
		var dup *duplicateEndpointError
		if errors.As(err, &dup) {
			if jsonIn {
				writeJSON(w, http.StatusConflict, map[string]any{"error": dup.Error(), "duplicate_endpoint": true})
				return
			}
			h.renderInventory(w, r, true, dup.Error(), true)
			return
		}
		if jsonIn {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.renderInventory(w, r, true, err.Error(), false)
		return
	}
	created, err := h.inventory.Create(ctx, host, inventory.CreateOptions{})
	if err != nil {
		if jsonIn {
			h.answerStoreError(w, "create host", host.ID, err)
			return
		}
		h.renderInventory(w, r, true, storeErrorText(err), false)
		return
	}
	h.audit(r, "host_created", created.ID)
	if jsonIn {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": created.ID})
		return
	}
	http.Redirect(w, r, "/hosts/"+created.ID, http.StatusSeeOther)
}

// storeErrorText is the form-facing text of a store error: input
// problems describe the input, everything else is fixed.
func storeErrorText(err error) string {
	var verr *inventory.ValidationError
	if errors.As(err, &verr) {
		return verr.Error()
	}
	if errors.Is(err, inventory.ErrHostExists) {
		return "A host with this ID already exists."
	}
	return "The inventory could not be reached."
}

// handleHostFormUpdate edits a host from the settings form (a plain form
// POST or the dialog's JSON POST).
func (h *Handler) handleHostFormUpdate(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil {
		http.Error(w, "inventory is not configured", http.StatusServiceUnavailable)
		return
	}
	var in hostRequest
	jsonIn := false
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.EqualFold(strings.TrimSpace(ct), "application/json") {
		jsonIn = true
		var host inventory.Host
		var err error
		in, host, err = decodeHostRequest(w, r)
		if err != nil {
			answerDecodeError(w, err)
			return
		}
		h.finishHostUpdate(w, r, in, host, jsonIn)
		return
	}
	if err := readHostForm(r, &in); err != nil {
		http.Redirect(w, r, "/hosts/"+urlEscape(in.ID)+"?tab=settings", http.StatusSeeOther)
		return
	}
	host, err := in.toHost()
	if err != nil {
		http.Redirect(w, r, "/hosts/"+urlEscape(in.ID)+"?tab=settings", http.StatusSeeOther)
		return
	}
	h.finishHostUpdate(w, r, in, host, jsonIn)
}

func (h *Handler) finishHostUpdate(w http.ResponseWriter, r *http.Request, in hostRequest, host inventory.Host, jsonIn bool) {
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.checkHostRequest(ctx, in, host); err != nil {
		var dup *duplicateEndpointError
		if errors.As(err, &dup) {
			if jsonIn {
				writeJSON(w, http.StatusConflict, map[string]any{"error": dup.Error(), "duplicate_endpoint": true})
				return
			}
			http.Redirect(w, r, "/hosts/"+urlEscape(in.ID)+"?tab=settings&warn="+urlEscape(dup.Error()), http.StatusSeeOther)
			return
		}
		if jsonIn {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		http.Redirect(w, r, "/hosts/"+urlEscape(in.ID)+"?tab=settings&warn="+urlEscape(err.Error()), http.StatusSeeOther)
		return
	}
	if _, err := h.inventory.Update(ctx, host); err != nil {
		if jsonIn {
			h.answerStoreError(w, "update host", host.ID, err)
			return
		}
		http.Redirect(w, r, "/hosts/"+urlEscape(in.ID)+"?tab=settings&warn="+urlEscape(storeErrorText(err)), http.StatusSeeOther)
		return
	}
	h.audit(r, "host_updated", host.ID)
	if jsonIn {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": host.ID})
		return
	}
	http.Redirect(w, r, "/hosts/"+urlEscape(in.ID)+"?tab=settings", http.StatusSeeOther)
}

// handleHostFormDelete deletes a host from the settings form. The host
// ID must be typed into the form (the delete confirmation); a mismatch
// goes back to the settings tab.
func (h *Handler) handleHostFormDelete(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil {
		http.Error(w, "inventory is not configured", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	id := r.PostFormValue("id")
	if r.PostFormValue("confirm_id") != id || !validHostIDText(id) {
		http.Redirect(w, r, "/hosts/"+urlEscape(id)+"?tab=settings&warn=Type the host ID to confirm the deletion.", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.inventory.Delete(ctx, id); err != nil {
		h.log.Error("delete host", "host", id, "error", err)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	h.audit(r, "host_deleted", id)
	http.Redirect(w, r, "/inventory", http.StatusSeeOther)
}

// urlEscape is the path-safe form of a host ID for redirects.
func urlEscape(s string) string {
	return strings.ReplaceAll(s, "%", "%25")
}

// dashboardTile is one of the host tiles on the dashboard.
type dashboardTile struct {
	Num   int
	Label string
	Class string
	Href  string
}

// dashboardTiles counts the hosts by state and by pending work, for the
// dashboard tiles. Each tile links to the filtered inventory.
func (h *Handler) dashboardTiles(ctx context.Context) []dashboardTile {
	ctx, cancel := context.WithTimeout(ctx, inventoryCallTimeout)
	defer cancel()
	hosts, err := h.hosts(ctx)
	if err != nil {
		return nil
	}
	pins, pinsUnavailable := h.hostKeyPins(ctx)
	b := h.batchData(ctx)
	tiles := []dashboardTile{
		{Label: "OK", Class: "tile--ok", Href: "/inventory?state=ok"},
		{Label: "Warning", Class: "tile--warning", Href: "/inventory?state=warning"},
		{Label: "Critical", Class: "tile--critical", Href: "/inventory?state=critical"},
		{Label: "Unknown", Class: "tile--unknown", Href: "/inventory?state=unknown"},
		{Label: "Not enrolled", Class: "tile--unknown", Href: "/inventory?state=not_enrolled"},
	}
	var updates, reboot, containers, services int
	for _, host := range hosts {
		v := viewHost(host, pins, pinsUnavailable, b)
		switch v.StateFilter {
		case "ok":
			tiles[0].Num++
		case "warning":
			tiles[1].Num++
		case "critical":
			tiles[2].Num++
		case "unknown":
			tiles[3].Num++
		case "not_enrolled":
			tiles[4].Num++
		}
		if v.UpdatesTotal > 0 {
			updates++
		}
		if v.Reboot {
			reboot++
		}
		if v.ContainerUpdates > 0 {
			containers++
		}
		if v.FailedServices > 0 {
			services++
		}
	}
	tiles = append(tiles,
		dashboardTile{Num: updates, Label: "Hosts with updates", Class: "tile--accent", Href: "/inventory?updates=1"},
		dashboardTile{Num: reboot, Label: "Reboot required", Class: "tile--accent", Href: "/inventory?reboot=1"},
		dashboardTile{Num: containers, Label: "Containers with updates", Class: "tile--accent", Href: "/inventory?containers=1"},
		dashboardTile{Num: services, Label: "Failed services", Class: "tile--accent", Href: "/inventory?services=1"},
	)
	return tiles
}

// handleHostDelete removes a host from the JSON endpoint (the inventory
// rows used to carry the delete button; the host page's settings tab
// now does it through the form).
func (h *Handler) handleHostDelete(w http.ResponseWriter, r *http.Request) {
	if !h.hostChangeAllowed(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxHostBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		answerDecodeError(w, err)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var in deleteRequest
	if err := dec.Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON: "+err.Error())
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeJSONError(w, http.StatusBadRequest, "request body contains data after the JSON object")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	if err := h.inventory.Delete(ctx, in.ID); err != nil {
		h.answerStoreError(w, "delete host", in.ID, err)
		return
	}
	h.audit(r, "host_deleted", in.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// validHostIDText reports whether the text is a valid host ID (the
// delete form's typed confirmation must match one).
func validHostIDText(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
