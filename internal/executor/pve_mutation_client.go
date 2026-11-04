// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvetransport"
)

// Limits of the production PVE mutation client, named next to the code
// that enforces them.
const (
	// pveMutationRequestTimeout bounds one PVE write or read call.
	pveMutationRequestTimeout = 30 * time.Second
	// pveMutationMaxReadBytes bounds one guest config, guest status, node
	// list or task list page response.
	pveMutationMaxReadBytes = 1 << 20
	// pveMutationMaxConfigKeys bounds the members of one guest config.
	pveMutationMaxConfigKeys = 1024
	// pveMutationTaskPage is the page size of a task list read.
	pveMutationTaskPage = 500
	// pveMutationMaxTaskPages bounds the pages of one task list read; a
	// longer list is not returned (the step stays reconciling).
	pveMutationMaxTaskPages = 10
	// pveMutationMaxStatusLen bounds a reported power or QMP status.
	pveMutationMaxStatusLen = 32
)

// pveNodeTargetDigestDomain separates the node target digest from every
// other hash.
const pveNodeTargetDigestDomain = "nos.pve.node-target.v1\x00"

var (
	// errPveMutationRead is a failed or invalid read of the remote. It
	// carries no remote text.
	errPveMutationRead = errors.New("executor: pve mutation client: read failed")
	// errPveMutationTaskList is a task list longer than the client reads.
	errPveMutationTaskList = errors.New("executor: pve mutation client: task list too long")

	pveStatusRe     = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	pveGenerationRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// pveMutationClient is the production PveMutationClient (ADR 0008). Every
// call builds the pinned transport of the remote (pveReadTrust and
// pveReadHTTP: pinned CA or leaf, approved endpoints, no proxy, no
// redirect). Writes carry only the action token the engine passes in;
// reads carry only the read token.
//
// A mutation is never sent twice: pvetransport fails a mutating request
// over to the next endpoint only while no connection to the failed
// endpoint was established, and reports anything later as ErrMaybeSent;
// the pveapi writer maps that to an unknown outcome, which the engine
// reconciles through the task list without redispatching.
type pveMutationClient struct {
	// trust returns the pinned transport trust of a remote.
	trust func(context.Context, executordb.PveRemote) (pvetransport.Trust, error)
	// secrets opens the guest password of a provisioning config step.
	secrets pveSecrets
	// now is the clock for certificate validity.
	now func() time.Time
	// block persistently blocks a remote whose trust rm (pin and trust
	// generation) failed verification (Service.pveTrustFailed: registry
	// block plus revocation of its provider grants and mutation permits,
	// and the trust fence when the block cannot be recorded), as every
	// other connection does. Nil only in tests that do not exercise trust
	// failures.
	block func(rm executordb.PveRemote)
}

var _ PveMutationClient = (*pveMutationClient)(nil)
var _ PveStepTaskIDer = (*pveMutationClient)(nil)

// pveTrustKey is one trust of a remote: its pin and the trust generation
// it was approved under. An admin re-pin always raises the generation.
type pveTrustKey struct {
	pin        string
	generation uint64
}

func pveTrustKeyOf(rm executordb.PveRemote) pveTrustKey {
	return pveTrustKey{pin: rm.TrustPin, generation: rm.TrustGeneration}
}

// pveTrustFence holds, per remote, the trust that failed verification but
// whose block could not be recorded in the registry. It fences exactly
// that trust: a remote record of the failed generation (or an older,
// stale record) is covered; a record of a newer generation means an admin
// re-pinned the remote since, and drops the entry. The fence is in memory
// only: after a restart the pin check fails again on the next connection
// and the block is retried there.
type pveTrustFence struct {
	mu     sync.Mutex
	failed map[string]pveTrustKey // remote ID -> failed trust
}

// add fences the trust of rm. An entry of a newer generation is kept: it
// covers rm's older record too.
func (f *pveTrustFence) add(rm executordb.PveRemote) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed == nil {
		f.failed = map[string]pveTrustKey{}
	}
	if k, ok := f.failed[rm.RemoteID]; ok && k.generation > rm.TrustGeneration {
		return
	}
	f.failed[rm.RemoteID] = pveTrustKeyOf(rm)
}

// covers reports whether rm is fenced and returns the fenced trust. A
// record of the failed generation is fenced also if its pin differs (that
// cannot come from a re-pin, so it fails closed). A record of a newer
// generation drops the entry and is not fenced. A nil fence covers
// nothing.
func (f *pveTrustFence) covers(rm executordb.PveRemote) (pveTrustKey, bool) {
	if f == nil {
		return pveTrustKey{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.failed[rm.RemoteID]
	if !ok {
		return pveTrustKey{}, false
	}
	if rm.TrustGeneration > k.generation {
		delete(f.failed, rm.RemoteID)
		return pveTrustKey{}, false
	}
	return k, true
}

// remove drops the entry of remoteID if it still fences k.
func (f *pveTrustFence) remove(remoteID string, k pveTrustKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed[remoteID] == k {
		delete(f.failed, remoteID)
	}
}

// pveStepFamily is the dispatcher a step method belongs to.
type pveStepFamily int

const (
	pveStepUnknown pveStepFamily = iota
	pveStepPower
	pveStepProvision
	pveStepImage
)

func pveStepFamilyOf(method string) pveStepFamily {
	if _, ok := GuestPowerStepTaskType(method); ok {
		return pveStepPower
	}
	if _, ok := ProvisionStepTaskType(method); ok {
		return pveStepProvision
	}
	if _, ok := ImageStepTaskType(method); ok {
		return pveStepImage
	}
	return pveStepUnknown
}

// TaskType implements PveMutationClient: the guest power, provisioning and
// image step allowlists, nothing else.
func (c *pveMutationClient) TaskType(method string) (string, bool) {
	switch pveStepFamilyOf(method) {
	case pveStepPower:
		return GuestPowerStepTaskType(method)
	case pveStepProvision:
		return ProvisionStepTaskType(method)
	case pveStepImage:
		return ImageStepTaskType(method)
	}
	return "", false
}

// TaskID implements PveStepTaskIDer with the ID field the step's PVE task
// carries.
func (c *pveMutationClient) TaskID(step PveMutationStep) (string, bool) {
	switch pveStepFamilyOf(step.Method) {
	case pveStepPower:
		return GuestPowerStepTaskID(step)
	case pveStepProvision:
		return ProvisionStepTaskID(step)
	case pveStepImage:
		return imageStepTaskID(step)
	}
	return "", false
}

// imageStepTaskID returns the ID field of the PVE task an image step
// creates: the file name of a download (pveapi.Writer.DownloadURL checks
// the same), otherwise the VMID.
func imageStepTaskID(step PveMutationStep) (string, bool) {
	switch step.Method {
	case pveStepImageDownload:
		var a pveImageDownloadArgs
		if decodeStepArgs(step.Args, &a) != nil || a.Filename == "" {
			return "", false
		}
		return a.Filename, true
	case pveStepImageCreateVM:
		var a pveImageCreateArgs
		if decodeStepArgs(step.Args, &a) != nil || a.VMID < pvecontract.MinVMID {
			return "", false
		}
		return strconv.FormatInt(a.VMID, 10), true
	case pveStepImageTemplate:
		var a pveImageTemplateArgs
		if decodeStepArgs(step.Args, &a) != nil || a.VMID < pvecontract.MinVMID {
			return "", false
		}
		return strconv.FormatInt(a.VMID, 10), true
	}
	return "", false
}

// conn builds the pinned HTTP client of rm for one call. A trust source
// that reports a changed trust identity (errPveReadTrust) blocks rm.
func (c *pveMutationClient) conn(ctx context.Context, rm executordb.PveRemote) (*http.Client, *pveTrustWatch, string, error) {
	if c.trust == nil {
		return nil, nil, "", errors.New("executor: pve mutation client: no trust source")
	}
	trust, err := c.trust(ctx, rm)
	if err != nil {
		if errors.Is(err, errPveReadTrust) {
			c.blockRemote(rm)
		}
		return nil, nil, "", fmt.Errorf("pve trust of remote %s: %w", rm.RemoteID, err)
	}
	now := c.now
	if now == nil {
		now = time.Now
	}
	return pveReadHTTP(rm, trust, now)
}

// blockRemote blocks rm after a trust failure seen by this client.
func (c *pveMutationClient) blockRemote(rm executordb.PveRemote) {
	if c.block != nil {
		c.block(rm)
	}
}

// checkTrust blocks rm when any request of this call failed pin
// verification and then reports the call as a trust failure, whatever its
// own result: a remote that presented another identity is blocked until
// an admin re-pins it (spec: the whole remote, persistently).
func (c *pveMutationClient) checkTrust(rm executordb.PveRemote, watch *pveTrustWatch, err error) error {
	if !watch.failed.Load() && !errors.Is(err, errPveReadTrust) {
		return err
	}
	c.blockRemote(rm)
	return fmt.Errorf("%w: %w", errPveMutationRead, errPveReadTrust)
}

// Dispatch implements PveMutationClient. It routes guest.qemu.* and
// guest.lxc.* to DispatchGuestPowerStep, pve.guest.* to
// DispatchProvisionStep and pve.image.* to DispatchImageStep, with a
// writer that carries only action. A step that cannot have reached the
// remote (unknown method, no transport, failed trust verification) wraps
// ErrPveRejected; every other failure means it may have been received.
func (c *pveMutationClient) Dispatch(ctx context.Context, rm executordb.PveRemote, node string, step PveMutationStep, action pveapi.TokenSupplier) (string, error) {
	family := pveStepFamilyOf(step.Method)
	if family == pveStepUnknown {
		return "", fmt.Errorf("dispatch: method not allowlisted: %w", ErrPveRejected)
	}
	if action == nil || !permit.ValidPveNodeName(node) {
		return "", fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		// No connection carried the step: the trust lookup is
		// credential-free and nothing was written.
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, err)
	}
	w, err := pveapi.NewWriter(base, hc, action, pveMutationRequestTimeout)
	if err != nil {
		return "", fmt.Errorf("dispatch %s: %w", step.Method, ErrPveRejected)
	}
	var upid string
	switch family {
	case pveStepPower:
		upid, err = DispatchGuestPowerStep(ctx, w, node, step)
	case pveStepProvision:
		upid, err = DispatchProvisionStep(ctx, w, c.secrets, node, step)
	default:
		upid, err = DispatchImageStep(ctx, w, node, step)
	}
	if watch.failed.Load() {
		// The TLS handshake that verifies the pin precedes every request
		// byte, a trust failure is terminal (no failover), and a mutation
		// is never failed over once a verified connection carried it: a
		// trust failure means nothing was sent. The remote is blocked.
		c.blockRemote(rm)
		return "", fmt.Errorf("dispatch %s: %w: %w", step.Method, ErrPveRejected, errPveReadTrust)
	}
	return upid, err
}

// TaskStatus implements PveMutationClient with the read token.
func (c *pveMutationClient) TaskStatus(ctx context.Context, rm executordb.PveRemote, node, upid string, read pveapi.TokenSupplier) (PveTaskStatus, error) {
	u, ok := executordb.ParsePveUPID(upid)
	if !ok || u.Node != node || read == nil {
		return PveTaskStatus{}, errPveMutationRead
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveTaskStatus{}, err
	}
	w, err := pveapi.NewWriter(base, hc, read, pveMutationRequestTimeout)
	if err != nil {
		return PveTaskStatus{}, errPveMutationRead
	}
	st, err := w.TaskStatus(ctx, upid)
	if terr := c.checkTrust(rm, watch, nil); terr != nil {
		return PveTaskStatus{}, terr
	}
	if err != nil {
		// PVE reports a missing task record like any other failure, so no
		// answer is taken as "task gone": the step stays reconciling.
		return PveTaskStatus{}, fmt.Errorf("task status: %w", errPveMutationRead)
	}
	if st.UPID != upid || st.Node != node {
		return PveTaskStatus{}, errPveMutationRead
	}
	if st.State == pveapi.TaskRunning {
		return PveTaskStatus{Running: true}, nil
	}
	return PveTaskStatus{ExitStatus: st.ExitStatus}, nil
}

// RecentTasks implements PveMutationClient: the UPIDs of node's tasks
// (finished and running) that started at or after since, with the read
// token. A list longer than the client reads is an error, never a partial
// answer.
func (c *pveMutationClient) RecentTasks(ctx context.Context, rm executordb.PveRemote, node string, since time.Time, read pveapi.TokenSupplier) ([]string, error) {
	if !permit.ValidPveNodeName(node) || read == nil {
		return nil, errPveMutationRead
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return nil, err
	}
	out, err := pveRecentTasks(ctx, hc, base, read, node, since)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return nil, err
	}
	return out, nil
}

// pveRecentTasks pages through node's task list. PVE pages by offset, so
// a task that starts between two page reads shifts the list and the last
// entry of a page reappears on the next one: every UPID is returned once.
func pveRecentTasks(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, node string, since time.Time) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for page := 0; page < pveMutationMaxTaskPages; page++ {
		q := url.Values{
			"source": {"all"},
			"start":  {strconv.Itoa(page * pveMutationTaskPage)},
			"limit":  {strconv.Itoa(pveMutationTaskPage)},
		}
		if !since.IsZero() {
			q.Set("since", strconv.FormatInt(since.Unix(), 10))
		}
		var entries []struct {
			UPID string `json:"upid"`
		}
		if err := pveGetData(ctx, hc, base, read, "/nodes/"+url.PathEscape(node)+"/tasks", q, &entries); err != nil {
			return nil, err
		}
		for _, e := range entries {
			if u, ok := executordb.ParsePveUPID(e.UPID); ok && u.Node == node && !seen[e.UPID] {
				seen[e.UPID] = true
				out = append(out, e.UPID)
			}
		}
		if len(entries) < pveMutationTaskPage {
			return out, nil
		}
	}
	return nil, errPveMutationTaskList
}

// TargetState implements PveMutationClient with the read token. A guest
// is read from the requested node and kind: ConfigDigest is the hex
// SHA-256 of its complete configuration (members in sorted order),
// Generation is PVE's config digest, Status and (QEMU) QMPStatus come from
// status/current. A node target must be listed online; its digest binds
// the node name.
func (c *pveMutationClient) TargetState(ctx context.Context, rm executordb.PveRemote, kind, node string, vmid uint64, read pveapi.TokenSupplier) (PveTargetState, error) {
	if err := permit.ValidateProviderMutationShape(kind, node, vmid); err != nil || read == nil {
		return PveTargetState{}, ErrPveMutationRequest
	}
	hc, watch, base, err := c.conn(ctx, rm)
	if err != nil {
		return PveTargetState{}, err
	}
	live, err := pveTargetState(ctx, hc, base, read, kind, node, vmid)
	if err = c.checkTrust(rm, watch, err); err != nil {
		return PveTargetState{}, err
	}
	return live, nil
}

// pveTargetState reads the live state of one validated target.
func pveTargetState(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, kind, node string, vmid uint64) (PveTargetState, error) {
	if kind == permit.ProviderKindNode {
		return pveNodeTargetState(ctx, hc, base, read, node)
	}
	guest := "/nodes/" + url.PathEscape(node) + "/" + kind + "/" + strconv.FormatUint(vmid, 10)
	var cfg map[string]json.RawMessage
	if err := pveGetData(ctx, hc, base, read, guest+"/config", nil, &cfg); err != nil {
		return PveTargetState{}, err
	}
	if len(cfg) == 0 || len(cfg) > pveMutationMaxConfigKeys {
		return PveTargetState{}, errPveMutationRead
	}
	var generation string
	if raw, ok := cfg["digest"]; !ok || json.Unmarshal(raw, &generation) != nil || !pveGenerationRe.MatchString(generation) {
		return PveTargetState{}, errPveMutationRead
	}
	canon, err := json.Marshal(cfg) // map members are marshalled in sorted order
	if err != nil {
		return PveTargetState{}, errPveMutationRead
	}
	sum := sha256.Sum256(canon)
	var st struct {
		VMID      json.RawMessage `json:"vmid"`
		Status    string          `json:"status"`
		QMPStatus string          `json:"qmpstatus"`
	}
	if err := pveGetData(ctx, hc, base, read, guest+"/status/current", nil, &st); err != nil {
		return PveTargetState{}, err
	}
	// PVE reports the VMID as a number (QEMU) or a string (LXC).
	want := strconv.FormatUint(vmid, 10)
	if (string(st.VMID) != want && string(st.VMID) != `"`+want+`"`) || !validPveStatus(st.Status) {
		return PveTargetState{}, errPveMutationRead
	}
	live := PveTargetState{Node: node, Kind: kind, ConfigDigest: hex.EncodeToString(sum[:]), Generation: generation, Status: st.Status}
	if kind == permit.ProviderKindQemu {
		if st.QMPStatus != "" && !validPveStatus(st.QMPStatus) {
			return PveTargetState{}, errPveMutationRead
		}
		// Not reported stays empty, and a power action fails closed.
		live.QMPStatus = st.QMPStatus
	}
	return live, nil
}

func validPveStatus(s string) bool {
	return len(s) <= pveMutationMaxStatusLen && pveStatusRe.MatchString(s)
}

// pveNodeTargetState reads the node list and reports node if it is listed
// online. A node target has no configuration of its own; its digest binds
// the exact node name.
func pveNodeTargetState(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, node string) (PveTargetState, error) {
	var nodes []struct {
		Node   string `json:"node"`
		Status string `json:"status"`
	}
	if err := pveGetData(ctx, hc, base, read, "/nodes", nil, &nodes); err != nil {
		return PveTargetState{}, err
	}
	found := 0
	online := false
	for _, n := range nodes {
		if n.Node == node {
			found++
			online = n.Status == "online"
		}
	}
	if found != 1 || !online {
		return PveTargetState{}, errPveMutationRead
	}
	sum := sha256.Sum256([]byte(pveNodeTargetDigestDomain + node))
	return PveTargetState{Node: node, ConfigDigest: hex.EncodeToString(sum[:])}, nil
}

// pveGetData performs one GET of the PVE API with the read token and
// decodes the "data" member of the envelope into out. The response must be
// HTTP 200, at most pveMutationMaxReadBytes and valid UTF-8 JSON. Errors
// carry no remote text.
func pveGetData(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, path string, q url.Values, out any) error {
	_, err := pveGet(ctx, hc, base, read, path, q, false, out)
	return err
}

// pveGetOptionalData is pveGetData for an endpoint that may not exist on
// the remote's version: HTTP 404 reports found false and decodes nothing.
func pveGetOptionalData(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, path string, out any) (bool, error) {
	return pveGet(ctx, hc, base, read, path, nil, true, out)
}

func pveGet(ctx context.Context, hc *http.Client, base string, read pveapi.TokenSupplier, path string, q url.Values, optional bool, out any) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, pveMutationRequestTimeout)
	defer cancel()
	u := base + "/api2/json" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, errPveMutationRead
	}
	tok, err := read(ctx)
	if err != nil || tok == "" {
		return false, errPveMutationRead
	}
	req.Header.Set("Authorization", tok)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, pvetransport.ErrTrustMismatch) {
			return false, fmt.Errorf("%w: %w", errPveMutationRead, errPveReadTrust)
		}
		return false, errPveMutationRead
	}
	defer resp.Body.Close()
	if optional && resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, pveMutationMaxReadBytes+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(raw) > pveMutationMaxReadBytes || !utf8.Valid(raw) {
		return false, errPveMutationRead
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil || len(env.Data) == 0 || strings.TrimSpace(string(env.Data)) == "null" {
		return false, errPveMutationRead
	}
	dd := json.NewDecoder(bytes.NewReader(env.Data))
	dd.UseNumber()
	if err := dd.Decode(out); err != nil {
		return false, errPveMutationRead
	}
	return true, nil
}
