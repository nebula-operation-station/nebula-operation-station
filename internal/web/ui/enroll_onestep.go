// SPDX-License-Identifier: AGPL-3.0-or-later

// One-step enrollment dialog (ADR 0013 D1, EN-10 part 1, without NetBird).
//
// The web session that holds the executor's privileged session creates an
// enrollment offer for an inventory host. The offer page shows the command
// block of ADR 0013 D1 step 3 (sudo and root variants) with the download
// URL and the script's SHA-256, a "Show script" view that never consumes
// the offer, a browser download fallback, and the pairing-code form. The
// code is checked (length, alphabet, check character) in the browser by
// static JavaScript and again here before the executor is asked; the
// executor decides whether the code matched. A match shows the approval
// page with the full fingerprint and "code matched"; a mismatch shows the
// ADR 0013 D3 text.
//
// The offer ID, the download capability, exists on the server only in the
// in-memory offer table, bound to the creating web session. UI URLs name
// the offer by the SHA-256 of its ID; the ID is never logged.

package ui

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
	"github.com/nebula-operation-station/nebula-operation-station/web/templates"
)

// EnrollOffers is the executor client of the one-step enrollment dialog
// (ADR 0013, spec 03 offer RPCs). New takes it from Options.Enroll when
// that value implements it, as the executor gRPC client does; otherwise
// the dialog's routes answer 404.
type EnrollOffers interface {
	CreateEnrollOffer(ctx context.Context, in *pb.CreateEnrollOfferRequest, opts ...grpc.CallOption) (*pb.CreateEnrollOfferResponse, error)
	ShowEnrollScript(ctx context.Context, in *pb.ShowEnrollScriptRequest, opts ...grpc.CallOption) (*pb.ShowEnrollScriptResponse, error)
	DownloadEnrollScript(ctx context.Context, in *pb.DownloadEnrollScriptRequest, opts ...grpc.CallOption) (*pb.DownloadEnrollScriptResponse, error)
	SubmitPairingCode(ctx context.Context, in *pb.SubmitPairingCodeRequest, opts ...grpc.CallOption) (*pb.SubmitPairingCodeResponse, error)
	CommitPairedEnroll(ctx context.Context, in *pb.CommitPairedEnrollRequest, opts ...grpc.CallOption) (*pb.CommitPairedEnrollResponse, error)
	RevokeEnrollOffer(ctx context.Context, in *pb.RevokeEnrollOfferRequest, opts ...grpc.CallOption) (*pb.RevokeEnrollOfferResponse, error)
	SubmitAssertion(ctx context.Context, in *pb.SubmitAssertionRequest, opts ...grpc.CallOption) (*pb.SubmitAssertionResponse, error)
}

// More limits of the one-step dialog.
const (
	// onestepScriptMax is the largest script passed on (ADR 0013 D5).
	onestepScriptMax = 64 << 10
	// onestepMaxEndpoints is the most inventory endpoints sent with a
	// code (SubmitPairingCodeRequest.inventory_endpoints).
	onestepMaxEndpoints = 8
	// onestepEndpointMaxLen bounds a typed endpoint: a DNS name of at most
	// 253 bytes, or a bracketed IPv6 literal, plus ":port".
	onestepEndpointMaxLen = 262
	// onestepCallTimeout bounds one executor call of the dialog; the
	// pairing probe and the commit's re-probe and login test take longest.
	onestepCallTimeout = time.Minute
	// onestepFormMax bounds a form body of the dialog.
	onestepFormMax = 8 << 10
	// onestepWebAuthnTimeoutMS is the browser's timeout for the approval
	// touch.
	onestepWebAuthnTimeoutMS = 120000
	// onestepDefaultUser and onestepDefaultCredential are the dialog's
	// defaults (ADR 0013 D1 step 1).
	onestepDefaultUser       = "nebula"
	onestepDefaultCredential = "nebula-default"
	// onestepPath is the dialog's route prefix.
	onestepPath = "/inventory/enroll/onestep"
)

// onestepMismatchText is the UI text for a code mismatch, verbatim from
// ADR 0013 D3 "Failure handling".
const onestepMismatchText = "The host at this endpoint presents a key that does not match the code from the host. " +
	"Either the endpoint is a different machine, or something is in between. Check the endpoint, then create a new offer."

var (
	// onestepUserRE is a non-root POSIX user name, as cmd/nebula/enroll.go
	// accepts; the executor validates again.
	onestepUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// onestepCredentialRE is a credential reference.
	onestepCredentialRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// onestepCredIDRE is a base64url WebAuthn credential ID.
	onestepCredIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,1000}$`)
)

// onestep is the dialog's state, built by New.
type onestep struct {
	offers EnrollOffers
	addr   *clientaddr.Resolver
	table  *onestepTable
	page   *template.Template
}

// newOnestep builds the dialog for o; offers nil disables it.
func newOnestep(o Options, log *slog.Logger) (*onestep, error) {
	offers, _ := o.Enroll.(EnrollOffers)
	addr := o.EnrollClientAddr
	if addr == nil {
		// No trusted proxy configured: the peer is the client.
		var err error
		if addr, err = clientaddr.New(clientaddr.Config{}, log); err != nil {
			return nil, fmt.Errorf("ui: enrollment client address: %w", err)
		}
	}
	page, err := template.New("").Funcs(template.FuncMap{"timeTag": timeTag}).ParseFS(templates.FS, "layout.html", "enroll_onestep.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parse template enroll_onestep: %w", err)
	}
	return &onestep{offers: offers, addr: addr, table: newOnestepTable(), page: page}, nil
}

// registerOnestep adds the dialog's routes.
func (h *Handler) registerOnestep(mux *http.ServeMux) {
	mux.HandleFunc("GET "+onestepPath, h.handleOnestepDialog)
	mux.HandleFunc("POST "+onestepPath, h.handleOnestepCreate)
	mux.HandleFunc("GET "+onestepPath+"/{offer}", h.handleOnestepOffer)
	mux.HandleFunc("GET "+onestepPath+"/{offer}/script", h.handleOnestepShow)
	mux.HandleFunc("POST "+onestepPath+"/{offer}/download", h.handleOnestepDownload)
	mux.HandleFunc("POST "+onestepPath+"/{offer}/code", h.handleOnestepCode)
	mux.HandleFunc("POST "+onestepPath+"/{offer}/commit", h.handleOnestepCommit)
	mux.HandleFunc("POST "+onestepPath+"/{offer}/revoke", h.handleOnestepRevoke)
}

// onestepHostOption is one host of the dialog's host picker.
type onestepHostOption struct {
	ID, Name string
	Selected bool
}

// onestepView is the data of enroll_onestep.html. Every string is
// rendered as text by html/template.
type onestepView struct {
	// Step is "dialog", "offer", "approve", "mismatch" or "final".
	Step       string
	Privileged bool
	Error      string
	// Dialog.
	Hosts      []onestepHostOption
	SSHUser    string
	Credential string
	Sudo       bool
	// Offer.
	Path        string
	HostID      string
	HostName    string
	OfferSudo   bool
	Expires     time.Time
	SHA256      string
	CommandSudo string
	CommandRoot string
	Endpoints   []string
	Code        string
	Other       string
	// Approve and mismatch.
	Paired     *onestepPaired
	Mismatch   string
	FinalState string
}

// onestepPageData is the layout data plus the dialog's view.
type onestepPageData struct {
	pageData
	Onestep *onestepView
}

func (h *Handler) onestepEnabled(w http.ResponseWriter, r *http.Request) bool {
	if h.onestep == nil || h.onestep.offers == nil || h.inventory == nil || h.hosts == nil {
		http.NotFound(w, r)
		return false
	}
	return true
}

// onestepBinding returns the session binding of an authenticated request.
func onestepBinding(r *http.Request) ([]byte, bool) {
	if _, ok := auth.SessionFrom(r.Context()); !ok {
		return nil, false
	}
	c, err := r.Cookie(auth.CookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	return onestepBindingOf(c.Value), true
}

// onestepPrivileged reports whether this web session holds the executor's
// open privileged session (ADR 0007). An unreadable status counts as not
// open (fail closed).
func (h *Handler) onestepPrivileged(ctx context.Context) bool {
	if h.status == nil {
		return false
	}
	sctx, cancel := context.WithTimeout(ctx, statusCallTimeout)
	defer cancel()
	st, err := h.status.GetStatus(sctx, &pb.GetStatusRequest{})
	if err != nil {
		h.log.Error("privileged session check for enrollment", "error", err)
		return false
	}
	return st.GetPrivilegedSessionActive() && auth.HoldsPrivilegedSession(ctx, st.GetPrivilegedSessionExpiryUnix())
}

// onestepClient resolves the client and peer address with the shared
// client-address function (ADR 0013 D7). A trusted proxy's request
// without a usable X-Forwarded-For header is refused with 400 before any
// state changes.
func (h *Handler) onestepClient(r *http.Request) (clientaddr.Result, error) {
	res, err := h.onestep.addr.Resolve(r)
	if err != nil {
		return clientaddr.Result{}, fmt.Errorf("client address: %w", err)
	}
	return res, nil
}

// onestepAudit writes an audit line with the user, the offer's hash
// prefix and the client and peer address. The offer ID is never logged.
func (h *Handler) onestepAudit(r *http.Request, kind, host, idHash string, addr clientaddr.Result, extra ...any) {
	args := []any{"kind", kind, "host", host, "user", webUser(r), "offer", onestepLogID(idHash),
		"client", addrText(addr.Client), "peer", addrText(addr.Peer)}
	h.log.Info("audit", append(args, extra...)...)
}

// onestepLogID is the first 8 hex characters of the offer ID hash.
func onestepLogID(idHash string) string {
	if len(idHash) < 8 {
		return idHash
	}
	return idHash[:8]
}

// renderOnestep renders the dialog page with status code.
func (h *Handler) renderOnestep(w http.ResponseWriter, r *http.Request, code int, v *onestepView) {
	data := onestepPageData{pageData: pageData{Title: "Add host (one step)", Active: "inventory", Content: "enroll_onestep",
		Scripts: []string{"webauthn.js", "enroll-onestep.js"}}, Onestep: v}
	data.Theme = themeFromRequest(r)
	data.NavCollapsed = navStateFromRequest(r) == navCollapsed
	data.PVENav = h.pve != nil
	data.DeployEnabled = h.deploy != nil && h.pve != nil && h.pveRemotes != nil
	if h.builtinTrust != nil {
		data.BuiltinTrust = h.builtinTrust.get(r.Context())
	}
	var buf strings.Builder
	if err := h.onestep.page.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.log.Error("render page", "page", "enroll_onestep", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The offer page carries the download capability: never cache it.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if _, err := w.Write([]byte(buf.String())); err != nil {
		h.log.Debug("write page", "page", "enroll_onestep", "error", err)
	}
}

// onestepHosts lists the inventory hosts without a pinned key.
func (h *Handler) onestepHosts(ctx context.Context) ([]inventory.Host, error) {
	hosts, err := h.hosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	pinned := map[string]bool{}
	if h.hostKeys != nil {
		pins, err := h.hostKeys(ctx)
		if err != nil {
			return nil, fmt.Errorf("list host keys: %w", err)
		}
		for _, p := range pins {
			pinned[p.GetHostId()] = true
		}
	}
	out := make([]inventory.Host, 0, len(hosts))
	for _, x := range hosts {
		if !pinned[x.ID] {
			out = append(out, x)
		}
	}
	return out, nil
}

func hostLabel(x inventory.Host) string {
	if x.DisplayName == "" {
		return x.ID
	}
	return x.DisplayName
}

func (h *Handler) handleOnestepDialog(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	v := &onestepView{Step: "dialog", SSHUser: onestepDefaultUser, Credential: onestepDefaultCredential, Sudo: true}
	h.onestepDialog(w, r, http.StatusOK, v, r.URL.Query().Get("host"))
}

// onestepDialog fills the host picker and renders the dialog; without the
// privileged session it renders the notice only, with 403.
func (h *Handler) onestepDialog(w http.ResponseWriter, r *http.Request, code int, v *onestepView, selected string) {
	v.Step = "dialog"
	v.Privileged = h.onestepPrivileged(r.Context())
	if !v.Privileged {
		h.renderOnestep(w, r, http.StatusForbidden, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), inventoryCallTimeout)
	defer cancel()
	hosts, err := h.onestepHosts(ctx)
	if err != nil {
		h.log.Error("enrollment dialog", "error", err)
		v.Error = "Inventory or executor unavailable."
		h.renderOnestep(w, r, http.StatusBadGateway, v)
		return
	}
	for _, x := range hosts {
		v.Hosts = append(v.Hosts, onestepHostOption{ID: x.ID, Name: hostLabel(x), Selected: x.ID == selected})
	}
	h.renderOnestep(w, r, code, v)
}

// onestepForm parses a small form body.
func onestepForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, onestepFormMax)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return false
	}
	return true
}

func (h *Handler) handleOnestepCreate(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	addr, err := h.onestepClient(r)
	if err != nil {
		http.Error(w, "the reverse proxy sent no usable X-Forwarded-For header", http.StatusBadRequest)
		return
	}
	binding, ok := onestepBinding(r)
	if !ok || !h.onestepPrivileged(r.Context()) {
		h.renderOnestep(w, r, http.StatusForbidden, &onestepView{Step: "dialog"})
		return
	}
	if !onestepForm(w, r) {
		return
	}
	v := &onestepView{SSHUser: r.PostForm.Get("ssh_user"), Credential: r.PostForm.Get("credential"), Sudo: onestepChecked(r.PostForm.Get("sudo"))}
	hostID := r.PostForm.Get("host")
	refuse := func(msg string) {
		v.Error = msg
		h.onestepDialog(w, r, http.StatusBadRequest, v, hostID)
	}
	switch {
	case r.PostForm.Has("netbird"):
		refuse("Joining NetBird is not available in this dialog yet.")
		return
	case !canonical.ValidHostID(hostID):
		refuse("Choose a host from the inventory.")
		return
	case v.SSHUser == "root" || !onestepUserRE.MatchString(v.SSHUser):
		refuse("The SSH user must be a valid user name other than root.")
		return
	case !onestepCredentialRE.MatchString(v.Credential):
		refuse("The credential reference is not valid.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), onestepCallTimeout)
	defer cancel()
	hosts, err := h.onestepHosts(ctx)
	if err != nil {
		h.log.Error("enrollment offer", "error", err)
		refuse("Inventory or executor unavailable.")
		return
	}
	i := slices.IndexFunc(hosts, func(x inventory.Host) bool { return x.ID == hostID })
	if i < 0 {
		refuse("The host is not in the inventory or already has a pinned key.")
		return
	}
	host := hosts[i]
	resp, err := h.onestep.offers.CreateEnrollOffer(ctx, &pb.CreateEnrollOfferRequest{HostId: hostID, SshUser: v.SSHUser,
		CredentialRef: v.Credential, Sudo: v.Sudo, SessionBinding: binding})
	if err != nil {
		refuse(h.onestepRefusal("create enrollment offer", err))
		return
	}
	id, idHash, sum := resp.GetOfferId(), resp.GetOfferIdHash(), resp.GetScriptSha256()
	idSum := sha256.Sum256([]byte(id))
	if !onestepValidOfferID(id) || idHash != hex.EncodeToString(idSum[:]) || !onestepValidHex(sum) || resp.GetNetbirdPermit() != nil {
		h.log.Error("enrollment offer: malformed executor answer", "offer", onestepLogID(idHash))
		h.onestepRevokeQuietly(idHash)
		refuse("The executor answered with a malformed offer; it was revoked.")
		return
	}
	if _, _, err := onestepCommands(h.publicOrigin, id, sum); err != nil {
		h.log.Error("enrollment offer: command", "error", err)
		h.onestepRevokeQuietly(idHash)
		refuse("The public origin cannot be used in the enrollment command; the offer was revoked.")
		return
	}
	now := h.clockNow()
	expires := time.Unix(resp.GetExpiresUnix(), 0)
	if resp.GetExpiresUnix() <= 0 || expires.After(now.Add(onestepOfferTTL+time.Minute)) {
		expires = now.Add(onestepOfferTTL)
	}
	o := &onestepOffer{idHash: idHash, id: id, binding: binding, hostID: hostID, hostName: hostLabel(host), sshUser: v.SSHUser,
		credential: v.Credential, sudo: v.Sudo, sha256: sum, created: now, expires: expires, endpoints: endpointStrings(host)}
	if err := h.onestep.table.add(o, now); err != nil {
		h.onestepRevokeQuietly(idHash)
		refuse("Too many open offers; revoke one or wait until they expire.")
		return
	}
	h.onestepAudit(r, "enroll_offer_created", hostID, idHash, addr, "ssh_user", v.SSHUser, "credential", v.Credential, "sudo", v.Sudo)
	http.Redirect(w, r, onestepPath+"/"+idHash, http.StatusSeeOther)
}

func onestepChecked(s string) bool { return s == "1" || s == "on" || s == "true" }

// onestepRevokeQuietly revokes an offer the server cannot use.
func (h *Handler) onestepRevokeQuietly(idHash string) {
	if !onestepValidHex(idHash) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), statusCallTimeout)
	defer cancel()
	if _, err := h.onestep.offers.RevokeEnrollOffer(ctx, &pb.RevokeEnrollOfferRequest{OfferIdHash: idHash}); err != nil {
		h.log.Error("revoke enrollment offer", "offer", onestepLogID(idHash), "error", err)
	}
}

// onestepRefusal turns an executor error into a message for the page.
func (h *Handler) onestepRefusal(op string, err error) string {
	st, _ := status.FromError(err)
	switch st.Code() {
	case codes.InvalidArgument, codes.FailedPrecondition, codes.PermissionDenied, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound:
		return "The executor refused: " + onestepTrim(st.Message(), 300)
	default:
		h.log.Error(op, "error", err)
		return "Executor unavailable."
	}
}

// onestepLookup finds the offer of the {offer} path value for this web
// session; anything else is 404.
func (h *Handler) onestepLookup(w http.ResponseWriter, r *http.Request) (onestepOffer, []byte, bool) {
	idHash := r.PathValue("offer")
	binding, ok := onestepBinding(r)
	if !ok || !onestepValidOfferHash(idHash) {
		http.NotFound(w, r)
		return onestepOffer{}, nil, false
	}
	o, ok := h.onestep.table.get(idHash, binding, h.clockNow())
	if !ok {
		http.NotFound(w, r)
		return onestepOffer{}, nil, false
	}
	return o, binding, true
}

// offerView builds the offer page's view.
func (h *Handler) offerView(o onestepOffer) *onestepView {
	v := &onestepView{Step: "offer", Path: onestepPath + "/" + o.idHash, HostID: o.hostID, HostName: o.hostName, SSHUser: o.sshUser,
		Credential: o.credential, OfferSudo: o.sudo, Expires: o.expires, SHA256: o.sha256, Endpoints: o.endpoints,
		Paired: o.paired, FinalState: o.finalState}
	if o.final {
		v.Step = "final"
		return v
	}
	if o.paired != nil {
		v.Step = "approve"
		return v
	}
	sudo, root, err := onestepCommands(h.publicOrigin, o.id, o.sha256)
	if err != nil {
		v.Error = "The enrollment command cannot be shown."
		return v
	}
	v.CommandSudo, v.CommandRoot = sudo, root
	return v
}

func (h *Handler) handleOnestepOffer(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	o, _, ok := h.onestepLookup(w, r)
	if !ok {
		return
	}
	h.renderOnestep(w, r, http.StatusOK, h.offerView(o))
}

// setScriptHeaders sets the headers of the script view and the browser
// download (ADR 0013 D1 step 3, D7).
func setScriptHeaders(w http.ResponseWriter) {
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	hd.Set("X-Accel-Buffering", "no")
}

// handleOnestepShow serves "Show script": the placeholder render as its
// own text/plain response. It never consumes the offer.
func (h *Handler) handleOnestepShow(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	o, binding, ok := h.onestepLookup(w, r)
	if !ok {
		return
	}
	if o.final {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), onestepCallTimeout)
	defer cancel()
	resp, err := h.onestep.offers.ShowEnrollScript(ctx, &pb.ShowEnrollScriptRequest{OfferId: o.id, SessionBinding: binding})
	if err != nil {
		h.log.Info("show enrollment script refused", "offer", onestepLogID(o.idHash), "code", status.Code(err).String())
		setScriptHeaders(w)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not available\n"))
		return
	}
	script := resp.GetScript()
	if len(script) > onestepScriptMax {
		setScriptHeaders(w)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("script too large\n"))
		return
	}
	setScriptHeaders(w)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(script)
}

// handleOnestepDownload serves "Download in browser": it consumes the
// offer like the download route and is answered with the D7 headers.
func (h *Handler) handleOnestepDownload(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	addr, err := h.onestepClient(r)
	if err != nil {
		http.Error(w, "the reverse proxy sent no usable X-Forwarded-For header", http.StatusBadRequest)
		return
	}
	o, binding, ok := h.onestepLookup(w, r)
	if !ok {
		return
	}
	if o.final || o.paired != nil {
		h.onestepOfferError(w, r, o, http.StatusConflict, "The offer can no longer be downloaded.")
		return
	}
	if !h.onestepPrivileged(r.Context()) {
		h.onestepOfferError(w, r, o, http.StatusForbidden, "Downloading needs this web session's privileged session.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), onestepCallTimeout)
	defer cancel()
	resp, err := h.onestep.offers.DownloadEnrollScript(ctx, &pb.DownloadEnrollScriptRequest{OfferId: o.id, SessionBinding: binding,
		ClientAddr: addrText(addr.Client), PeerAddr: addrText(addr.Peer)})
	if err != nil {
		h.onestepOfferError(w, r, o, http.StatusConflict, "The script was not released (already downloaded, expired or revoked).")
		return
	}
	script := resp.GetScript()
	sum := sha256.Sum256(script)
	if len(script) > onestepScriptMax || hex.EncodeToString(sum[:]) != o.sha256 || resp.GetScriptSha256() != o.sha256 {
		h.log.Error("browser download: script does not match the offer's hash", "offer", onestepLogID(o.idHash))
		h.onestepOfferError(w, r, o, http.StatusBadGateway, "The script does not match the offer's SHA-256; it was not passed on.")
		return
	}
	setScriptHeaders(w)
	w.Header().Set("Content-Disposition", `attachment; filename="`+onestepScriptName+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(script)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(script)
	clear(script)
}

// onestepOfferError renders the offer page with an error.
func (h *Handler) onestepOfferError(w http.ResponseWriter, r *http.Request, o onestepOffer, code int, msg string) {
	v := h.offerView(o)
	v.Error = msg
	h.renderOnestep(w, r, code, v)
}

// onestepEndpoint returns the endpoint the operator picked or typed.
func onestepEndpoint(o onestepOffer, choice, typed string) (string, bool) {
	if choice != "other" {
		return choice, slices.Contains(o.endpoints, choice)
	}
	typed = strings.TrimSpace(typed)
	if typed == "" || len(typed) > onestepEndpointMaxLen {
		return "", false
	}
	for i := 0; i < len(typed); i++ {
		c := typed[i]
		if c <= ' ' || c >= 0x7f || c == '\'' || c == '"' || c == '\\' || c == '/' || c == '@' {
			return "", false
		}
	}
	return typed, true
}

// onestepCodeMessage explains a malformed code.
func onestepCodeMessage(err error) string {
	var me *pairing.MalformedError
	if errors.As(err, &me) {
		switch me.Kind {
		case pairing.KindAlphabet:
			return fmt.Sprintf("The pairing code has an invalid character at position %d.", me.Position)
		case pairing.KindCheck:
			return "The pairing code's check character does not match: there is a typing error in the code."
		}
	}
	return "The pairing code must have 25 characters (five groups of five)."
}

func (h *Handler) handleOnestepCode(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	addr, err := h.onestepClient(r)
	if err != nil {
		http.Error(w, "the reverse proxy sent no usable X-Forwarded-For header", http.StatusBadRequest)
		return
	}
	o, binding, ok := h.onestepLookup(w, r)
	if !ok {
		return
	}
	if o.final || o.paired != nil {
		h.onestepOfferError(w, r, o, http.StatusConflict, "This offer accepts no further code.")
		return
	}
	if !onestepForm(w, r) {
		return
	}
	raw, choice, typed := r.PostForm.Get("code"), r.PostForm.Get("endpoint"), r.PostForm.Get("endpoint_other")
	fail := func(code int, msg string) {
		v := h.offerView(o)
		v.Error, v.Other = msg, onestepTrim(typed, onestepEndpointMaxLen)
		h.renderOnestep(w, r, code, v)
	}
	parsed, err := pairing.Parse(raw)
	if err != nil {
		fail(http.StatusBadRequest, onestepCodeMessage(err))
		return
	}
	endpoint, ok := onestepEndpoint(o, choice, typed)
	if !ok {
		fail(http.StatusBadRequest, "Pick an inventory endpoint or type an address the script printed.")
		return
	}
	if !h.onestepPrivileged(r.Context()) {
		fail(http.StatusForbidden, "Submitting the code needs this web session's privileged session.")
		return
	}
	eps := o.endpoints
	if len(eps) > onestepMaxEndpoints {
		eps = eps[:onestepMaxEndpoints]
	}
	ctx, cancel := context.WithTimeout(r.Context(), onestepCallTimeout)
	defer cancel()
	resp, err := h.onestep.offers.SubmitPairingCode(ctx, &pb.SubmitPairingCodeRequest{OfferIdHash: o.idHash, SessionBinding: binding,
		Code: parsed.String(), Endpoint: endpoint, InventoryEndpoints: eps})
	if err != nil {
		fail(http.StatusConflict, h.onestepRefusal("submit pairing code", err))
		return
	}
	switch resp.GetOutcome() {
	case pb.PairingOutcome_PAIRING_OUTCOME_MATCHED:
		h.onestepMatched(w, r, o, binding, addr, parsed.String(), resp)
	case pb.PairingOutcome_PAIRING_OUTCOME_MISMATCH:
		h.onestep.table.update(o.idHash, binding, func(x *onestepOffer) { x.final, x.finalState = true, "failed" })
		h.onestepAudit(r, "enroll_code_mismatch", o.hostID, o.idHash, addr, "endpoint", resp.GetEndpoint(),
			"presented", resp.GetFingerprint(), "notify", resp.GetNotify())
		v := h.offerView(o)
		v.Step, v.Mismatch, v.FinalState = "mismatch", onestepMismatchText, "failed"
		v.Paired = &onestepPaired{Endpoint: resp.GetEndpoint(), Fingerprint: resp.GetFingerprint(), KeyType: resp.GetKeyType()}
		h.renderOnestep(w, r, http.StatusOK, v)
	case pb.PairingOutcome_PAIRING_OUTCOME_CODE_REJECTED:
		fail(http.StatusBadRequest, "The executor rejected the pairing code: "+onestepTrim(resp.GetDetail(), 200))
	case pb.PairingOutcome_PAIRING_OUTCOME_PROBE_FAILED:
		fail(http.StatusOK, "The endpoint could not be probed ("+onestepTrim(resp.GetDetail(), 200)+"). This is not a mismatch; pick another endpoint.")
	default:
		fail(http.StatusBadGateway, "The executor gave no pairing result.")
	}
}

// onestepMatched stores the paired permit and renders the approval page.
func (h *Handler) onestepMatched(w http.ResponseWriter, r *http.Request, o onestepOffer, binding []byte, addr clientaddr.Result, code string,
	resp *pb.SubmitPairingCodeResponse) {
	perm := resp.GetPermit()
	if perm == nil || !onestepValidHex(perm.GetDigest()) || len(perm.GetChallenge()) == 0 {
		h.onestepOfferError(w, r, o, http.StatusBadGateway, "The executor proposed no valid approval.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), statusCallTimeout)
	defer cancel()
	p := &onestepPaired{Digest: perm.GetDigest(), Endpoint: resp.GetEndpoint(), EndpointToAdd: resp.GetEndpointToAdd(),
		Fingerprint: resp.GetFingerprint(), KeyType: resp.GetKeyType(), Code: code,
		OptionsJSON: h.onestepRequestOptions(ctx, perm.GetChallenge()), ApprovalUntil: time.Unix(perm.GetApprovalExpiryUnix(), 0)}
	if !h.onestep.table.update(o.idHash, binding, func(x *onestepOffer) { x.paired = p }) {
		http.NotFound(w, r)
		return
	}
	h.onestepAudit(r, "enroll_paired_proposed", o.hostID, o.idHash, addr, "endpoint", p.Endpoint, "endpoint_to_add", p.EndpointToAdd,
		"fingerprint", p.Fingerprint, "digest", p.Digest)
	o.paired = p
	h.renderOnestep(w, r, http.StatusOK, h.offerView(o))
}

// onestepRequestOptions builds the WebAuthn request options for the
// paired permit's challenge. The browser signs the challenge; the
// executor verifies the assertion.
func (h *Handler) onestepRequestOptions(ctx context.Context, challenge []byte) string {
	type cred struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	type pk struct {
		Challenge        string `json:"challenge"`
		Timeout          int    `json:"timeout"`
		UserVerification string `json:"userVerification"`
		AllowCredentials []cred `json:"allowCredentials,omitempty"`
	}
	opts := struct {
		PublicKey pk `json:"publicKey"`
	}{pk{Challenge: base64.RawURLEncoding.EncodeToString(challenge), Timeout: onestepWebAuthnTimeoutMS, UserVerification: "required"}}
	if h.securityKeys != nil {
		keys, err := h.securityKeys(ctx)
		if err != nil {
			h.log.Error("list security keys for enrollment approval", "error", err)
		}
		for _, k := range keys {
			if id := k.GetCredentialId(); onestepCredIDRE.MatchString(id) {
				opts.PublicKey.AllowCredentials = append(opts.PublicKey.AllowCredentials, cred{Type: "public-key", ID: id})
			}
		}
	}
	b, err := json.Marshal(opts)
	if err != nil {
		return ""
	}
	return string(b)
}

func (h *Handler) handleOnestepCommit(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	addr, err := h.onestepClient(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "the reverse proxy sent no usable X-Forwarded-For header")
		return
	}
	idHash := r.PathValue("offer")
	binding, ok := onestepBinding(r)
	if !ok || !onestepValidOfferHash(idHash) {
		writeJSONError(w, http.StatusNotFound, "no such offer")
		return
	}
	o, ok := h.onestep.table.get(idHash, binding, h.clockNow())
	if !ok {
		writeJSONError(w, http.StatusNotFound, "no such offer")
		return
	}
	var in struct {
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readOpsJSON(w, r, &in) {
		return
	}
	if o.final || o.paired == nil {
		writeJSONError(w, http.StatusConflict, "this offer has no pending approval")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*onestepCallTimeout)
	defer cancel()
	if len(in.Assertion) > 0 && string(in.Assertion) != "null" {
		if _, err := h.onestep.offers.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{ExecutionDigest: o.paired.Digest, AssertionJson: in.Assertion}); err != nil {
			switch status.Code(err) {
			case codes.PermissionDenied, codes.Unauthenticated:
				writeJSONError(w, http.StatusForbidden, "security key not accepted")
			default:
				h.executorRefusal(w, "approve paired enrollment", err)
			}
			return
		}
	}
	c, err := h.onestep.offers.CommitPairedEnroll(ctx, &pb.CommitPairedEnrollRequest{OfferIdHash: o.idHash, SessionBinding: binding,
		PermitDigest: o.paired.Digest})
	if err != nil {
		h.executorRefusal(w, "commit paired enrollment", err)
		return
	}
	out := map[string]any{"pinned": c.GetPinned(), "fingerprint": c.GetFingerprint(), "login_ok": c.GetLoginOk(),
		"login_detail": c.GetLoginDetail(), "error": c.GetError(), "state": c.GetState()}
	if c.GetPinned() {
		h.onestep.table.update(o.idHash, binding, func(x *onestepOffer) { x.final, x.finalState = true, "enrolled" })
		h.onestepAudit(r, "host_enrolled", o.hostID, o.idHash, addr, "fingerprint", c.GetFingerprint(), "source", "paired")
		if ep := c.GetEndpointAdded(); ep != "" {
			if err := h.onestepAddEndpoint(ctx, o.hostID, ep); err != nil {
				h.log.Error("add paired endpoint to inventory", "host", o.hostID, "error", err)
				out["endpoint_error"] = "the host is pinned, but the endpoint could not be added to the inventory: add " + ep + " by hand"
			} else {
				out["endpoint_added"] = ep
				h.onestepAudit(r, "inventory_endpoint_added", o.hostID, o.idHash, addr, "endpoint", ep, "source", "paired")
			}
		}
	} else if c.GetState() == "failed" {
		h.onestep.table.update(o.idHash, binding, func(x *onestepOffer) { x.final, x.finalState = true, "failed" })
		if c.GetNotify() {
			h.onestepAudit(r, "enroll_commit_key_changed", o.hostID, o.idHash, addr, "presented", c.GetFingerprint())
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// onestepAddEndpoint appends an endpoint the executor named after a
// successful pin to the host's endpoint list; it never replaces or
// reorders the existing endpoints.
func (h *Handler) onestepAddEndpoint(ctx context.Context, hostID, ep string) error {
	addrPart, portPart, err := net.SplitHostPort(ep)
	port := 22
	if err != nil {
		addrPart = strings.Trim(ep, "[]")
	} else if port, err = strconv.Atoi(portPart); err != nil {
		return fmt.Errorf("endpoint %q: port: %w", ep, err)
	}
	host, err := h.inventory.Get(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get host %s: %w", hostID, err)
	}
	for _, e := range host.Endpoints {
		p := e.Port
		if p == 0 {
			p = 22
		}
		if strings.EqualFold(e.Address, addrPart) && p == port {
			return nil
		}
	}
	host.Endpoints = append(host.Endpoints, inventory.Endpoint{Address: addrPart, Port: port})
	if _, err := h.inventory.Update(ctx, host); err != nil {
		return fmt.Errorf("update host %s: %w", hostID, err)
	}
	return nil
}

func (h *Handler) handleOnestepRevoke(w http.ResponseWriter, r *http.Request) {
	if !h.onestepEnabled(w, r) {
		return
	}
	addr, err := h.onestepClient(r)
	if err != nil {
		http.Error(w, "the reverse proxy sent no usable X-Forwarded-For header", http.StatusBadRequest)
		return
	}
	o, binding, ok := h.onestepLookup(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), onestepCallTimeout)
	defer cancel()
	if _, err := h.onestep.offers.RevokeEnrollOffer(ctx, &pb.RevokeEnrollOfferRequest{OfferIdHash: o.idHash}); err != nil {
		h.onestepOfferError(w, r, o, http.StatusConflict, h.onestepRefusal("revoke enrollment offer", err))
		return
	}
	h.onestep.table.update(o.idHash, binding, func(x *onestepOffer) { x.final, x.finalState = true, "revoked" })
	h.onestepAudit(r, "enroll_offer_revoked", o.hostID, o.idHash, addr)
	http.Redirect(w, r, onestepPath, http.StatusSeeOther)
}
