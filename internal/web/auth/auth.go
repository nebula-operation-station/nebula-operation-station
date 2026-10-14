// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth is the web login of nebula-server (Milestone 2, spec 05).
//
// The server holds no credential store. Login and registration are relayed
// to the executor, which verifies every WebAuthn response itself:
//
//	POST /login/begin    -> executor BeginLogin
//	POST /login/finish   -> executor FinishLogin, then a web session
//	POST /setup/begin    -> executor BeginRegistration (one-time code)
//	POST /setup/finish   -> executor FinishRegistration
//	POST /logout         -> session deleted
//
// Wrap protects every other path: without a valid session a GET is
// redirected to /login and anything else is answered 401. The session
// cookie is __Host- prefixed, Secure, HttpOnly and SameSite=Strict; the
// security middleware (internal/web/middleware) checks the Origin of every
// state-changing request before this package sees it. Pages therefore send
// POSTs with fetch (or htmx): under Referrer-Policy no-referrer a plain HTML
// form sends "Origin: null" and is rejected.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// CookieName is the session cookie. The __Host- prefix makes the browser
// insist on Secure, Path=/ and no Domain attribute.
const CookieName = "__Host-nebula_session"

// maxJSONBody bounds the JSON bodies of the login and setup endpoints.
const maxJSONBody = 64 << 10

// executorCallTimeout bounds each relayed executor call.
const executorCallTimeout = 10 * time.Second

// Executor is the part of the executor client the login needs.
// executorclient.Client implements it.
type Executor interface {
	BeginLogin(ctx context.Context, in *pb.BeginLoginRequest, opts ...grpc.CallOption) (*pb.BeginLoginResponse, error)
	FinishLogin(ctx context.Context, in *pb.FinishLoginRequest, opts ...grpc.CallOption) (*pb.FinishLoginResponse, error)
	BeginRegistration(ctx context.Context, in *pb.BeginRegistrationRequest, opts ...grpc.CallOption) (*pb.BeginRegistrationResponse, error)
	FinishRegistration(ctx context.Context, in *pb.FinishRegistrationRequest, opts ...grpc.CallOption) (*pb.FinishRegistrationResponse, error)
	BeginPrivilegedSession(ctx context.Context, in *pb.BeginPrivilegedSessionRequest, opts ...grpc.CallOption) (*pb.BeginPrivilegedSessionResponse, error)
	CompletePrivilegedSession(ctx context.Context, in *pb.CompletePrivilegedSessionRequest, opts ...grpc.CallOption) (*pb.CompletePrivilegedSessionResponse, error)
	Lock(ctx context.Context, in *pb.LockRequest, opts ...grpc.CallOption) (*pb.LockResponse, error)
	CheckCredential(ctx context.Context, in *pb.CheckCredentialRequest, opts ...grpc.CallOption) (*pb.CheckCredentialResponse, error)
}

// Options configure the Handler.
type Options struct {
	Executor Executor
	Sessions *Store
	Log      *slog.Logger
}

// Handler serves the login endpoints and enforces sessions.
type Handler struct {
	exec     Executor
	sessions *Store
	log      *slog.Logger
	checks   credentialChecks
}

// New returns a Handler. Executor and Sessions are required.
func New(o Options) (*Handler, error) {
	if o.Executor == nil || o.Sessions == nil {
		return nil, errors.New("auth: executor and session store are required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Handler{exec: o.Executor, sessions: o.Sessions, log: o.Log}, nil
}

type ctxKey struct{}

// SessionFrom returns the session of an authenticated request.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// publicPath reports whether path is reachable without a session: the
// login and setup pages and their endpoints, and static assets.
func publicPath(path string) bool {
	switch path {
	case "/login", "/login/begin", "/login/finish", "/setup", "/setup/begin", "/setup/finish":
		return true
	}
	return strings.HasPrefix(path, "/static/")
}

// Wrap returns next with the login endpoints added and every other path
// protected by a session. pages must serve GET /login and GET /setup (the
// UI does); they are reached through next.
func (h *Handler) Wrap(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/begin", h.loginBegin)
	mux.HandleFunc("POST /login/finish", h.loginFinish)
	mux.HandleFunc("POST /setup/begin", h.setupBegin)
	mux.HandleFunc("POST /setup/finish", h.setupFinish)
	mux.HandleFunc("POST /logout", h.logout)
	api := map[string]bool{"/login/begin": true, "/login/finish": true, "/setup/begin": true, "/setup/finish": true, "/logout": true}
	// Endpoints that need a session, served here after the session check.
	protected := http.NewServeMux()
	protected.HandleFunc("POST /privileged/begin", h.privilegedBegin)
	protected.HandleFunc("POST /privileged/finish", h.privilegedFinish)
	protected.HandleFunc("POST /executor/lock", h.executorLock)
	protectedAPI := map[string]bool{"/privileged/begin": true, "/privileged/finish": true, "/executor/lock": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if api[r.URL.Path] {
			mux.ServeHTTP(w, r)
			return
		}
		if publicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(CookieName)
		if err != nil {
			h.unauthenticated(w, r)
			return
		}
		sess, err := h.sessions.Lookup(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, ErrNoSession) {
				h.log.Error("session lookup", "error", err)
			}
			clearCookie(w)
			h.unauthenticated(w, r)
			return
		}
		if !h.credentialStillRegistered(r.Context(), c.Value, sess) {
			if err := h.sessions.Delete(r.Context(), c.Value); err != nil {
				h.log.Error("delete revoked session", "error", err)
			}
			h.log.Info("audit", "kind", "web_session_revoked", "user", sess.UserName, "credential", sess.CredentialID,
				"reason", "credential no longer registered")
			clearCookie(w)
			h.unauthenticated(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess))
		if protectedAPI[r.URL.Path] {
			protected.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
}

func setCookie(w http.ResponseWriter, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/", Expires: exp, MaxAge: int(time.Until(exp).Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON decodes a bounded JSON body into v; unknown fields are errors.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": "JSON expected"})
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "malformed request"})
		return false
	}
	return true
}

// relayError answers a failed executor call with a fixed message per
// class; the detail goes to the log only.
func (h *Handler) relayError(w http.ResponseWriter, op string, err error, msgs map[codes.Code]string) {
	code := status.Code(err)
	h.log.Warn("auth", "op", op, "code", code.String(), "error", err)
	if m, ok := msgs[code]; ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": m})
		return
	}
	if code == codes.ResourceExhausted {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many attempts in progress, try again shortly"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "executor unavailable"})
}

func (h *Handler) loginBegin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	b, err := h.exec.BeginLogin(ctx, &pb.BeginLoginRequest{})
	if status.Code(err) == codes.FailedPrecondition {
		writeJSON(w, http.StatusConflict, map[string]any{"setup": true, "error": "no security key is registered yet"})
		return
	}
	if err != nil {
		h.relayError(w, "begin_login", err, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"login_id": b.GetLoginId(), "options": json.RawMessage(b.GetRequestOptionsJson())})
}

func (h *Handler) loginFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LoginID   string          `json:"login_id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	res, err := h.exec.FinishLogin(ctx, &pb.FinishLoginRequest{LoginId: req.LoginID, AssertionJson: req.Assertion})
	if err != nil {
		h.relayError(w, "finish_login", err, map[codes.Code]string{
			codes.NotFound:        "login expired, try again",
			codes.Unauthenticated: "security key not accepted",
			codes.InvalidArgument: "security key not accepted",
		})
		return
	}
	token, sess, err := h.sessions.Create(r.Context(), res.GetCredentialId(), res.GetUserName())
	if err != nil {
		h.log.Error("create session", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create session"})
		return
	}
	h.log.Info("audit", "kind", "web_login", "user", res.GetUserName(), "credential", res.GetCredentialId())
	setCookie(w, token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": "/dashboard"})
}

func (h *Handler) setupBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	b, err := h.exec.BeginRegistration(ctx, &pb.BeginRegistrationRequest{Code: req.Code})
	if err != nil {
		h.relayError(w, "begin_registration", err, map[codes.Code]string{
			codes.Unauthenticated:    "registration code invalid or expired",
			codes.FailedPrecondition: "registration code required: run `nebula webauthn code` on the executor host",
			codes.InvalidArgument:    "registration code invalid or expired",
		})
		return
	}
	out := map[string]any{"registration_id": b.GetRegistrationId(), "creation_options": json.RawMessage(b.GetCreationOptionsJson())}
	if len(b.GetAuthorizationOptionsJson()) > 0 {
		out["authorization_options"] = json.RawMessage(b.GetAuthorizationOptionsJson())
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) setupFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RegistrationID string          `json:"registration_id"`
		Attestation    json.RawMessage `json:"attestation"`
		Assertion      json.RawMessage `json:"assertion,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), executorCallTimeout)
	defer cancel()
	if _, err := h.exec.FinishRegistration(ctx, &pb.FinishRegistrationRequest{
		RegistrationId: req.RegistrationID, AttestationJson: req.Attestation, AssertionJson: req.Assertion,
	}); err != nil {
		h.relayError(w, "finish_registration", err, map[codes.Code]string{
			codes.NotFound:           "registration expired, start again",
			codes.FailedPrecondition: "registration expired, start again",
			codes.PermissionDenied:   "security key or confirmation not accepted",
			codes.AlreadyExists:      "this security key is already registered",
			codes.InvalidArgument:    "registration not accepted",
		})
		return
	}
	h.log.Info("audit", "kind", "web_registration_relayed")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": "/login"})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		if err := h.sessions.Delete(r.Context(), c.Value); err != nil {
			h.log.Error("logout", "error", err)
		}
	}
	clearCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": "/login"})
}
