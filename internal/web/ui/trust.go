// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Built-in trust banner cache limits. Every non-bare page shows the
// banner, so the server caches the executor's verdict instead of asking
// it (a full dry-run review) on every render.
const (
	// builtinTrustTTL is how long a fetched verdict is shown. After it
	// expires the verdict is stale and is never shown again: a stale
	// status renders as unavailable until a refresh succeeds.
	builtinTrustTTL = 30 * time.Second
	// builtinTrustFailTTL is how long an RPC failure is cached before
	// the next refresh is attempted.
	builtinTrustFailTTL = 5 * time.Second
	// builtinTrustPageWait bounds how long a page render waits for a
	// refresh. A slower executor makes that render show "unavailable";
	// the refresh keeps running in the background and fills the cache.
	builtinTrustPageWait = 300 * time.Millisecond
)

// Built-in trust banner display limits. The module list comes from the
// executor and is untrusted input; every page renders the banner, so
// its size is bounded.
const (
	// builtinTrustMaxModules is the most affected built-ins the banner
	// lists; the rest are counted in the detail sentence.
	builtinTrustMaxModules = 50
	// builtinTrustMaxNameBytes caps a displayed module name.
	builtinTrustMaxNameBytes = 128
	// builtinTrustMaxVersionBytes caps a displayed release or trusted
	// version.
	builtinTrustMaxVersionBytes = 64
)

// BuiltinTrustProvider reports the executor's built-in trust verdict
// (ADR 0007 E17, E19c). executorclient.Client satisfies it; in
// production cmd/nebula-server wires the (lazy) executor client as
// Options.BuiltinTrust.
type BuiltinTrustProvider interface {
	GetBuiltinTrustStatus(ctx context.Context, in *pb.GetBuiltinTrustStatusRequest, opts ...grpc.CallOption) (*pb.GetBuiltinTrustStatusResponse, error)
}

// builtinTrustView is the layout's built-in trust banner, pre-formatted
// for display. Module names and versions come from the executor and are
// untrusted text: the template renders them escaped, as text only.
type builtinTrustView struct {
	// Kind is "untrusted" or "unavailable"; it selects the banner style.
	Kind string
	// Headline is the banner's first sentence.
	Headline string
	// Command is the local CLI command, shown in <code>; empty when the
	// state is not untrusted.
	Command string
	// Affected lists the built-ins whose current state is not trusted.
	Affected []builtinTrustEntryView
	// Detail is the closing guidance sentence.
	Detail string
}

// builtinTrustEntryView is one affected built-in (untrusted text only).
type builtinTrustEntryView struct {
	// Name is the module name from the executor.
	Name string
	// Version is the version in the local release; empty when Removed.
	Version string
	// Trusted is the trusted version; empty when none is.
	Trusted string
	// Removed is true when the module is trusted locally but absent
	// from the release.
	Removed bool
}

// unavailableBuiltinTrust is the "unreachable" banner: not a trust
// verdict, no versions.
func unavailableBuiltinTrust() *builtinTrustView {
	return &builtinTrustView{
		Kind:     "unavailable",
		Headline: "Built-in trust status is unreachable: the executor could not read its local release bundle or trust store.",
		Detail:   "This is not a trust verdict: whether the built-ins are trusted is unknown. Check the executor on its host.",
	}
}

// builtinTrustBanner maps the executor's built-in trust status to the
// layout banner (ADR 0007 E17). A fully trusted status yields nil (no
// banner). Untrusted names the affected modules, the local CLI command
// and the lease-replacement rule. Unavailable is a distinct
// "unreachable" state: it is not a trust verdict and names no versions.
//
// Which modules are affected is the executor's per-module verdict
// (Change), not re-derived from versions and hashes: the executor can
// mark a module CHANGED with identical versions and hashes (its
// retained bytes are missing or corrupt).
func builtinTrustBanner(st *pb.GetBuiltinTrustStatusResponse) *builtinTrustView {
	switch st.GetState() {
	case pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED:
		v := &builtinTrustView{
			Kind:     "untrusted",
			Headline: "Built-ins are untrusted: every operation using them needs UV until you trust them.",
			Command:  "nebula artifact trust-builtins",
			Detail:   "Trusting new built-in versions does not amend existing read leases: approve a replacement grant for those exact versions.",
		}
		omitted := 0
		for _, m := range st.GetModules() {
			if m.GetChange() == pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_UNCHANGED {
				continue // byte-identical to the trusted version
			}
			if len(v.Affected) == builtinTrustMaxModules {
				omitted++
				continue
			}
			v.Affected = append(v.Affected, builtinTrustEntryView{
				Name:    clipTrustText(m.GetName(), builtinTrustMaxNameBytes),
				Version: clipTrustText(m.GetReleaseVersion(), builtinTrustMaxVersionBytes),
				Trusted: clipTrustText(m.GetTrustedVersion(), builtinTrustMaxVersionBytes),
				Removed: m.GetChange() == pb.BuiltinTrustChange_BUILTIN_TRUST_CHANGE_REMOVED,
			})
		}
		if omitted > 0 {
			v.Detail = fmt.Sprintf("%d more affected built-in(s) not listed. %s", omitted, v.Detail)
		}
		return v
	case pb.BuiltinTrustState_BUILTIN_TRUST_STATE_TRUSTED:
		return nil // the executor says trusted: no banner
	default:
		// Unavailable, unspecified, a nil response or a state this
		// build does not know: fail closed, never shown as trusted.
		return unavailableBuiltinTrust()
	}
}

// clipTrustText returns s as valid UTF-8 of at most limit bytes. Longer
// text is cut on a rune boundary and ends in "…" (within the limit).
func clipTrustText(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= limit {
		return s
	}
	const ellipsis = "…"
	n := max(limit-len(ellipsis), 0)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + ellipsis
}

// builtinTrustCache caches the banner for page renders. One refresh
// runs at a time (single flight), detached from the request and bounded
// by callTimeout; a render waits at most wait for it. A verdict is shown
// only while fresh: an expired, failed or still-pending status renders
// as unavailable, never as trusted.
type builtinTrustCache struct {
	provider    BuiltinTrustProvider
	now         func() time.Time
	log         *slog.Logger
	ttl         time.Duration
	failTTL     time.Duration
	wait        time.Duration
	callTimeout time.Duration

	mu       sync.Mutex
	view     *builtinTrustView
	expires  time.Time
	have     bool
	inflight chan struct{} // closed when the running refresh finishes
	failing  bool          // last refresh failed (logged once per change)
}

func newBuiltinTrustCache(p BuiltinTrustProvider, now func() time.Time, log *slog.Logger) *builtinTrustCache {
	return &builtinTrustCache{
		provider:    p,
		now:         now,
		log:         log,
		ttl:         builtinTrustTTL,
		failTTL:     builtinTrustFailTTL,
		wait:        builtinTrustPageWait,
		callTimeout: statusCallTimeout,
	}
}

// get returns the banner for a page render (nil: no banner).
func (c *builtinTrustCache) get(ctx context.Context) *builtinTrustView {
	c.mu.Lock()
	if c.have && c.now().Before(c.expires) {
		v := c.view
		c.mu.Unlock()
		return v
	}
	ch := c.inflight
	if ch == nil {
		ch = make(chan struct{})
		c.inflight = ch
		go c.refresh(ch)
	}
	c.mu.Unlock()

	t := time.NewTimer(c.wait)
	defer t.Stop()
	select {
	case <-ch:
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.have {
			return c.view // just fetched
		}
	case <-t.C:
	case <-ctx.Done():
	}
	return unavailableBuiltinTrust()
}

// refresh fetches the status once and stores it, then closes ch. An RPC
// failure is stored as the unreachable state; it is logged once per
// change of state, never shown raw.
func (c *builtinTrustCache) refresh(ch chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), c.callTimeout)
	st, err := c.provider.GetBuiltinTrustStatus(ctx, &pb.GetBuiltinTrustStatusRequest{})
	cancel()
	view, ttl := builtinTrustBanner(st), c.ttl
	if err != nil {
		view, ttl = unavailableBuiltinTrust(), c.failTTL
	}

	c.mu.Lock()
	switch {
	case err != nil && !c.failing:
		c.log.Error("builtin trust status", "error", err)
	case err == nil && c.failing:
		c.log.Info("builtin trust status reachable again")
	}
	c.failing = err != nil
	c.view, c.have, c.expires = view, true, c.now().Add(ttl)
	c.inflight = nil
	c.mu.Unlock()
	close(ch)
}
