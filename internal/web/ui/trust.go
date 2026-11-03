// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
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
	// Affected lists the built-in versions that are not trusted yet.
	Affected []builtinTrustEntryView
	// Detail is the closing guidance sentence.
	Detail string
}

// builtinTrustEntryView is one affected built-in (untrusted text only).
type builtinTrustEntryView struct {
	// Name is the module name from the executor.
	Name string
	// Version is the version in the local release.
	Version string
	// Trusted is the trusted version when a different one is trusted;
	// empty when none is.
	Trusted string
}

// builtinTrustBanner maps the executor's built-in trust status to the
// layout banner (ADR 0007 E17). A fully trusted status yields nil (no
// banner). Untrusted names the affected versions, the local CLI command
// and the lease-replacement rule. Unavailable is a distinct
// "unreachable" state: it is not a trust verdict and names no versions.
func builtinTrustBanner(st *pb.GetBuiltinTrustStatusResponse) *builtinTrustView {
	switch st.GetState() {
	case pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNTRUSTED:
		v := &builtinTrustView{
			Kind:     "untrusted",
			Headline: "Built-ins are untrusted: every operation using them needs UV until you trust them.",
			Command:  "nebula artifact trust-builtins",
			Detail:   "Trusting new built-in versions does not amend existing read leases: approve a replacement grant for those exact versions.",
		}
		for _, m := range st.GetModules() {
			if m.GetReleaseVersion() == "" {
				continue // not part of the local release
			}
			if m.GetTrustedVersion() == m.GetReleaseVersion() && m.GetTrustedSha256() == m.GetReleaseSha256() {
				continue // this exact version is trusted
			}
			v.Affected = append(v.Affected, builtinTrustEntryView{
				Name:    m.GetName(),
				Version: m.GetReleaseVersion(),
				Trusted: m.GetTrustedVersion(),
			})
		}
		return v
	case pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE:
		return &builtinTrustView{
			Kind:     "unavailable",
			Headline: "Built-in trust status is unreachable: the executor could not read its local release bundle or trust store.",
			Detail:   "This is not a trust verdict: whether the built-ins are trusted is unknown. Check the executor on its host.",
		}
	default:
		return nil // trusted (or unspecified): no banner
	}
}

// builtinTrustStatus fetches the banner state for a page render. An RPC
// failure is the same "unreachable" state as UNAVAILABLE: it is logged,
// never shown raw, and never conflated with "untrusted".
func (h *Handler) builtinTrustStatus(ctx context.Context) *builtinTrustView {
	ctx, cancel := context.WithTimeout(ctx, statusCallTimeout)
	defer cancel()
	st, err := h.builtinTrust.GetBuiltinTrustStatus(ctx, &pb.GetBuiltinTrustStatusRequest{})
	if err != nil {
		h.log.Error("builtin trust status", "error", err)
		return builtinTrustBanner(&pb.GetBuiltinTrustStatusResponse{State: pb.BuiltinTrustState_BUILTIN_TRUST_STATE_UNAVAILABLE})
	}
	return builtinTrustBanner(st)
}
