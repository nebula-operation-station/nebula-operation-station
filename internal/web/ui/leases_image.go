// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
)

// Image read leases (ADR 0011): the "Image packages" section of the lease
// form. The browser offers the (container, pinned image) pairs that recent
// docker.inspect results of one host name; POST /leases/preview with
// scope=image proposes exactly that pair for image.packages and
// docker.inspect and redirects to the same proposal page as every other
// lease. Nothing is approved before the security key approves the digest.
// The section is a separate form, so the general action list is unchanged.

// ScopeImage is the scope value of an image read lease on POST /leases/preview.
const ScopeImage = "image"

const (
	// maxImageLeaseChoices bounds the (container, image) pairs the form offers.
	maxImageLeaseChoices = 200
	// maxImageLeasePairLen bounds the posted pair ("container|image").
	maxImageLeasePairLen = 600
	// imageInspectActionID and imagePackagesActionID are the two actions of
	// an image lease.
	imageInspectActionID  = "docker.inspect"
	imagePackagesActionID = "image.packages"
)

// imageLeaseHost is one inventory host of the image section.
type imageLeaseHost struct {
	ID       string
	Selected bool
}

// imageLeaseChoice is one (container, image) pair of the image section.
type imageLeaseChoice struct {
	Container, Image string
	// Value is "container|image", the form value of the pair.
	Value string
}

// imageLeaseForm is the image section of the lease form.
type imageLeaseForm struct {
	Hosts []imageLeaseHost
	// Host is the chosen inventory host; empty when none is chosen.
	Host string
	// Pairs are the offered pairs of Host, at most maxImageLeaseChoices.
	Pairs []imageLeaseChoice
	// Unavailable is set when the pairs of Host could not be read.
	Unavailable bool
}

// imageParamRow is one plain-text parameter of an image lease proposal.
type imageParamRow struct {
	Action, Name, Value string
}

// imageLeaseOf returns the container and image of an image lease's
// parameters, or ok=false when the parameters name no such pair.
func imageLeaseOf(params map[string]map[string]string) (container, image string, ok bool) {
	c, okC := params[imageInspectActionID]["container"]
	i, okI := params[imagePackagesActionID]["image"]
	if !okC || !okI {
		return "", "", false
	}
	return c, i, true
}

// imageParamRows renders the plain-text parameters of a proposal, sorted by
// action and name.
func imageParamRows(params map[string]map[string]string) []imageParamRow {
	var out []imageParamRow
	actionIDs := make([]string, 0, len(params))
	for a := range params {
		actionIDs = append(actionIDs, a)
	}
	slices.Sort(actionIDs)
	for _, a := range actionIDs {
		names := make([]string, 0, len(params[a]))
		for n := range params[a] {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			out = append(out, imageParamRow{Action: a, Name: n, Value: params[a][n]})
		}
	}
	return out
}

// imageIntervalText is the minimum interval of an image lease in hours
// ("24 h"); other intervals are shown in full.
func imageIntervalText(d time.Duration) string {
	if d > 0 && d%time.Hour == 0 {
		return fmt.Sprintf("%d h", int(d/time.Hour))
	}
	return d.String()
}

// imageLeaseForm fills the image section of the lease form. The pairs are
// read only for a chosen inventory host, so a query cannot make the page read
// the lease database for an arbitrary host name.
func (h *Handler) imageLeaseForm(ctx context.Context, d *leaseNewData, q url.Values) {
	f := &imageLeaseForm{}
	choice := q.Get("image_host")
	var known bool
	if h.hosts != nil {
		hosts, err := h.hosts(ctx)
		if err != nil {
			h.log.Error("list hosts", "error", err)
		}
		for _, x := range hosts {
			f.Hosts = append(f.Hosts, imageLeaseHost{ID: x.ID, Selected: x.ID == choice})
			known = known || x.ID == choice
		}
	}
	d.ImageForm = f
	if !known || !canonical.ValidHostID(choice) {
		return
	}
	f.Host = choice
	opts, err := h.leases.ImageLeaseOptions(ctx, choice)
	if err != nil {
		h.log.Error("list image lease options", "error", err)
		f.Unavailable = true
		return
	}
	for i, o := range opts {
		if i == maxImageLeaseChoices {
			break
		}
		f.Pairs = append(f.Pairs, imageLeaseChoice{Container: o.Container, Image: o.Image,
			Value: o.Container + "|" + o.Image})
	}
}

// checkImageLeaseForm turns the posted image form into a request, or returns
// the reason it is refused. The container and image must match the action
// parameter patterns; the service then checks that the host offers the pair.
func checkImageLeaseForm(form url.Values) (executions.ImageReadGrantRequest, string) {
	days, err := strconv.Atoi(form.Get("days"))
	if err != nil || (days != executions.ReadGrantShortDays && days != executions.ReadGrantLongDays) {
		return executions.ImageReadGrantRequest{}, fmt.Sprintf("a read lease lasts %d or %d days", executions.ReadGrantShortDays, executions.ReadGrantLongDays)
	}
	host := form.Get("host")
	if !canonical.ValidHostID(host) {
		return executions.ImageReadGrantRequest{}, "the host is unknown"
	}
	pair := form.Get("pair")
	container, image, ok := strings.Cut(pair, "|")
	if !ok || len(pair) > maxImageLeasePairLen {
		return executions.ImageReadGrantRequest{}, "choose one container and image"
	}
	inspect, okI := actions.Lookup(imageInspectActionID)
	if !okI || inspect.ValidParams(map[string]string{"container": container}) != nil {
		return executions.ImageReadGrantRequest{}, "the container name is not valid"
	}
	pkgs, okP := actions.Lookup(imagePackagesActionID)
	if !okP || pkgs.ValidParams(map[string]string{"image": image}) != nil {
		return executions.ImageReadGrantRequest{}, "the image reference is not a digest-pinned image"
	}
	return executions.ImageReadGrantRequest{HostID: host, Container: container, Image: image, Days: days}, ""
}

// handleImageLeasePreview proposes an image lease (scope=image of POST
// /leases/preview; the form is already parsed) and redirects to its proposal
// page. Errors are plain text for formpost.js.
func (h *Handler) handleImageLeasePreview(w http.ResponseWriter, r *http.Request) {
	in, reason := checkImageLeaseForm(r.PostForm)
	if reason != "" {
		http.Error(w, reason, http.StatusBadRequest)
		return
	}
	user := webUser(r)
	now := h.clockNow()
	if !h.leaseProposals.allow(user, now) {
		w.Header().Set("Retry-After", strconv.Itoa(int(leasePreviewInterval/time.Second)))
		http.Error(w, "at most one read lease preview every 10 seconds: wait and try again", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	v, err := h.leases.ProposeImageReadGrant(ctx, user, in)
	if err != nil {
		var ie *executions.ReadGrantInputError
		switch {
		case errors.As(err, &ie):
			http.Error(w, ie.Reason, http.StatusBadRequest)
		case errors.Is(err, executions.ErrReadGrantProposeFailed), errors.Is(err, executions.ErrReadGrantCredentials),
			errors.Is(err, executions.ErrReadGrantProposalMismatch), errors.Is(err, executions.ErrReadGrantProposeUnsupported):
			h.log.Error("propose image read grant", "error", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
		default:
			h.log.Error("propose image read grant", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}
	if !leaseDigestRe.MatchString(v.Digest) {
		http.Error(w, "the executor returned no usable digest", http.StatusBadGateway)
		return
	}
	h.leaseProposals.put(user, v, now)
	http.Redirect(w, r, "/leases/proposals/"+v.Digest, http.StatusSeeOther)
}
