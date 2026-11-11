// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevinventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// Network device ↔ asset link on the device detail page (ADR 0010 D4
// "Device as an asset", ND-18 part 2).
//
// The page shows the confirmed link, or, without one, the assets whose
// MAC appears in the switch's MAC table as suggestions with their source
// label, next to a choice of every switch or firewall asset. Rendering
// never writes: ipam.SuggestDeviceAssets is a pure function. A link is
// confirmed or removed only by a form POST from the page, which the
// security middleware accepts only with this server's Origin (the CSRF
// defence of every state change), by a web user with the admin role. Each
// change is written as an audit line with the user; a refused or failed
// request is not.

// netdevLinkFormMax bounds the confirm and remove form bodies.
const netdevLinkFormMax = 4 << 10

// netdevLinkAssetsMax caps the assets offered in the confirm choice.
const netdevLinkAssetsMax = 500

// NetDevLinkStore is the IPAM part the device ↔ asset link uses;
// *ipam.Store implements it. ConfirmDeviceLink and RemoveDeviceLink are
// the only writers and are called only from an admin's POST.
type NetDevLinkStore interface {
	// Assets lists the IPAM assets.
	Assets(ctx context.Context) ([]ipam.Asset, error)
	// DeviceLink returns the confirmed link of a device or ipam.ErrNotFound.
	DeviceLink(ctx context.Context, deviceID string) (ipam.DeviceLink, error)
	// ConfirmDeviceLink records an admin's confirmation.
	ConfirmDeviceLink(ctx context.Context, deviceID, assetID, actor string) (ipam.DeviceLink, error)
	// RemoveDeviceLink removes a device's link and returns it.
	RemoveDeviceLink(ctx context.Context, deviceID string) (ipam.DeviceLink, error)
}

// netdevAssetLinkView is the link section of the detail page.
type netdevAssetLinkView struct {
	// Unavailable: the link store failed; nothing else is shown.
	Unavailable bool
	// Linked is the confirmed link, nil when there is none.
	Linked *netdevLinkedAsset
	// Suggestions are the MAC matches (not linked, never auto-linked).
	Suggestions []netdevAssetSuggestionRow
	// Options are the switch and firewall assets the admin may choose.
	Options []netdevAssetOption
	// ConfirmURL and RemoveURL are the form actions.
	ConfirmURL, RemoveURL string
}

// netdevLinkedAsset is a confirmed link.
type netdevLinkedAsset struct {
	AssetID, AssetName, AssetKind, AssetURL string
	ConfirmedBy                             string
	ConfirmedAt                             time.Time
}

// netdevAssetSuggestionRow is one MAC match.
type netdevAssetSuggestionRow struct {
	AssetID, AssetName, AssetKind string
	KindMatches                   bool
	MAC, Port, EntryType, Source  string
	VLAN                          uint16
	Self                          bool
}

// netdevAssetOption is one choice of the confirm form.
type netdevAssetOption struct {
	ID, Label string
}

// assetLink fills the link section of device d. A store error is logged
// and shown as unavailable.
func (p *NetDevPages) assetLink(ctx context.Context, d netdevinventory.Device) *netdevAssetLinkView {
	if p.o.Links == nil {
		return nil
	}
	base := "/netdev/" + url.PathEscape(d.DeviceID) + "/asset-link"
	v := &netdevAssetLinkView{ConfirmURL: base, RemoveURL: base + "/remove"}
	assets, err := p.o.Links.Assets(ctx)
	if err != nil {
		p.h.log.Error("network device page: list assets", "device", d.DeviceID, "error", err)
		return &netdevAssetLinkView{Unavailable: true}
	}
	l, err := p.o.Links.DeviceLink(ctx, d.DeviceID)
	switch {
	case err == nil:
		for _, a := range assets {
			if a.ID == l.AssetID {
				v.Linked = &netdevLinkedAsset{AssetID: a.ID, AssetName: a.Name, AssetKind: string(a.Kind),
					AssetURL: "/network/a/" + url.PathEscape(a.ID), ConfirmedBy: l.ConfirmedBy, ConfirmedAt: l.ConfirmedAt}
			}
		}
		if v.Linked != nil {
			return v
		}
		// The asset vanished between the two reads: show as unlinked.
	case !errors.Is(err, ipam.ErrNotFound):
		p.h.log.Error("network device page: read asset link", "device", d.DeviceID, "error", err)
		return &netdevAssetLinkView{Unavailable: true}
	}
	if d.Family == netdevcontract.FamilyCBS {
		macs, _, err := p.o.Store.MACEntries(ctx, d.DeviceID, 0, netdevcontract.MaxMACEntriesPerDevice)
		if err != nil && !errors.Is(err, netdevinventory.ErrDatasetNotFound) {
			p.h.log.Error("network device page: MAC table for suggestions", "device", d.DeviceID, "error", err)
		}
		macs = macs[:min(len(macs), netdevcontract.MaxMACEntriesPerDevice)]
		for _, s := range ipam.SuggestDeviceAssets(assets, macs) {
			v.Suggestions = append(v.Suggestions, netdevAssetSuggestionRow{
				AssetID: s.AssetID, AssetName: s.AssetName, AssetKind: string(s.AssetKind), KindMatches: s.KindMatches,
				MAC: s.MAC, Port: netdevText(s.Port), EntryType: netdevText(string(s.EntryType)), Source: s.Source,
				VLAN: s.VLAN, Self: s.SelfEntry,
			})
		}
	}
	for _, a := range assets {
		if len(v.Options) >= netdevLinkAssetsMax {
			break
		}
		if a.Kind == ipam.KindSwitch || a.Kind == ipam.KindFirewall {
			v.Options = append(v.Options, netdevAssetOption{ID: a.ID, Label: a.Name + " (" + a.ID + ", " + string(a.Kind) + ")"})
		}
	}
	return v
}

// linkRequest runs the checks both link POSTs share: a link store, the
// admin role, a valid device ID and a bounded, parsed form. It returns
// the device ID and the web user, or false when it already answered.
func (p *NetDevPages) linkRequest(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return "", "", false
	}
	if p.o.Links == nil {
		http.NotFound(w, r)
		return "", "", false
	}
	if !p.authorize(w, r) {
		return "", "", false
	}
	id := r.PathValue("id")
	if !netdevcontract.ValidDeviceID(id) {
		http.NotFound(w, r)
		return "", "", false
	}
	r.Body = http.MaxBytesReader(w, r.Body, netdevLinkFormMax)
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return "", "", false
		}
		http.Error(w, "bad request: invalid form", http.StatusBadRequest)
		return "", "", false
	}
	s, _ := auth.SessionFrom(r.Context()) // authorize checked it
	return id, s.UserName, true
}

// linkError answers a failed link change; internal errors are logged and
// never shown.
func (p *NetDevPages) linkError(w http.ResponseWriter, op, id string, err error) {
	var ve *ipam.ValidationError
	switch {
	case errors.As(err, &ve):
		http.Error(w, "bad request: "+ve.Reason, http.StatusBadRequest)
	case errors.Is(err, ipam.ErrDeviceUnknown):
		http.Error(w, "network device not found", http.StatusNotFound)
	case errors.Is(err, ipam.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, ipam.ErrDeviceLinked):
		http.Error(w, "conflict: the device is already linked to an asset; remove that link first", http.StatusConflict)
	case errors.Is(err, ipam.ErrAssetLinked):
		http.Error(w, "conflict: the asset is already linked to another network device", http.StatusConflict)
	default:
		p.h.log.Error("network device asset link: "+op, "device", id, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// handleLinkConfirm serves POST /netdev/{id}/asset-link: the admin
// confirms that the device is the asset named by the form field "asset".
func (p *NetDevPages) handleLinkConfirm(w http.ResponseWriter, r *http.Request) {
	id, user, ok := p.linkRequest(w, r)
	if !ok {
		return
	}
	vs := r.PostForm["asset"]
	if len(vs) != 1 || vs[0] == "" {
		http.Error(w, "bad request: choose exactly one asset", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), netdevCallTimeout)
	defer cancel()
	if _, err := p.o.Store.GetDevice(ctx, id); err != nil {
		if errors.Is(err, netdevinventory.ErrDeviceNotFound) {
			http.NotFound(w, r)
			return
		}
		p.linkError(w, "get device", id, err)
		return
	}
	l, err := p.o.Links.ConfirmDeviceLink(ctx, id, vs[0], user)
	if err != nil {
		p.linkError(w, "confirm", id, err)
		return
	}
	p.h.log.Info("audit", "kind", "netdev_asset_link_confirmed", "device", l.DeviceID, "asset", l.AssetID, "user", user)
	http.Redirect(w, r, "/netdev/"+url.PathEscape(id)+"#asset-link", http.StatusSeeOther)
}

// handleLinkRemove serves POST /netdev/{id}/asset-link/remove.
func (p *NetDevPages) handleLinkRemove(w http.ResponseWriter, r *http.Request) {
	id, user, ok := p.linkRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), netdevCallTimeout)
	defer cancel()
	l, err := p.o.Links.RemoveDeviceLink(ctx, id)
	if err != nil {
		p.linkError(w, "remove", id, err)
		return
	}
	p.h.log.Info("audit", "kind", "netdev_asset_link_removed", "device", l.DeviceID, "asset", l.AssetID, "user", user)
	http.Redirect(w, r, "/netdev/"+url.PathEscape(id)+"#asset-link", http.StatusSeeOther)
}
