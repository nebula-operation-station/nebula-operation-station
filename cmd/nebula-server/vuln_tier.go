// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// The D7 tier of a finding with the host criticality (ADR 0011 D7, G23).
// The criticality comes from the inventory (spec 12): a host takes its own,
// an image takes the criticality of the host it names, and a device, an
// unknown host or a host without a criticality counts as unset (0.85, the
// ADR default). A read error never lowers a tier (see Tier).

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnprio"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// vulnCriticalityTTL is how long one read of the host criticalities is
// reused. The tier is computed for every row of a page and for every stored
// finding, so the inventory is read once per TTL, not once per finding; a
// change in the inventory shows after at most this long.
const vulnCriticalityTTL = time.Minute

// vulnCriticalityReadTimeout bounds one read of the inventory for the tier.
const vulnCriticalityReadTimeout = 5 * time.Second

// vulnTierer computes the D7 tier of a finding with the criticality of its
// subject's host. Safe for concurrent use.
type vulnTierer struct {
	hosts vulnHostLister // nil: no inventory, every subject is unset
	now   func() time.Time
	log   *slog.Logger

	mu      sync.Mutex
	loaded  bool      // a read has been attempted
	fetched time.Time // when the last read was attempted
	failed  bool      // the last read failed; crit holds the read before it
	crit    map[string]inventory.Criticality
}

// newVulnTierer returns a tierer reading the criticalities from hosts. A nil
// hosts gives every subject the unset criticality. now defaults to time.Now.
func newVulnTierer(hosts vulnHostLister, now func() time.Time, log *slog.Logger) *vulnTierer {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &vulnTierer{hosts: hosts, now: now, log: log}
}

// Tier is the D7 tier of record r on subject s. It is the vulnstore.TierFunc
// of the findings store and of the pages.
//
// A failed read keeps the unset tier and the criticality of the read before
// it, and the higher of the two tiers counts: a read error can not lower a
// tier below today's (unset) tier, nor below the one the last read gave.
func (t *vulnTierer) Tier(s vulnstore.Subject, r vulnfinding.Record) vulnstore.Tier {
	crit, failed := t.view()
	var known inventory.Criticality // unset
	if s.Kind == vulnfinding.SubjectHost || s.Kind == vulnfinding.SubjectImage {
		known = crit[s.ID]
	}
	if !failed {
		return vulnTierWith(r, known)
	}
	return max(vulnTierWith(r, ""), vulnTierWith(r, known))
}

// view returns the criticalities by host ID and whether the last read
// failed, reading the inventory again once vulnCriticalityTTL has passed.
func (t *vulnTierer) view() (map[string]inventory.Criticality, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if now := t.now(); t.hosts != nil && (!t.loaded || now.Sub(t.fetched) >= vulnCriticalityTTL) {
		t.refresh(now)
	}
	return t.crit, t.failed
}

// refresh reads the hosts. The caller holds t.mu.
func (t *vulnTierer) refresh(now time.Time) {
	t.loaded = true
	t.fetched = now
	ctx, cancel := context.WithTimeout(context.Background(), vulnCriticalityReadTimeout)
	defer cancel()
	hs, err := t.hosts.List(ctx)
	if err != nil {
		t.failed = true
		t.log.Error("vulnerability tier: host criticality read failed, the unset tier or the last read counts", "error", err)
		return
	}
	crit := make(map[string]inventory.Criticality, len(hs))
	for _, h := range hs {
		crit[h.ID] = knownCriticality(h.Criticality)
	}
	t.crit = crit
	t.failed = false
}

// knownCriticality returns c when it is one of the four spec 12 classes and
// the unset criticality ("") otherwise.
func knownCriticality(c inventory.Criticality) inventory.Criticality {
	switch c {
	case inventory.CriticalityLow, inventory.CriticalityMedium, inventory.CriticalityHigh, inventory.CriticalityCritical:
		return c
	}
	return ""
}

// vulnTierWith is vu-prio-v1 (vulnprio.Compute) for record r with host
// criticality crit ("" is unset). Exposure stays unknown (0.7, never
// "internal"): the entry exposure of internal/attackpath/jewels has no rule
// data while the ADR 0010 firewall data is missing, so nothing is derived
// here. Invalid scores give TierUnknown.
func vulnTierWith(r vulnfinding.Record, crit inventory.Criticality) vulnstore.Tier {
	res, err := vulnprio.Compute(vulnprio.Input{Scores: r.Scores, Criticality: crit})
	if err != nil {
		return vulnstore.TierUnknown
	}
	switch res.Tier {
	case vulnprio.TierLow:
		return vulnstore.TierLow
	case vulnprio.TierMedium:
		return vulnstore.TierMedium
	case vulnprio.TierHigh:
		return vulnstore.TierHigh
	case vulnprio.TierCritical:
		return vulnstore.TierCritical
	}
	return vulnstore.TierUnknown
}
