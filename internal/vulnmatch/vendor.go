// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"cmp"
	"slices"
	"strings"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfeed"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// vendorFeed returns the signed CSAF feed of a device ecosystem.
func vendorFeed(eco string) (string, bool) {
	switch {
	case ciscoEcoRe.MatchString(eco):
		return FeedCiscoCSAF, true
	case eco == "vendor:paloalto:panos":
		return FeedPaloAltoCSAF, true
	}
	return "", false
}

// device matches a device's firmware against the CSAF products of its
// ecosystem (vendor_advisory, D2). internal/vulnver has no vendor version
// scheme, so the matcher never orders firmware versions: only an exact
// product_version equal to the firmware decides. A firmware that only a
// version range could cover, or that appears in contradicting status
// lists, is a coverage gap, never fixed or not affected.
func (m *matcher) device(s Subject) {
	feed, ok := vendorFeed(s.Ecosystem)
	if !ok {
		m.gap(s, "", "", GapEcosystemUnknown)
		return
	}
	if s.Device == nil || s.Device.Model == "" {
		// A device without a model is not identified; it is never clean.
		m.gap(s, "", "", GapInventoryIncomplete)
		return
	}
	if s.Device.Firmware == "" || !versionRe.MatchString(s.Device.Firmware) {
		m.gap(s, "", "", GapVersionUnknown)
		return
	}
	if _, ok := m.db.feeds[feed]; !ok {
		// A covered ecosystem without its feed snapshot is unknown, never
		// clean.
		m.gap(s, "", "", GapFeedMissing)
		return
	}
	keys := modelKeys(s.Device.Model)
	var modelSeen, firmwareSeen bool
	for _, d := range m.vendorDocs(feed) {
		for _, v := range d.adv.Vulnerabilities {
			hit := m.deviceVuln(s, feed, d.adv, d.byID, v, keys)
			modelSeen = modelSeen || hit.model
			firmwareSeen = firmwareSeen || hit.firmware
		}
	}
	// A finding needs a unique hit on the model and on the firmware's train
	// (ADR 0011 D4). Without a hit on both, coverage is unknown, never clean.
	switch {
	case !modelSeen:
		m.gap(s, s.Device.Model, "", GapDeviceModelUnknown)
	case !firmwareSeen:
		m.gap(s, s.Device.Model, "", GapDeviceVersionUnknown)
	}
}

// deviceHit says which parts of one vulnerability's product lists match the
// device: a product of its model (model) and an exact product version equal
// to its firmware (firmware).
type deviceHit struct {
	model, firmware bool
}

// modelKeys returns the token sequences by which a product names the
// device's model: the whole model, and its family before the first "-" when
// the family has a letter and a digit ("CBS350" for "CBS350-24P-4G"). A bare
// word such as "PA" is no key: it would name every Palo Alto product.
func modelKeys(model string) [][]string {
	keys := [][]string{modelTokens(model)}
	if i := strings.IndexByte(model, '-'); i > 0 {
		fam := model[:i]
		if strings.IndexFunc(fam, unicode.IsDigit) >= 0 && strings.IndexFunc(fam, unicode.IsLetter) >= 0 {
			keys = append(keys, modelTokens(fam))
		}
	}
	return keys
}

// modelTokens splits s into lower-case runs of letters and digits.
func modelTokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// namesModel reports whether text holds one of the model keys as whole
// tokens, so "CBS35" never names "CBS350".
func namesModel(text string, keys [][]string) bool {
	tokens := modelTokens(text)
	for _, k := range keys {
		for i := 0; len(k) > 0 && i+len(k) <= len(tokens); i++ {
			if slices.Equal(tokens[i:i+len(k)], k) {
				return true
			}
		}
	}
	return false
}

// indexedAdvisory is a CSAF advisory with its products by ID.
type indexedAdvisory struct {
	adv  *vulnfeed.CSAFAdvisory
	byID map[string]vulnfeed.CSAFProduct
}

// vendorDocs returns the advisories of feed in (tracking ID, version)
// order with their product maps. It builds them once per Match and feed,
// so the work does not grow with the number of device subjects.
func (m *matcher) vendorDocs(feed string) []indexedAdvisory {
	if docs, ok := m.vendor[feed]; ok {
		return docs
	}
	var docs []indexedAdvisory
	for i := range m.db.csaf {
		if m.db.csaf[i].feed != feed {
			continue
		}
		adv := &m.db.csaf[i].adv
		byID := make(map[string]vulnfeed.CSAFProduct, len(adv.Products))
		for _, p := range adv.Products {
			byID[p.ProductID] = p
		}
		docs = append(docs, indexedAdvisory{adv: adv, byID: byID})
	}
	slices.SortStableFunc(docs, func(a, b indexedAdvisory) int {
		return cmp.Or(strings.Compare(a.adv.TrackingID, b.adv.TrackingID), strings.Compare(a.adv.Version, b.adv.Version))
	})
	if m.vendor == nil {
		m.vendor = map[string][]indexedAdvisory{}
	}
	m.vendor[feed] = docs
	return docs
}

func (m *matcher) deviceVuln(s Subject, feed string, adv *vulnfeed.CSAFAdvisory, byID map[string]vulnfeed.CSAFProduct, v vulnfeed.CSAFVulnerability, keys [][]string) deviceHit {
	fw := s.Device.Firmware
	var affected []vulnfeed.CSAFProduct
	var isFixed, isNotAffected, rangeSeen bool
	var hit deviceHit
	scan := func(ids []string, f func(p vulnfeed.CSAFProduct)) {
		for _, id := range ids {
			p, ok := byID[id]
			// A product counts only when it is the device's ecosystem and
			// names its model (ADR 0011 D4): firmware of another model is no
			// hit.
			if !ok || p.Ecosystem != s.Ecosystem || !namesModel(p.Name+" "+p.Product, keys) {
				continue
			}
			hit.model = true
			if p.Version == "" {
				if p.VersionRange != "" {
					rangeSeen = true
				}
				continue
			}
			if p.Version == fw {
				hit.firmware = true
				f(p)
			}
		}
	}
	scan(v.Affected, func(p vulnfeed.CSAFProduct) { affected = append(affected, p) })
	scan(v.Fixed, func(vulnfeed.CSAFProduct) { isFixed = true })
	scan(v.NotAffected, func(vulnfeed.CSAFProduct) { isNotAffected = true })
	ids := []string{v.CVE, adv.TrackingID}
	firstID := v.CVE
	if firstID == "" {
		firstID = adv.TrackingID
	}
	n := 0
	for _, b := range []bool{len(affected) > 0, isFixed, isNotAffected} {
		if b {
			n++
		}
	}
	switch {
	case n > 1:
		m.gap(s, s.Device.Model, canonicalID(firstID), GapVendorRange)
	case isFixed:
		// The firmware is a fixed release: no record.
	case isNotAffected:
		m.emitDevice(s, ids, vulnfinding.Fix{State: vulnfinding.FixNotAffected}, feed)
	case len(affected) > 0:
		m.emitDevice(s, ids, vendorFix(adv, byID, v, s.Ecosystem, affected, &m.feedCut), feed)
	case rangeSeen:
		m.gap(s, s.Device.Model, canonicalID(firstID), GapVendorRange)
	}
	return hit
}

// vendorFix returns the fixed release of the affected firmware's train:
// the single distinct exact fixed version of the same ecosystem and train.
// None, several or an over-bound version give no_fix_yet; the matcher
// never picks among fixed releases by ordering them.
func vendorFix(adv *vulnfeed.CSAFAdvisory, byID map[string]vulnfeed.CSAFProduct, v vulnfeed.CSAFVulnerability, eco string, affected []vulnfeed.CSAFProduct, cut *int) vulnfinding.Fix {
	trains := map[string]bool{}
	for _, p := range affected {
		if p.Train != "" {
			trains[p.Train] = true
		}
	}
	versions := map[string]bool{}
	for _, id := range v.Fixed {
		p, ok := byID[id]
		if ok && p.Ecosystem == eco && p.Version != "" && trains[p.Train] {
			versions[p.Version] = true
		}
	}
	if len(versions) != 1 {
		return vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
	}
	for ver := range versions {
		if len(ver) > MaxFixedVersionLen || !versionRe.MatchString(ver) {
			*cut++
			return vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
		}
		return vulnfinding.Fix{State: vulnfinding.FixFixed, Version: ver}
	}
	return vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
}

func (m *matcher) emitDevice(s Subject, ids []string, fix vulnfinding.Fix, feed string) {
	var valid []string
	for _, id := range ids {
		if id != "" {
			valid = append(valid, id)
		}
	}
	primary, aliases, cut, ok := chooseIDs(valid, s.Ecosystem, s.Device.Model, m.opts.Anchors)
	m.feedCut += cut
	if !ok {
		m.gap(s, s.Device.Model, "", GapNoValidID)
		return
	}
	rec := vulnfinding.Record{
		SubjectKind: s.Kind,
		SubjectRef:  s.Ref,
		Ecosystem:   s.Ecosystem,
		Component:   vulnfinding.Component{Model: s.Device.Model, Firmware: s.Device.Firmware},
		Vuln:        vulnfinding.Vuln{ID: primary, Aliases: aliases},
		Fix:         fix,
		MatchBasis:  vulnfinding.MatchVendorAdvisory,
	}
	m.finish(s, rec, feed, nil)
}
