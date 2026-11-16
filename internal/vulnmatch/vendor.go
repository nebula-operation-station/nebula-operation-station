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
//
// Every advisory is judged on its own: an advisory that names the device's
// model but neither lists its firmware nor is silent about it is a gap,
// whatever other advisories say (ADR 0011 D4).
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
	model := newDeviceModel(s.Device.Model)
	var exactSeen, firmwareSeen bool
	for _, d := range m.vendorDocs(feed) {
		for _, v := range d.adv.Vulnerabilities {
			hit := m.deviceVuln(s, feed, d, v, model)
			exactSeen = exactSeen || hit.exact
			firmwareSeen = firmwareSeen || hit.firmware
		}
	}
	// A finding needs a unique hit on the model and on the firmware's train
	// (ADR 0011 D4). Without a hit on both, coverage is unknown, never clean.
	switch {
	case !exactSeen:
		m.gap(s, s.Device.Model, "", GapDeviceModelUnknown)
	case !firmwareSeen:
		m.gap(s, s.Device.Model, "", GapDeviceVersionUnknown)
	}
}

// deviceHit says which products of one vulnerability name the device: the
// exact model (exact), only its family (family), and an exact product
// version equal to its firmware (firmware).
type deviceHit struct {
	exact, family, firmware bool
}

// deviceModel is a device's model. exact is the normalised model string: a
// product is the exact model only when its normalised model string is equal
// (case and whitespace only). family is the model's family before the first
// "-" when the family has a letter and a digit ("CBS350" for "CBS350-24P-4G");
// it names sibling SKUs in either direction and only ever leads to a coverage
// gap, never to a finding. A bare word such as "PA" is no family: it would
// name every Palo Alto product.
type deviceModel struct {
	exact  string
	family []string
}

// newDeviceModel normalises a device model once per device subject.
func newDeviceModel(model string) deviceModel {
	d := deviceModel{exact: normalizeModel(model)}
	if i := strings.IndexByte(model, '-'); i > 0 {
		fam := model[:i]
		if strings.IndexFunc(fam, unicode.IsDigit) >= 0 && strings.IndexFunc(fam, unicode.IsLetter) >= 0 {
			d.family = modelTokens(fam)
		}
	}
	return d
}

// productModel is a CSAF product's model string with its family tokens,
// built once per product. Only the product's model field (product_name) is
// used: the full name carries version and vendor words, whose digits must
// never form a device model.
type productModel struct {
	key    string
	tokens []string
}

// newProductModel indexes the model field of a CSAF product.
func newProductModel(product string) productModel {
	return productModel{key: normalizeModel(product), tokens: modelTokens(product)}
}

// modelNaming says how a product names a device's model.
type modelNaming int

const (
	// namesNothing: the product names neither the model nor its family.
	namesNothing modelNaming = iota
	// namesFamily: the product names only the family, a sibling SKU.
	namesFamily
	// namesExact: the product's model string equals the device's model.
	namesExact
)

// naming reports how a product names the model. Equality of the normalised
// model strings is the only exact hit; the family key is a hint at most.
func (d deviceModel) naming(p productModel) modelNaming {
	switch {
	case d.exact != "" && p.key == d.exact:
		return namesExact
	case containsRun(p.tokens, d.family):
		return namesFamily
	}
	return namesNothing
}

// normalizeModel lower-cases s and drops all white space: the only
// normalisation two model strings are compared under.
func normalizeModel(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// modelTokens splits s into lower-case runs of letters and digits.
func modelTokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// containsRun reports whether run occurs in tokens as whole tokens, so
// "CBS35" never names "CBS350". An empty run names nothing.
func containsRun(tokens, run []string) bool {
	for i := 0; len(run) > 0 && i+len(run) <= len(tokens); i++ {
		if slices.Equal(tokens[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

// indexedProduct is a CSAF product with its model string, built once.
type indexedProduct struct {
	p     vulnfeed.CSAFProduct
	model productModel
}

// indexedAdvisory is a CSAF advisory with its products by ID.
type indexedAdvisory struct {
	adv  *vulnfeed.CSAFAdvisory
	byID map[string]indexedProduct
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
		byID := make(map[string]indexedProduct, len(adv.Products))
		for _, p := range adv.Products {
			byID[p.ProductID] = indexedProduct{p: p, model: newProductModel(p.Product)}
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

// deviceVuln judges one vulnerability of one advisory for the device. The
// advisory's own products decide: a model hit without a firmware hit here is
// a gap for this advisory, whatever other advisories list.
func (m *matcher) deviceVuln(s Subject, feed string, d indexedAdvisory, v vulnfeed.CSAFVulnerability, model deviceModel) deviceHit {
	fw := s.Device.Firmware
	var affected []vulnfeed.CSAFProduct
	var isFixed, isNotAffected, rangeSeen bool
	var hit deviceHit
	scan := func(ids []string, f func(p vulnfeed.CSAFProduct)) {
		for _, id := range ids {
			ip, ok := d.byID[id]
			if !ok || ip.p.Ecosystem != s.Ecosystem {
				continue
			}
			// Only the exact model is a hit (ADR 0011 D4). A sibling SKU of
			// the family never decides a finding or a clean status.
			switch model.naming(ip.model) {
			case namesFamily:
				hit.family = true
				continue
			case namesExact:
				hit.exact = true
			default:
				continue
			}
			p := ip.p
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
	ids := []string{v.CVE, d.adv.TrackingID}
	firstID := v.CVE
	if firstID == "" {
		firstID = d.adv.TrackingID
	}
	switch {
	case hit.family && !hit.exact:
		m.gap(s, s.Device.Model, canonicalID(firstID), GapDeviceModelUnknown)
	case hit.exact && !hit.firmware:
		m.gap(s, s.Device.Model, canonicalID(firstID), GapDeviceVersionUnknown)
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
		m.emitDevice(s, ids, vendorFix(d.byID, v, s.Ecosystem, affected, &m.feedCut), feed)
	case rangeSeen:
		m.gap(s, s.Device.Model, canonicalID(firstID), GapVendorRange)
	}
	return hit
}

// vendorFix returns the fixed release of the affected firmware's train:
// the single distinct exact fixed version of the same ecosystem and train.
// None, several or an over-bound version give no_fix_yet; the matcher
// never picks among fixed releases by ordering them.
func vendorFix(byID map[string]indexedProduct, v vulnfeed.CSAFVulnerability, eco string, affected []vulnfeed.CSAFProduct, cut *int) vulnfinding.Fix {
	trains := map[string]bool{}
	for _, p := range affected {
		if p.Train != "" {
			trains[p.Train] = true
		}
	}
	versions := map[string]bool{}
	for _, id := range v.Fixed {
		ip, ok := byID[id]
		if ok && ip.p.Ecosystem == eco && ip.p.Version != "" && trains[ip.p.Train] {
			versions[ip.p.Version] = true
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
