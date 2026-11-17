// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnmatch

import (
	"cmp"
	"regexp"
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
// ecosystem (vendor_advisory, D2). The OS (ecosystem) and the models come
// from the structured product tree (vulnfeed.CSAFProduct.OS and Models): a
// product applies when it names no model or the device's exact model; a
// product naming only complete SKUs of a known vendor scheme, distinct from
// the device's complete SKU and not a prefix of it, does not affect the
// device; any other model scope (series or family names, series designations
// written like a SKU, CPE spellings, shorter or longer SKUs, unknown schemes,
// unreadable scopes) is a coverage gap of that vulnerability. internal/vulnver has no
// vendor version scheme, so the matcher never orders firmware versions: only an exact
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
	var appliesSeen, firmwareSeen bool
	for _, d := range m.vendorDocs(feed) {
		for _, v := range d.adv.Vulnerabilities {
			hit := m.deviceVuln(s, feed, d, v, model)
			appliesSeen = appliesSeen || hit.applies
			firmwareSeen = firmwareSeen || hit.firmware
		}
	}
	// A finding needs a product that applies to the device (its OS and
	// either no model or its exact model) and an exact hit on its firmware
	// (ADR 0011 D4). Without both, coverage is unknown, never clean: a
	// device whose model the feed only ever excludes is a model unknown to
	// the feed, not a clean device.
	switch {
	case !appliesSeen:
		m.gap(s, s.Device.Model, "", GapDeviceModelUnknown)
	case !firmwareSeen:
		m.gap(s, s.Device.Model, "", GapDeviceVersionUnknown)
	}
}

// deviceHit says which products of one vulnerability apply to the device:
// any product of its OS that names no model or its exact model (applies),
// one that names its exact model (exact), and an applying product whose
// exact version equals its firmware (firmware).
type deviceHit struct {
	applies, exact, firmware bool
}

// modelScope is how a CSAF product's model scope relates to a device.
type modelScope int

const (
	// scopeAll: the product names no model; it covers every device of its
	// OS.
	scopeAll modelScope = iota
	// scopeDevice: one of the product's models is the device's model.
	scopeDevice
	// scopeUnknown: the product's scope cannot be read exactly, or one of
	// its models is not provably another model (see differs): a series or
	// family name, a CPE or lower-case spelling, a shorter or longer SKU of
	// the device. Whether it is the device is unknown.
	scopeUnknown
	// scopeOther: every model of the product is an exact SKU distinct from
	// the device's exact SKU; it is not the device.
	scopeOther
)

// scope classifies a product's models against the device's model.
func (d deviceModel) scope(p indexedProduct) modelScope {
	unknown := false
	for _, pm := range p.models {
		if d.isExact(pm) {
			return scopeDevice
		}
		unknown = unknown || !d.differs(pm)
	}
	switch {
	case p.p.ModelsIncomplete || unknown:
		return scopeUnknown
	case len(p.models) == 0:
		return scopeAll
	}
	return scopeOther
}

// differs reports whether the product's model is provably not the device's
// model: both are complete SKUs of the same vendor scheme (see skuSchemeOf),
// they are not equal, and neither is a prefix of the other or a whole-word
// run of the other (a shorter or longer SKU, "CBS350-24P" and "CBS350-24P-4G",
// may name the same hardware). Anything else (series names, series
// designations written like a SKU such as "PA-400", CPE spellings, family
// names, unknown schemes) is never proof that a device is not affected.
func (d deviceModel) differs(p productModel) bool {
	if d.scheme == schemeNone || d.scheme != p.scheme || d.key == p.key {
		return false
	}
	if strings.HasPrefix(d.key, p.key) || strings.HasPrefix(p.key, d.key) {
		return false
	}
	return !wordRun(d.key, p.key) && !wordRun(p.key, d.key)
}

// MaxExactSKULen caps the length of a model string read as an exact SKU.
const MaxExactSKULen = 64

// exactSKURe is the shape of an exact hardware SKU as vendors print it:
// upper-case letters and digits in at least two '-'-separated parts
// ("C9300-24T", "CBS350-8T", "PA-440"). Lower case, white space, '_' and
// any other character mark a spelling (a CPE product, a series or family
// name) that is not read as an exact SKU.
var exactSKURe = regexp.MustCompile(`^[A-Z0-9]+(-[A-Z0-9]+)+$`)

// isExactSKU reports whether model is an exact SKU: the SKU shape with at
// least one digit, within MaxExactSKULen.
func isExactSKU(model string) bool {
	return len(model) <= MaxExactSKULen && exactSKURe.MatchString(model) && strings.ContainsAny(model, "0123456789")
}

// skuScheme names a vendor's complete-SKU scheme. Two models are compared
// as distinct only under the same scheme; a model under no known scheme is
// never proof of a different model.
type skuScheme int

const (
	// schemeNone: not a complete SKU of a known scheme.
	schemeNone skuScheme = iota
	// schemeCisco: a family of letters and digits, '-', a port count, then
	// one or more type letters, optionally followed by '-'-suffix words
	// ("C9300-24T", "CBS350-8T", "C9200L-24P-4G"). A port count with no type
	// letter ("C9300-24") is a series or family spelling, not a SKU.
	schemeCisco
	// schemePANOS: a PAN-OS appliance "PA-" and a 3- or 4-digit model
	// ("PA-440", "PA-3220"). A round number ending in 00 is a series name
	// ("PA-400", "PA-5400"), not a SKU.
	schemePANOS
)

// ciscoSKURe is the Cisco scheme of exact SKUs (see schemeCisco).
var ciscoSKURe = regexp.MustCompile(`^[A-Z]+[0-9]+[A-Z]*-[0-9]+[A-Z]+(-[A-Z0-9]+)*$`)

// panosSKURe is the PAN-OS appliance scheme (see schemePANOS).
var panosSKURe = regexp.MustCompile(`^PA-[1-9][0-9]{2,3}$`)

// skuSchemeOf classifies a raw model string. Only an exact SKU (isExactSKU)
// that matches a known scheme gets one; everything else is schemeNone.
func skuSchemeOf(model string) skuScheme {
	switch {
	case !isExactSKU(model):
		return schemeNone
	case ciscoSKURe.MatchString(model):
		return schemeCisco
	case panosSKURe.MatchString(model) && !strings.HasSuffix(model, "00"):
		return schemePANOS
	}
	return schemeNone
}

// wordRun reports whether the '-'-separated words of inner appear as a
// contiguous run in outer.
func wordRun(outer, inner string) bool {
	return strings.Contains("-"+outer+"-", "-"+inner+"-")
}

// deviceModel is a device's model in the normalised form that exact hits are
// compared under (see normalizeModel). An empty form names no product.
// scheme is the device's complete-SKU scheme (schemeNone unless its model
// string is a complete SKU of a known scheme).
type deviceModel struct {
	key    string
	scheme skuScheme
}

// newDeviceModel normalises a device model once per device subject.
func newDeviceModel(model string) deviceModel {
	return deviceModel{key: normalizeModel(model), scheme: skuSchemeOf(strings.TrimSpace(model))}
}

// isExact reports whether the product's model is the device's model: the
// normalised model strings are equal. Nothing else is a hit, so a near name,
// a sibling SKU or a series word never decides a finding or a clean status.
func (d deviceModel) isExact(p productModel) bool {
	return d.key != "" && p.key == d.key
}

// productModel is one of a CSAF product's models in the normalised form.
// Only the structured Models field from the product tree is used: the full
// name and the OS or family name carry version, series and vendor words,
// which must never form a device model. scheme is the SKU scheme of the
// tree's spelling of this model; when a product carries several spellings,
// the first known scheme wins (a product may carry both "PA-220" and the CPE
// spelling "pa-220").
type productModel struct {
	key    string
	scheme skuScheme
}

// newProductModel indexes one model of a CSAF product.
func newProductModel(model string) productModel {
	return productModel{key: normalizeModel(model), scheme: skuSchemeOf(strings.TrimSpace(model))}
}

// normalizeModel lower-cases s and folds every run of white space, '-' and
// '_' to one '-', dropping leading and trailing separators. Nothing else is
// folded: "CBS350 24P" and "CBS350-24P" are equal, "CBS350-24P-4G" is not.
func normalizeModel(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), isModelSeparator), "-")
}

// isModelSeparator reports whether r separates the words of a model string.
func isModelSeparator(r rune) bool {
	return r == '-' || r == '_' || unicode.IsSpace(r)
}

// indexedProduct is a CSAF product with its normalised models, built once.
// A model that normalises to nothing is no readable model, so the product's
// scope counts as incomplete.
type indexedProduct struct {
	p      vulnfeed.CSAFProduct
	models []productModel
}

// newIndexedProduct normalises the models of p, one entry per normalised
// model; the entry is an exact SKU when any of its spellings is one.
func newIndexedProduct(p vulnfeed.CSAFProduct) indexedProduct {
	ip := indexedProduct{p: p}
	for _, m := range p.Models {
		pm := newProductModel(m)
		if pm.key == "" {
			ip.p.ModelsIncomplete = true
			continue
		}
		if i := slices.IndexFunc(ip.models, func(o productModel) bool { return o.key == pm.key }); i >= 0 {
			if ip.models[i].scheme == schemeNone {
				ip.models[i].scheme = pm.scheme
			}
			continue
		}
		ip.models = append(ip.models, pm)
	}
	return ip
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
			byID[p.ProductID] = newIndexedProduct(p)
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

// deviceVuln judges one vulnerability of one advisory for the device. Only
// products of the device's OS (ecosystem) count, and of those only the ones
// whose model scope applies to it: no model named, or its exact model. A
// product naming only distinct exact SKUs is not the device; any other
// product scope leaves the vulnerability's coverage unknown.
// The advisory's own products decide: a hit on the device's exact model
// without a firmware hit here is a gap for this advisory, whatever other
// advisories list.
func (m *matcher) deviceVuln(s Subject, feed string, d indexedAdvisory, v vulnfeed.CSAFVulnerability, model deviceModel) deviceHit {
	fw := s.Device.Firmware
	var affected []vulnfeed.CSAFProduct
	var isFixed, isNotAffected, rangeSeen, unknownModel bool
	var hit deviceHit
	scan := func(ids []string, f func(p vulnfeed.CSAFProduct)) {
		for _, id := range ids {
			ip, ok := d.byID[id]
			if !ok || ip.p.Ecosystem != s.Ecosystem {
				continue
			}
			switch model.scope(ip) {
			case scopeOther:
				// The tree scopes this product to other models only.
				continue
			case scopeUnknown:
				unknownModel = true
				continue
			case scopeDevice:
				hit.exact = true
			}
			hit.applies = true
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
	if unknownModel {
		// A product whose model scope may or may not be the device sits in
		// this vulnerability: the coverage is unknown, never silent.
		m.gap(s, s.Device.Model, canonicalID(firstID), GapDeviceModelUnknown)
	}
	if hit.exact && !hit.firmware {
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
		m.emitDevice(s, ids, vendorFix(d.byID, v, s.Ecosystem, model, affected, &m.feedCut), feed)
	case rangeSeen:
		m.gap(s, s.Device.Model, canonicalID(firstID), GapVendorRange)
	}
	return hit
}

// vendorFix returns the fixed release of the affected firmware's train:
// the single distinct exact fixed version of the same ecosystem and train.
// Only fixed products whose model scope applies to the device count, so a
// fixed release of another model is never offered. None, several or an
// over-bound version give no_fix_yet; the matcher never picks among fixed
// releases by ordering them.
func vendorFix(byID map[string]indexedProduct, v vulnfeed.CSAFVulnerability, eco string, model deviceModel, affected []vulnfeed.CSAFProduct, cut *int) vulnfinding.Fix {
	trains := map[string]bool{}
	for _, p := range affected {
		if p.Train != "" {
			trains[p.Train] = true
		}
	}
	versions := map[string]bool{}
	for _, id := range v.Fixed {
		ip, ok := byID[id]
		if !ok {
			continue
		}
		if sc := model.scope(ip); sc != scopeAll && sc != scopeDevice {
			continue
		}
		if ip.p.Ecosystem == eco && ip.p.Version != "" && trains[ip.p.Train] {
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
