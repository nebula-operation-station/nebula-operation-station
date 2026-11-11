// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Work limits of one Index over all rules (ADR 0012 D2 "Limits"). Fields
// that would exceed them are marked LimitReached.
const (
	// MaxExpansionStepsPerSnapshot bounds the members visited while
	// expanding all rule fields of one snapshot.
	MaxExpansionStepsPerSnapshot = 1 << 24
	// MaxExpandedRangesPerSnapshot bounds the address and port ranges
	// held by one Index.
	MaxExpandedRangesPerSnapshot = 1 << 21
	// MaxCausesPerRule bounds the unevaluable causes recorded per rule;
	// the first one is always kept.
	MaxCausesPerRule = 16
)

// droppedPrefix starts a marker the ADR 0010 D4 redaction leaves in place
// of a dropped element.
const droppedPrefix = "<dropped:"

// Member values with a fixed meaning.
const (
	memberAny        = "any"
	memberAppDefault = "application-default"
)

// Cause is one reason a rule cannot be evaluated: the field (or marker)
// and a detail text. Detail may contain device text; render it as text.
type Cause struct {
	Field  string
	Detail string
}

// String returns "field: detail" or "field".
func (c Cause) String() string {
	if c.Detail == "" {
		return c.Field
	}
	return c.Field + ": " + c.Detail
}

// AddrRange is an inclusive address range of one family.
type AddrRange struct {
	From, To netip.Addr
}

// AddrSet is an expanded address field: Any or the union of Ranges.
// Negation is not applied (see RuleView).
type AddrSet struct {
	Any    bool
	Ranges []AddrRange
}

// PortRange is an inclusive destination port range of one protocol.
type PortRange struct {
	Protocol string
	From, To uint16
}

// ServiceSet is an expanded service field.
type ServiceSet struct {
	Any                bool
	ApplicationDefault bool
	Ports              []PortRange
}

// RuleView is the classified form of one security rule or the
// default-rule step, ready for evaluation in rule order.
//
// A disabled rule has Disabled set and nothing else is classified: it is
// skipped and listed. Otherwise Unevaluable lists the causes that make the
// rule unevaluable (ADR 0012 D2 fail-safe); LimitReached is set when its
// expansion hit a limit. A rule with either set must end the evaluation
// with unknown when it is reached; its other fields are then incomplete.
// Conditions lists the match conditions the model has no data for (rule
// is conditional, ADR 0012 D2 step 4).
type RuleView struct {
	Index             int
	Name              string
	Disabled          bool
	Unevaluable       []Cause
	LimitReached      bool
	Action            Action
	From, To          []string
	Source            AddrSet
	Destination       AddrSet
	NegateSource      bool
	NegateDestination bool
	Service           ServiceSet
	Conditions        []string
}

// Evaluable reports whether the rule (if enabled) can be evaluated.
func (v RuleView) Evaluable() bool {
	return v.Disabled || (len(v.Unevaluable) == 0 && !v.LimitReached)
}

// Reason returns the fail-safe reason of ADR 0012 D2, "rule <name>
// unevaluable: <field or marker>", or "rule <name>: limit reached", or ""
// for an evaluable rule.
func (v RuleView) Reason() string {
	return reason(v.Name, v.Unevaluable, v.LimitReached, v.Disabled)
}

// NATRuleView is the classified form of one NAT rule. Fields mean the same
// as in RuleView. Translation is nil when the rule translates no
// destination; TranslatedAddress is its expanded address.
type NATRuleView struct {
	Index             int
	Name              string
	Disabled          bool
	Unevaluable       []Cause
	LimitReached      bool
	From              []string
	To                string
	Source            AddrSet
	Destination       AddrSet
	Service           ServiceSet
	Translation       *DestinationTranslation
	TranslatedAddress AddrSet
}

// Evaluable reports whether the NAT rule (if enabled) can be evaluated.
func (v NATRuleView) Evaluable() bool {
	return v.Disabled || (len(v.Unevaluable) == 0 && !v.LimitReached)
}

// Reason returns the fail-safe reason as RuleView.Reason does.
func (v NATRuleView) Reason() string {
	return reason(v.Name, v.Unevaluable, v.LimitReached, v.Disabled)
}

func reason(name string, causes []Cause, limit, disabled bool) string {
	switch {
	case disabled:
		return ""
	case len(causes) > 0:
		return fmt.Sprintf("rule %s unevaluable: %s", sanitizeText(name), causes[0])
	case limit:
		return fmt.Sprintf("rule %s: %s", sanitizeText(name), ErrLimitReached)
	}
	return ""
}

// Names of the default rules as PAN-OS shows them.
const (
	DefaultIntrazoneName = "intrazone-default"
	DefaultInterzoneName = "interzone-default"
)

// Index is the classified, expanded form of one snapshot. It is immutable
// after NewIndex and safe for concurrent use.
type Index struct {
	snap      *Snapshot
	placer    *Placer
	zones     map[string]bool
	rules     []RuleView
	nat       []NATRuleView
	intrazone RuleView
	interzone RuleView
	// ruleAddrs and natAddrs hold the address and service fields of rules
	// and nat, index by index, merged once at build time.
	ruleAddrs []ruleAddrs
	natAddrs  []natAddrs
	// natZone is the post-NAT zone of each NAT rule (postNATZones).
	natZone []postZone
}

// ruleAddrs are the merged address and service fields of one security
// rule.
type ruleAddrs struct {
	src, dst mergedAddrs
	svc      mergedService
}

// natAddrs are the merged address and service fields of one NAT rule.
type natAddrs struct {
	src, dst, translated mergedAddrs
	svc                  mergedService
}

// NewIndex checks the snapshot limits, validates name uniqueness and
// classifies every rule. It fails (ErrLimitReached, ErrInvalidSnapshot)
// only when the snapshot as a whole cannot be used; a single rule that
// cannot be evaluated is marked in its view instead.
func NewIndex(s *Snapshot) (*Index, error) {
	return newIndex(s, defaultWorkLimits())
}

// workLimits are the per-snapshot work limits of one Index. They are a
// value so tests can check the limit logic at small sizes.
type workLimits struct {
	steps  int // MaxExpansionStepsPerSnapshot
	ranges int // MaxExpandedRangesPerSnapshot
}

func defaultWorkLimits() workLimits {
	return workLimits{steps: MaxExpansionStepsPerSnapshot, ranges: MaxExpandedRangesPerSnapshot}
}

func newIndex(s *Snapshot, lim workLimits) (*Index, error) {
	return buildIndex(s, lim, nil, MaxNATPlacementsPerSnapshot)
}

// buildIndex builds the Index. place places the translated NAT addresses
// (nil: the snapshot's Placer); maxPlacements bounds its calls.
func buildIndex(s *Snapshot, lim workLimits, place placeFunc, maxPlacements int) (*Index, error) {
	pl, err := NewPlacer(s)
	if err != nil {
		return nil, fmt.Errorf("new index: %w", err)
	}
	if place == nil {
		place = pl.Place
	}
	x := &Index{snap: s, placer: pl, zones: make(map[string]bool, len(s.Zones))}
	for _, z := range s.Zones {
		if x.zones[z.Name] {
			return nil, fmt.Errorf("new index: %w: duplicate zone %q", ErrInvalidSnapshot, z.Name)
		}
		x.zones[z.Name] = true
	}
	ex, err := newExpander(s, lim)
	if err != nil {
		return nil, fmt.Errorf("new index: %w", err)
	}
	x.rules = make([]RuleView, len(s.SecurityRules))
	for i := range s.SecurityRules {
		x.rules[i] = x.classifyRule(ex, i, &s.SecurityRules[i])
	}
	x.nat = make([]NATRuleView, len(s.NATRules))
	for i := range s.NATRules {
		x.nat[i] = x.classifyNAT(ex, i, &s.NATRules[i])
	}
	x.intrazone, x.interzone = classifyDefaults(s.DefaultRules)
	x.ruleAddrs = make([]ruleAddrs, len(x.rules))
	for i := range x.rules {
		v := &x.rules[i]
		x.ruleAddrs[i] = ruleAddrs{src: mergeSet(v.Source), dst: mergeSet(v.Destination), svc: mergeService(v.Service)}
	}
	x.natAddrs = make([]natAddrs, len(x.nat))
	for i := range x.nat {
		v := &x.nat[i]
		x.natAddrs[i] = natAddrs{
			src: mergeSet(v.Source), dst: mergeSet(v.Destination), translated: mergeSet(v.TranslatedAddress),
			svc: mergeService(v.Service),
		}
	}
	x.natZone = postNATZones(x.nat, place, maxPlacements)
	return x, nil
}

// Placer returns the placer of the snapshot.
func (x *Index) Placer() *Placer { return x.placer }

// SecurityRules returns the classified security rules in rule order. The
// slice is shared; callers must not modify it.
func (x *Index) SecurityRules() []RuleView { return x.rules }

// NATRules returns the classified NAT rules in NAT rule order. The slice
// is shared; callers must not modify it.
func (x *Index) NATRules() []NATRuleView { return x.nat }

// DefaultRule returns the default intrazone (intrazone true) or interzone
// rule. Without collected default rules it is unevaluable.
func (x *Index) DefaultRule(intrazone bool) RuleView {
	if intrazone {
		return x.intrazone
	}
	return x.interzone
}

// MaxCauseTextBytes bounds the field and the detail text of one Cause
// after sanitizing.
const MaxCauseTextBytes = 2048

// causes collects unevaluable causes up to MaxCausesPerRule.
type causes []Cause

// add records a cause whose detail is the concatenation of parts. The
// cap is checked first, so a full list builds no strings. Field and
// detail are sanitized: they hold device text.
func (c *causes) add(field string, parts ...string) {
	if len(*c) >= MaxCausesPerRule {
		return
	}
	*c = append(*c, Cause{Field: sanitizeText(field), Detail: sanitizeText(parts...)})
}

// sanitizeText concatenates parts into a text safe to render: invalid
// UTF-8, C0/C1 control and bidi formatting characters (isControl) become
// U+FFFD, and the result is cut
// at a rune boundary to at most MaxCauseTextBytes. Snapshot texts already
// passed CheckLimits; this is the last line of defence for reason texts.
func sanitizeText(parts ...string) string {
	if len(parts) == 1 && len(parts[0]) <= MaxCauseTextBytes && cleanText(parts[0]) {
		return parts[0]
	}
	var b strings.Builder
	for _, p := range parts {
		for _, r := range p {
			if r == utf8.RuneError || isControl(r) {
				r = utf8.RuneError
			}
			if b.Len()+utf8.RuneLen(r) > MaxCauseTextBytes {
				return b.String()
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if isControl(r) {
			return false
		}
	}
	return true
}

// isControl reports C0 and C1 control characters, DEL and the Unicode
// bidirectional formatting characters (marks, embeddings, overrides,
// isolates), which can reorder how a name is displayed. CheckLimits
// rejects them and sanitizeText replaces them.
func isControl(r rune) bool {
	switch {
	case r < 0x20, r >= 0x7f && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f, // ALM, LRM, RLM
		r >= 0x202a && r <= 0x202e, // LRE, RLE, PDF, LRO, RLO
		r >= 0x2066 && r <= 0x2069: // LRI, RLI, FSI, PDI
		return true
	}
	return false
}

func (c *causes) markers(owner string, dropped, outside []string) {
	for _, m := range dropped {
		c.add(m, owner)
	}
	for _, f := range outside {
		c.add(f, "outside the collected allowlist")
	}
}

// list requires a collected, non-empty list. An adapter fills the PAN-OS
// default ("any") explicitly; an empty list is never read as "any".
func (c *causes) list(field string, f Field[[]string]) ([]string, bool) {
	switch {
	case !f.Collected:
		c.add(field, "not collected")
		return nil, false
	case len(f.Value) == 0:
		c.add(field, "empty")
		return nil, false
	}
	for _, m := range f.Value {
		if strings.HasPrefix(m, droppedPrefix) {
			c.add(m, field)
			return nil, false
		}
	}
	return f.Value, true
}

// flag returns a collected bool. A field that was not collected records
// the cause and returns false whatever its Value: an uncollected field
// never decides (an uncollected Disabled never skips a rule).
func (c *causes) flag(field string, f Field[bool]) bool {
	if !f.Collected {
		c.add(field, "not collected")
		return false
	}
	return f.Value
}

func isAny(l []string) bool { return len(l) == 1 && l[0] == memberAny }

func (x *Index) zoneList(c *causes, field string, f Field[[]string]) []string {
	l, ok := c.list(field, f)
	if !ok || isAny(l) {
		return l
	}
	for _, z := range l {
		if !x.zones[z] {
			c.add(field, "zone ", z, " not in snapshot")
		}
	}
	return l
}

func (x *Index) classifyRule(ex *expander, i int, r *SecurityRule) RuleView {
	v := RuleView{Index: i, Name: r.Name, Action: r.Action}
	var c causes
	if c.flag("disabled", r.Disabled) {
		v.Disabled = true
		return v
	}
	c.markers("rule", r.Dropped, r.OutsideAllowlist)
	if !validAction(r.Action) {
		c.add("action", "unknown action")
	}
	v.From = x.zoneList(&c, "from", r.From)
	v.To = x.zoneList(&c, "to", r.To)
	v.NegateSource = c.flag("negate-source", r.NegateSource)
	v.NegateDestination = c.flag("negate-destination", r.NegateDestination)
	switch {
	case !r.Type.Collected:
		c.add("rule-type", "not collected")
	case r.Type.Value != RuleTypeUniversal:
		c.add("rule-type", string(r.Type.Value), " not modelled")
	}
	for _, h := range []struct {
		name string
		f    Field[[]string]
	}{{"source-hip", r.SourceHIP}, {"destination-hip", r.DestinationHIP}} {
		// Like every list: not collected, empty or a marker is
		// unevaluable; only an explicit "any" means no HIP condition.
		if l, ok := c.list(h.name, h.f); ok && !isAny(l) {
			c.add(h.name, "HIP profiles not modelled")
		}
	}
	if l, ok := c.list("source", r.Source); ok {
		v.Source = ex.addresses(&c, &v.LimitReached, "source", l)
	}
	if l, ok := c.list("destination", r.Destination); ok {
		v.Destination = ex.addresses(&c, &v.LimitReached, "destination", l)
	}
	if l, ok := c.list("service", r.Service); ok {
		v.Service = ex.services(&c, &v.LimitReached, l)
	}
	for _, cf := range []struct {
		name string
		f    Field[[]string]
	}{{"application", r.Application}, {"source-user", r.SourceUser}, {"category", r.Category}} {
		if l, ok := c.list(cf.name, cf.f); ok && !isAny(l) {
			v.Conditions = append(v.Conditions, cf.name)
		}
	}
	if v.Service.ApplicationDefault {
		v.Conditions = append(v.Conditions, "service application-default")
	}
	switch {
	case !r.Schedule.Collected:
		v.Conditions = append(v.Conditions, "schedule not collected")
	case r.Schedule.Value != "":
		v.Conditions = append(v.Conditions, "schedule")
	}
	v.Unevaluable = c
	return v
}

func (x *Index) classifyNAT(ex *expander, i int, r *NATRule) NATRuleView {
	v := NATRuleView{Index: i, Name: r.Name}
	var c causes
	if c.flag("disabled", r.Disabled) {
		v.Disabled = true
		return v
	}
	c.markers("NAT rule", r.Dropped, r.OutsideAllowlist)
	v.From = x.zoneList(&c, "from", r.From)
	switch {
	case !r.To.Collected:
		c.add("to", "not collected")
	case strings.HasPrefix(r.To.Value, droppedPrefix):
		c.add(r.To.Value, "to")
	case r.To.Value != memberAny && !x.zones[r.To.Value]:
		c.add("to", "zone ", r.To.Value, " not in snapshot")
	default:
		v.To = r.To.Value
	}
	if l, ok := c.list("source", r.Source); ok {
		v.Source = ex.addresses(&c, &v.LimitReached, "source", l)
	}
	if l, ok := c.list("destination", r.Destination); ok {
		v.Destination = ex.addresses(&c, &v.LimitReached, "destination", l)
	}
	switch {
	case !r.Service.Collected:
		c.add("service", "not collected")
	case r.Service.Value == "":
		c.add("service", "empty")
	default:
		v.Service = ex.services(&c, &v.LimitReached, []string{r.Service.Value})
		if v.Service.ApplicationDefault {
			c.add("service", "application-default in a NAT rule")
		}
	}
	switch dt := r.DestinationTranslation; {
	case !dt.Collected:
		c.add("destination-translation", "not collected")
	case dt.Value == nil:
	case dt.Value.Dynamic:
		c.add("destination-translation", "dynamic destination translation not modelled")
	case dt.Value.Address == "":
		c.add("destination-translation", "no translated address")
	default:
		t := *dt.Value
		v.Translation = &t
		v.TranslatedAddress = ex.addresses(&c, &v.LimitReached, "translated-address", []string{t.Address})
		if v.TranslatedAddress.Any {
			c.add("translated-address", "any")
		}
	}
	v.Unevaluable = c
	return v
}

func classifyDefaults(f Field[DefaultRules]) (RuleView, RuleView) {
	intra := RuleView{Index: -1, Name: DefaultIntrazoneName}
	inter := RuleView{Index: -1, Name: DefaultInterzoneName}
	if !f.Collected {
		cause := Cause{Field: "rulebase/default-security-rules", Detail: "not collected"}
		intra.Unevaluable = []Cause{cause}
		inter.Unevaluable = []Cause{cause}
		return intra, inter
	}
	for _, d := range []struct {
		v *RuleView
		a Action
	}{{&intra, f.Value.Intrazone}, {&inter, f.Value.Interzone}} {
		var c causes
		c.markers("default rules", f.Value.Dropped, f.Value.OutsideAllowlist)
		if !validAction(d.a) {
			c.add("action", "unknown action")
		}
		d.v.Action = d.a
		d.v.Source.Any, d.v.Destination.Any, d.v.Service.Any = true, true, true
		d.v.From, d.v.To = []string{memberAny}, []string{memberAny}
		d.v.Unevaluable = c
	}
	return intra, inter
}

func validAction(a Action) bool {
	switch a {
	case ActionAllow, ActionDeny, ActionDrop, ActionResetClient, ActionResetServer, ActionResetBoth:
		return true
	}
	return false
}

// Completeness says whether a snapshot is complete for one path (ADR 0012
// D4): every input fresh, exactly one vsys, and no unevaluable rule, NAT
// rule or default rule that the path touches. Reasons lists every gap.
type Completeness struct {
	Complete bool
	Reasons  []string
}

// PathCompleteness returns the completeness of the snapshot for traffic
// from zone src to zone dst. An empty zone (not proven by placement) is
// incomplete, and so is a zone that the zones dataset does not hold (an
// interface or route may name a zone the dataset lacks; the rules and the
// default step cannot be trusted for it). A security rule touches the path when its zones could match
// it (zone lists not collected count as matching); every unevaluable NAT
// rule touches every path, because the reverse-NAT lookup cannot exclude
// that it forwards to the destination.
func (x *Index) PathCompleteness(src, dst string) Completeness {
	var rs []string
	for _, k := range RequiredInputs {
		if st := x.snap.Inputs[k].State; st != InputFresh {
			rs = append(rs, fmt.Sprintf("input %s %s", k, st))
		}
	}
	switch x.snap.Vsys {
	case 1:
	case 0:
		rs = append(rs, "vsys count not reported")
	default:
		rs = append(rs, "more than one vsys")
	}
	if src == "" || dst == "" {
		rs = append(rs, "zone not proven")
	}
	for i, z := range []string{src, dst} {
		if z != "" && !x.zones[z] && (i == 0 || z != src) {
			rs = append(rs, "zone "+sanitizeText(z)+" not in snapshot")
		}
	}
	for i := range x.rules {
		v := &x.rules[i]
		if v.Evaluable() || !x.touches(&x.snap.SecurityRules[i], src, dst) {
			continue
		}
		rs = append(rs, v.Reason())
	}
	for i := range x.nat {
		if v := &x.nat[i]; !v.Evaluable() {
			rs = append(rs, v.Reason())
		}
	}
	if d := x.DefaultRule(src != "" && src == dst); !d.Evaluable() {
		rs = append(rs, d.Reason())
	}
	return Completeness{Complete: len(rs) == 0, Reasons: rs}
}

// touches reports whether a rule's zones could match src → dst. Unknown
// zones (empty src or dst) and uncollected zone lists always match.
func (x *Index) touches(r *SecurityRule, src, dst string) bool {
	return zoneMayMatch(r.From, src) && zoneMayMatch(r.To, dst)
}

func zoneMayMatch(f Field[[]string], zone string) bool {
	if !f.Collected || zone == "" || len(f.Value) == 0 {
		return true
	}
	return slices.Contains(f.Value, memberAny) || slices.Contains(f.Value, zone) ||
		slices.ContainsFunc(f.Value, func(m string) bool { return strings.HasPrefix(m, droppedPrefix) })
}

// expander expands address and service members against the objects of
// one snapshot, within the per-field and per-snapshot limits.
type expander struct {
	addrs      map[string]*AddressObject
	addrGroups map[string]*Group
	svcs       map[string]*ServiceObject
	svcGroups  map[string]*Group
	steps      int // per snapshot
	ranges     int // per snapshot
	lim        workLimits
}

func newExpander(s *Snapshot, lim workLimits) (*expander, error) {
	ex := &expander{
		lim:        lim,
		addrs:      make(map[string]*AddressObject, len(s.Addresses)),
		addrGroups: make(map[string]*Group, len(s.AddressGroups)),
		svcs:       make(map[string]*ServiceObject, len(s.Services)),
		svcGroups:  make(map[string]*Group, len(s.ServiceGroups)),
	}
	for i := range s.Addresses {
		n := s.Addresses[i].Name
		if ex.addrs[n] != nil {
			return nil, fmt.Errorf("%w: duplicate address name %q", ErrInvalidSnapshot, n)
		}
		ex.addrs[n] = &s.Addresses[i]
	}
	for i := range s.AddressGroups {
		n := s.AddressGroups[i].Name
		if ex.addrs[n] != nil || ex.addrGroups[n] != nil {
			return nil, fmt.Errorf("%w: duplicate address name %q", ErrInvalidSnapshot, n)
		}
		ex.addrGroups[n] = &s.AddressGroups[i]
	}
	for i := range s.Services {
		n := s.Services[i].Name
		if ex.svcs[n] != nil {
			return nil, fmt.Errorf("%w: duplicate service name %q", ErrInvalidSnapshot, n)
		}
		ex.svcs[n] = &s.Services[i]
	}
	for i := range s.ServiceGroups {
		n := s.ServiceGroups[i].Name
		if ex.svcs[n] != nil || ex.svcGroups[n] != nil {
			return nil, fmt.Errorf("%w: duplicate service name %q", ErrInvalidSnapshot, n)
		}
		ex.svcGroups[n] = &s.ServiceGroups[i]
	}
	return ex, nil
}

// fieldWork tracks the work of expanding one rule field.
type fieldWork struct {
	steps, ranges int
	limit         bool
	stack         []string
}

// step charges one member visit; false means a limit was reached.
func (ex *expander) step(w *fieldWork) bool {
	if w.limit || w.steps >= MaxExpansionSteps || ex.steps >= ex.lim.steps {
		w.limit = true
		return false
	}
	w.steps++
	ex.steps++
	return true
}

// addRange charges one result range; false means a limit was reached.
func (ex *expander) addRange(w *fieldWork, max int) bool {
	if w.limit || w.ranges >= max || ex.ranges >= ex.lim.ranges {
		w.limit = true
		return false
	}
	w.ranges++
	ex.ranges++
	return true
}

func (ex *expander) addresses(c *causes, limit *bool, field string, members []string) AddrSet {
	var out AddrSet
	w := &fieldWork{}
	for _, m := range members {
		if m == memberAny {
			out.Any = true
			continue
		}
		ex.addrMember(c, w, &out, field, m, 0)
	}
	if w.limit {
		*limit = true
	}
	return out
}

func (ex *expander) addrMember(c *causes, w *fieldWork, out *AddrSet, field, m string, depth int) {
	if !ex.step(w) {
		return
	}
	if strings.HasPrefix(m, droppedPrefix) {
		c.add(m, field)
		return
	}
	if o := ex.addrs[m]; o != nil {
		ex.addrObject(c, w, out, field, o)
		return
	}
	if g := ex.addrGroups[m]; g != nil {
		ex.group(c, w, field, g, depth, func(mm string) { ex.addrMember(c, w, out, field, mm, depth+1) })
		return
	}
	r, err := parseAddrLiteral(m)
	if err != nil {
		c.add(field, "member ", m, ": object not found")
		return
	}
	if ex.addRange(w, MaxExpandedRangesPerField) {
		out.Ranges = append(out.Ranges, r)
	}
}

func (ex *expander) addrObject(c *causes, w *fieldWork, out *AddrSet, field string, o *AddressObject) {
	if len(o.Dropped) > 0 {
		c.add(o.Dropped[0], "address ", o.Name)
		return
	}
	var r AddrRange
	var err error
	switch o.Type {
	case AddressNetmask:
		r, err = parseAddrLiteral(o.Value)
		if err == nil && strings.Contains(o.Value, "-") {
			err = fmt.Errorf("range in an ip-netmask object")
		}
	case AddressRange:
		r, err = parseAddrLiteral(o.Value)
		if err == nil && !strings.Contains(o.Value, "-") {
			err = fmt.Errorf("no range in an ip-range object")
		}
	default:
		c.add(field, "address ", o.Name, ": type ", string(o.Type), " not evaluable")
		return
	}
	if err != nil {
		c.add(field, "address ", o.Name, ": ", err.Error())
		return
	}
	if ex.addRange(w, MaxExpandedRangesPerField) {
		out.Ranges = append(out.Ranges, r)
	}
}

// group expands the static members of g through each, checking dynamic
// groups, markers, empty groups, cycles and the depth limit. depth is the
// number of groups above g.
func (ex *expander) group(c *causes, w *fieldWork, field string, g *Group, depth int, each func(string)) {
	switch {
	case depth+1 > MaxGroupDepth:
		w.limit = true
		return
	case slices.Contains(w.stack, g.Name):
		c.add(field, "group ", g.Name, ": cycle")
		return
	case g.Dynamic:
		c.add(field, "group ", g.Name, ": dynamic members unknown")
		return
	case len(g.Dropped) > 0:
		c.add(g.Dropped[0], "group ", g.Name)
		return
	case len(g.Static) == 0:
		c.add(field, "group ", g.Name, ": no members")
		return
	}
	w.stack = append(w.stack, g.Name)
	for _, m := range g.Static {
		if w.limit {
			break
		}
		each(m)
	}
	w.stack = w.stack[:len(w.stack)-1]
}

func (ex *expander) services(c *causes, limit *bool, members []string) ServiceSet {
	var out ServiceSet
	w := &fieldWork{}
	for _, m := range members {
		switch m {
		case memberAny:
			out.Any = true
		case memberAppDefault:
			out.ApplicationDefault = true
		default:
			ex.svcMember(c, w, &out, m, 0)
		}
	}
	if w.limit {
		*limit = true
	}
	return out
}

func (ex *expander) svcMember(c *causes, w *fieldWork, out *ServiceSet, m string, depth int) {
	if !ex.step(w) {
		return
	}
	if strings.HasPrefix(m, droppedPrefix) {
		c.add(m, "service")
		return
	}
	if o := ex.svcs[m]; o != nil {
		ex.svcObject(c, w, out, o)
		return
	}
	if g := ex.svcGroups[m]; g != nil {
		ex.group(c, w, "service", g, depth, func(mm string) { ex.svcMember(c, w, out, mm, depth+1) })
		return
	}
	c.add("service", "member ", m, ": object not found")
}

func (ex *expander) svcObject(c *causes, w *fieldWork, out *ServiceSet, o *ServiceObject) {
	switch {
	case len(o.Dropped) > 0:
		c.add(o.Dropped[0], "service ", o.Name)
		return
	case !o.SourcePorts.Collected:
		c.add("service", "service ", o.Name, ": source-port not collected")
		return
	case o.SourcePorts.Value != "":
		c.add("service", "service ", o.Name, ": source-port condition not modelled")
		return
	case o.Protocol != "tcp" && o.Protocol != "udp" && o.Protocol != "sctp":
		c.add("service", "service ", o.Name, ": protocol not evaluable")
		return
	}
	ranges, err := parsePorts(o.Ports)
	if err != nil {
		c.add("service", "service ", o.Name, ": ", err.Error())
		return
	}
	for _, r := range ranges {
		if !ex.addRange(w, MaxPortRangesPerField) {
			return
		}
		out.Ports = append(out.Ports, PortRange{Protocol: o.Protocol, From: r[0], To: r[1]})
	}
}

// parseAddrLiteral parses an address, prefix or ascending range of one
// family. IPv6 zones and IPv4-mapped IPv6 forms are refused: their match
// semantics on the device are not modelled.
func parseAddrLiteral(s string) (AddrRange, error) {
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, err1 := netip.ParseAddr(lo)
		b, err2 := netip.ParseAddr(hi)
		if err1 != nil || err2 != nil {
			return AddrRange{}, fmt.Errorf("invalid range")
		}
		if err := plainAddr(a); err != nil {
			return AddrRange{}, err
		}
		if err := plainAddr(b); err != nil {
			return AddrRange{}, err
		}
		if a.BitLen() != b.BitLen() || b.Less(a) {
			return AddrRange{}, fmt.Errorf("invalid range")
		}
		return AddrRange{From: a, To: b}, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return AddrRange{}, fmt.Errorf("invalid prefix")
		}
		if err := plainAddr(p.Addr()); err != nil {
			return AddrRange{}, err
		}
		return prefixRange(p.Masked()), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return AddrRange{}, fmt.Errorf("invalid address")
	}
	if err := plainAddr(a); err != nil {
		return AddrRange{}, err
	}
	return AddrRange{From: a, To: a}, nil
}

func plainAddr(a netip.Addr) error {
	switch {
	case a.Zone() != "":
		return fmt.Errorf("address with IPv6 zone")
	case a.Is4In6():
		return fmt.Errorf("IPv4-mapped IPv6 address")
	}
	return nil
}

// prefixRange returns the first and last address of a masked prefix.
func prefixRange(p netip.Prefix) AddrRange {
	from := p.Addr()
	b := from.AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	to, _ := netip.AddrFromSlice(b)
	return AddrRange{From: from, To: to}
}

// maxPortItems bounds the comma-separated items of one port value.
const maxPortItems = 256

// parsePorts parses "80", "80,443" or "8000-8080" lists of ports 1–65535.
func parsePorts(s string) ([][2]uint16, error) {
	if s == "" {
		return nil, fmt.Errorf("no ports")
	}
	items := strings.Split(s, ",")
	if len(items) > maxPortItems {
		return nil, fmt.Errorf("too many port items")
	}
	out := make([][2]uint16, 0, len(items))
	for _, it := range items {
		lo, hi, isRange := strings.Cut(it, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("invalid port range")
			}
		}
		out = append(out, [2]uint16{a, b})
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	if s == "" || len(s) > 5 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, fmt.Errorf("invalid port")
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("invalid port")
	}
	return uint16(n), nil
}
