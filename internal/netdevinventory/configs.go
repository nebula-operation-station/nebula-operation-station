// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

// Config versions and diffs (ADR 0010 D4 "Config versions, diff and
// drift", plan ND-17 part 1). The executor returns each configuration read
// as redacted text with a keyed raw_digest; the server stores one version
// per distinct raw_digest of a (device, config) and only advances
// last_seen on an identical read. Diffs between two versions run
// internal/textdiff over the redacted text; a PAN-OS configuration is
// normalized first (one element per line, stable sibling order outside
// order-significant containers, volatile attributes dropped) so the diff
// is readable. Retention is Prune's (retention.go); RecordConfig enforces
// its count limit on every new version. The baseline flag and change
// binding are set
// by the executor-mirroring code of ND-17 part 2 and never by a read.
//
// Every stored line is device text: validated with the netdevcontract
// limits, stored verbatim and rendered as text only.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/textdiff"
)

// ConfigKind names the configuration a version belongs to.
type ConfigKind string

// Configurations. Startup exists on CBS only.
const (
	ConfigRunning ConfigKind = "running"
	ConfigStartup ConfigKind = "startup"
)

// Limits of config versions.
const (
	// MaxLeaseIDBytes bounds the reading lease ID stored with a version
	// (the CHECK of migration 0038).
	MaxLeaseIDBytes = 128
	// MaxListedConfigVersions bounds ListConfigVersions. Retention keeps at
	// most this many versions per device unless its protected versions
	// alone exceed it.
	MaxListedConfigVersions = MaxConfigVersionsPerDevice
	// MaxNormalizedConfigBytes bounds the text NormalizePANOSConfig
	// renders, so the indentation of deep elements cannot amplify a
	// configuration of MaxRedactedConfigBytes without bound.
	MaxNormalizedConfigBytes = 2 * netdevcontract.MaxRedactedConfigBytes
)

// Sentinel errors of config versions.
var (
	// ErrUnknownConfig is returned for a config name other than running or
	// startup.
	ErrUnknownConfig = errors.New("netdevinventory: unknown config")
	// ErrInvalidConfig is returned for a snapshot or lease ID that fails
	// validation. Its messages never quote the configuration text.
	ErrInvalidConfig = errors.New("netdevinventory: invalid config snapshot")
	// ErrRedactionMismatch is returned when a read carries a stored
	// raw_digest with another redacted text. Redaction is deterministic
	// for one raw config, so this is an executor fault; the stored version
	// is kept unchanged rather than rewritten.
	ErrRedactionMismatch = errors.New("netdevinventory: stored raw_digest with other redacted text")
	// ErrConfigVersionNotFound is returned for a version ID that is not a
	// stored version of the device.
	ErrConfigVersionNotFound = errors.New("netdevinventory: config version not found")
)

// ConfigVersion is one stored configuration version.
type ConfigVersion struct {
	ID             int64
	DeviceID       string
	Config         ConfigKind
	RawDigest      string
	RedactedDigest string
	// LeaseID is the reading lease of the first read of this version.
	LeaseID   string
	FirstSeen time.Time
	LastSeen  time.Time
	// Baseline marks the mirrored executor-approved baseline.
	Baseline bool
	// ChangeBoundAt is the time of the newest change the version is bound
	// to; zero if none.
	ChangeBoundAt time.Time
	// Lines is the redacted text; set by GetConfigVersion only.
	Lines []string
}

// RecordConfigResult is the answer of RecordConfig.
type RecordConfigResult struct {
	// VersionID is the stored version the read belongs to.
	VersionID int64
	// New is set when the read's raw_digest made a new version.
	New bool
}

func validConfigKind(c ConfigKind) bool { return c == ConfigRunning || c == ConfigStartup }

func validLeaseID(s string) bool {
	if len(s) > MaxLeaseIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// RecordConfig stores one redacted configuration read of deviceID observed
// at observedAt under trustGeneration. A raw_digest already stored for the
// (device, config) makes no new version: last_seen advances (never
// backwards) and first_seen moves back for a delayed read; baseline and
// change binding are untouched. A new raw_digest becomes a new version
// unless it was observed at or before the last_seen of the current
// version (ErrOutOfOrder: a delayed read cannot become history behind the
// current version). The snapshot is validated with the netdevcontract
// observation limits of the device family; the trust generation is checked
// inside the write transaction.
func (s *Store) RecordConfig(ctx context.Context, deviceID string, config ConfigKind, trustGeneration uint64,
	observedAt time.Time, leaseID string, c netdevcontract.ConfigSnapshot) (RecordConfigResult, error) {
	if !validConfigKind(config) {
		return RecordConfigResult{}, ErrUnknownConfig
	}
	if !validLeaseID(leaseID) {
		return RecordConfigResult{}, fmt.Errorf("%w: lease ID is not printable ASCII of at most %d bytes", ErrInvalidConfig, MaxLeaseIDBytes)
	}
	now := s.now()
	if observedAt.After(now.Add(MaxFutureSkew)) {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: device %s config %s: %w", deviceID, config, ErrFutureObservation)
	}
	if observedAt.Before(now.Add(-ConfigVersionRetention)) {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: device %s config %s: %w", deviceID, config, ErrObservationTooOld)
	}
	var res RecordConfigResult
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		res, err = s.recordConfig(ctx, tx, deviceID, config, trustGeneration, observedAt, leaseID, c, now)
		return err
	})
	if err != nil {
		return RecordConfigResult{}, err
	}
	return res, nil
}

func (s *Store) recordConfig(ctx context.Context, tx *sql.Tx, deviceID string, config ConfigKind, trustGeneration uint64,
	observedAt time.Time, leaseID string, c netdevcontract.ConfigSnapshot, now time.Time) (RecordConfigResult, error) {
	var family string
	var gen int64
	err := tx.QueryRowContext(ctx, `SELECT family, trust_generation FROM netdev_devices_seen WHERE device_id = ?`,
		deviceID).Scan(&family, &gen)
	if errors.Is(err, sql.ErrNoRows) {
		return RecordConfigResult{}, ErrDeviceNotFound
	}
	if err != nil {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: load device %s: %w", deviceID, err)
	}
	if trustGeneration > uint64(1<<63-1) || int64(trustGeneration) != gen {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: device %s config %s: observed generation %d, current %d: %w",
			deviceID, config, trustGeneration, gen, ErrTrustGenerationChanged)
	}
	fam := netdevcontract.Family(family)
	if config == ConfigStartup && fam != netdevcontract.FamilyCBS {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: device %s config %s: %w", deviceID, config, ErrWrongFamily)
	}
	o := netdevcontract.Observation{DeviceID: deviceID, Family: fam, TrustGeneration: trustGeneration, ObservedAt: observedAt}
	if config == ConfigStartup {
		o.StartupConfig = netdevcontract.AvailableDataset(c)
	} else {
		o.RunningConfig = netdevcontract.AvailableDataset(c)
	}
	if _, err := netdevcontract.ValidateObservation(o); err != nil {
		return RecordConfigResult{}, fmt.Errorf("%w: device %s config %s: %w", ErrInvalidConfig, deviceID, config, err)
	}
	obs, nowM := micros(observedAt), micros(now)

	var id int64
	var red string
	err = tx.QueryRowContext(ctx, `SELECT id, redacted_digest FROM netdev_config_versions
		WHERE device_id = ? AND config = ? AND raw_digest = ?`, deviceID, string(config), c.RawDigest).Scan(&id, &red)
	switch {
	case err == nil:
		if red != c.RedactedDigest {
			return RecordConfigResult{}, fmt.Errorf("netdevinventory: device %s config %s version %d: %w", deviceID, config, id, ErrRedactionMismatch)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE netdev_config_versions
			SET last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?) WHERE id = ?`, obs, obs, id); err != nil {
			return RecordConfigResult{}, fmt.Errorf("netdevinventory: advance config version %d: %w", id, err)
		}
		if err := s.touchDevice(ctx, tx, deviceID, obs, nowM); err != nil {
			return RecordConfigResult{}, err
		}
		return RecordConfigResult{VersionID: id}, nil
	case !errors.Is(err, sql.ErrNoRows):
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: load config version of %s: %w", deviceID, err)
	}

	var newest sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(last_seen) FROM netdev_config_versions WHERE device_id = ? AND config = ?`,
		deviceID, string(config)).Scan(&newest); err != nil {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: load current config version of %s: %w", deviceID, err)
	}
	if newest.Valid && obs <= newest.Int64 {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: device %s config %s: %w", deviceID, config, ErrOutOfOrder)
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO netdev_config_versions
		(device_id, config, raw_digest, redacted_digest, redacted_text, lease_id, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceID, string(config), c.RawDigest, c.RedactedDigest, c.RedactedText(), leaseID, obs, obs)
	if err != nil {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: insert config version of %s: %w", deviceID, err)
	}
	id, err = r.LastInsertId()
	if err != nil {
		return RecordConfigResult{}, fmt.Errorf("netdevinventory: config version id of %s: %w", deviceID, err)
	}
	if err := boundConfigVersions(ctx, tx, deviceID, now); err != nil {
		return RecordConfigResult{}, err
	}
	if err := s.touchDevice(ctx, tx, deviceID, obs, nowM); err != nil {
		return RecordConfigResult{}, err
	}
	return RecordConfigResult{VersionID: id, New: true}, nil
}

// boundConfigVersions enforces the count limit of Prune's
// pruneConfigVersions for deviceID inside tx, so RecordConfig keeps
// netdev_config_versions bounded after every new version whether or not
// Prune runs (as boundHistory does for ReplaceDataset). The limit is
// MaxConfigVersionsPerDevice over all configs of the device, as in Prune;
// protected versions (baseline, change-bound within ConfigVersionRetention,
// newest of each config) count against it but are never removed, and the
// oldest unprotected versions go first. Age is left to Prune: a version
// within the count limit cannot make the table grow without bound.
func boundConfigVersions(ctx context.Context, tx *sql.Tx, deviceID string, now time.Time) error {
	// The newest version of each config, looked up once on
	// idx_netdev_config_versions_seen instead of per row.
	newest := []any{int64(-1), int64(-1)}
	for i, c := range []ConfigKind{ConfigRunning, ConfigStartup} {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM netdev_config_versions WHERE device_id = ? AND config = ?
			ORDER BY last_seen DESC, id DESC LIMIT 1`, deviceID, string(c)).Scan(&id)
		switch {
		case err == nil:
			newest[i] = id
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("netdevinventory: load newest %s config version of %s: %w", c, deviceID, err)
		}
	}
	cutoff := micros(now.Add(-ConfigVersionRetention))
	if _, err := tx.ExecContext(ctx, `WITH
		p AS (SELECT id, last_seen, (baseline = 1 OR (change_bound_at IS NOT NULL AND change_bound_at >= ?)
			OR id IN (?, ?)) AS prot FROM netdev_config_versions WHERE device_id = ?),
		u AS (SELECT id, ROW_NUMBER() OVER (ORDER BY last_seen DESC, id DESC) AS rn FROM p WHERE prot = 0)
		DELETE FROM netdev_config_versions WHERE id IN (
			SELECT id FROM u WHERE rn > ? - (SELECT SUM(prot) FROM p))`,
		cutoff, newest[0], newest[1], deviceID, MaxConfigVersionsPerDevice); err != nil {
		return fmt.Errorf("netdevinventory: cap config versions of %s: %w", deviceID, err)
	}
	return nil
}

const configVersionCols = `id, device_id, config, raw_digest, redacted_digest, lease_id, first_seen, last_seen, baseline, change_bound_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanConfigVersion(r rowScanner, extra ...any) (ConfigVersion, error) {
	var v ConfigVersion
	var config string
	var first, last int64
	var baseline int
	var bound sql.NullInt64
	dest := append([]any{&v.ID, &v.DeviceID, &config, &v.RawDigest, &v.RedactedDigest, &v.LeaseID, &first, &last, &baseline, &bound}, extra...)
	if err := r.Scan(dest...); err != nil {
		return ConfigVersion{}, err
	}
	v.Config = ConfigKind(config)
	v.FirstSeen, v.LastSeen = fromMicros(first), fromMicros(last)
	v.Baseline = baseline == 1
	if bound.Valid {
		v.ChangeBoundAt = fromMicros(bound.Int64)
	}
	return v, nil
}

// ListConfigVersions returns the versions of (deviceID, config) without
// their text, current first (by last_seen, as ConfigChangedNotDisplayed
// orders them): the newest MaxListedConfigVersions, plus every version
// retention protects beyond them (the baseline and versions bound to a
// change within ConfigVersionRetention), so a version retention promises
// to keep never drops out of the list. Those are bounded by the count
// limit RecordConfig enforces on every write unless the protected versions
// alone exceed it.
func (s *Store) ListConfigVersions(ctx context.Context, deviceID string, config ConfigKind) ([]ConfigVersion, error) {
	if !validConfigKind(config) {
		return nil, ErrUnknownConfig
	}
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	cutoff := micros(s.now().Add(-ConfigVersionRetention))
	rs, err := s.db.QueryContext(ctx, `SELECT `+configVersionCols+` FROM netdev_config_versions
		WHERE device_id = ? AND config = ? AND (baseline = 1
			OR (change_bound_at IS NOT NULL AND change_bound_at >= ?)
			OR id IN (SELECT id FROM netdev_config_versions WHERE device_id = ? AND config = ?
				ORDER BY last_seen DESC, id DESC LIMIT ?))
		ORDER BY last_seen DESC, id DESC`,
		deviceID, string(config), cutoff, deviceID, string(config), MaxListedConfigVersions)
	if err != nil {
		return nil, fmt.Errorf("netdevinventory: list config versions of %s: %w", deviceID, err)
	}
	defer rs.Close()
	var out []ConfigVersion
	for rs.Next() {
		v, err := scanConfigVersion(rs)
		if err != nil {
			return nil, fmt.Errorf("netdevinventory: scan config version of %s: %w", deviceID, err)
		}
		out = append(out, v)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("netdevinventory: read config versions of %s: %w", deviceID, err)
	}
	return out, nil
}

// GetConfigVersion returns version id of deviceID with its redacted text.
// A version of another device is ErrConfigVersionNotFound.
func (s *Store) GetConfigVersion(ctx context.Context, deviceID string, id int64) (ConfigVersion, error) {
	v, text, err := s.getConfigVersion(ctx, deviceID, id)
	if err != nil {
		return ConfigVersion{}, err
	}
	v.Lines = strings.Split(text, "\n")
	return v, nil
}

func (s *Store) getConfigVersion(ctx context.Context, deviceID string, id int64) (ConfigVersion, string, error) {
	var text string
	v, err := scanConfigVersion(s.db.QueryRowContext(ctx, `SELECT `+configVersionCols+`, redacted_text
		FROM netdev_config_versions WHERE id = ? AND device_id = ?`, id, deviceID), &text)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigVersion{}, "", fmt.Errorf("netdevinventory: device %s version %d: %w", deviceID, id, ErrConfigVersionNotFound)
	}
	if err != nil {
		return ConfigVersion{}, "", fmt.Errorf("netdevinventory: load config version %d of %s: %w", id, deviceID, err)
	}
	return v, text, nil
}

// ConfigDiff is the diff of two config versions of one device.
type ConfigDiff struct {
	// From and To are the compared versions, without their text.
	From, To ConfigVersion
	// Lines is the edit script from From to To (textdiff: minimal up to
	// textdiff.MaxEdits, else a full replacement of the changed middle).
	Lines []textdiff.Line
	// Normalized is set when both sides are PAN-OS text rendered by
	// NormalizePANOSConfig; otherwise Lines compares the stored lines.
	Normalized bool
	// Changed is set when Lines has an insertion or deletion.
	Changed bool
	// NotDisplayed is set when the raw digests differ but Lines shows no
	// change: the configuration changed in elements not displayed (ADR
	// 0010 D4), or only in order or volatile attributes the PAN-OS
	// normalization drops.
	NotDisplayed bool
}

// DiffConfigVersions diffs version fromID against toID, both versions of
// deviceID (any config, so running can be compared with startup). CBS text
// is compared line by line as stored. PAN-OS text is normalized with
// NormalizePANOSConfig first; if either side cannot be normalized, both
// sides are compared as stored.
func (s *Store) DiffConfigVersions(ctx context.Context, deviceID string, fromID, toID int64) (ConfigDiff, error) {
	dev, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		return ConfigDiff{}, err
	}
	from, fromText, err := s.getConfigVersion(ctx, deviceID, fromID)
	if err != nil {
		return ConfigDiff{}, err
	}
	to, toText, err := s.getConfigVersion(ctx, deviceID, toID)
	if err != nil {
		return ConfigDiff{}, err
	}
	d := ConfigDiff{From: from, To: to}
	if dev.Family == netdevcontract.FamilyPANOS {
		a, okA := NormalizePANOSConfig(fromText)
		b, okB := NormalizePANOSConfig(toText)
		if okA && okB {
			fromText, toText = strings.Join(a, "\n"), strings.Join(b, "\n")
			d.Normalized = true
		}
	}
	// The stored text has no final newline; adding one keeps a trailing
	// empty line a line of its own in textdiff.Lines.
	d.Lines = textdiff.Diff(fromText+"\n", toText+"\n")
	d.Changed = textdiff.Changed(d.Lines)
	d.NotDisplayed = !d.Changed && from.RawDigest != to.RawDigest
	return d, nil
}

// orderedPANOSContainers are the PAN-OS elements whose children keep their
// document order in NormalizePANOSConfig, because the order is
// significant: rule order in a rulebase is the policy, the member order of
// IKE and IPsec crypto profiles (encryption, hash, dh-group,
// authentication) is the proposal preference, and an authentication
// sequence tries its profiles in order. Every other element's children are
// sorted. Keeping a non-significant order only adds diff lines; it never
// hides a change. The keys are local names and match whatever namespace
// the element is in.
var orderedPANOSContainers = map[string]bool{
	"rules":                   true,
	"encryption":              true,
	"hash":                    true,
	"dh-group":                true,
	"authentication":          true,
	"authentication-profiles": true,
}

// volatilePANOSAttrs are the attributes NormalizePANOSConfig drops: the
// PAN-OS change metadata (who changed an element, its dirty ID and change
// time), which differs between reads of an unchanged configuration. Only
// these exact names without a namespace are dropped; every other attribute,
// known or not, is rendered, so normalization never hides a change of an
// attribute it does not know.
var volatilePANOSAttrs = map[string]bool{"admin": true, "dirtyId": true, "time": true}

// leadingPANOSAttrs are rendered first, in this order: the identity of an
// element. The other attributes follow sorted by rendered key.
var leadingPANOSAttrs = [...]string{"name", "uuid"}

// panosAttr is one rendered attribute of a PAN-OS element.
type panosAttr struct {
	// key is the local name, prefixed with the Go-quoted namespace in
	// braces if the attribute has one.
	key   string
	value string
}

// panosNode is one element (or comment) of a parsed PAN-OS configuration.
type panosNode struct {
	// tag is the local name, prefixed with the Go-quoted namespace in
	// braces if the element has one.
	tag string
	// local is the local name alone, which orderedPANOSContainers is
	// matched on: a namespace (a default one on the root included) must not
	// make an order-significant container sorted.
	local string
	// attrs are the non-volatile attributes in rendering order.
	attrs    []panosAttr
	text     []byte
	comment  bool
	children []*panosNode
}

// panosName renders an XML name. The namespace is device text that
// encoding/xml may have resolved to an arbitrary URI, so it is Go-quoted;
// the local name is an XML name, which a strict decoder has checked holds
// no quote, space or newline.
func panosName(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return "{" + strconv.Quote(n.Space) + "}" + n.Local
}

func panosAttrRank(a panosAttr) int {
	if i := slices.Index(leadingPANOSAttrs[:], a.key); i >= 0 {
		return i
	}
	return len(leadingPANOSAttrs)
}

func comparePANOSAttrs(a, b panosAttr) int {
	if c := panosAttrRank(a) - panosAttrRank(b); c != 0 {
		return c
	}
	if c := strings.Compare(a.key, b.key); c != 0 {
		return c
	}
	return strings.Compare(a.value, b.value)
}

// NormalizePANOSConfig renders redacted PAN-OS XML text as one element per
// line for a readable diff (ADR 0010 D4): each line is the element name
// indented two spaces per depth, its attributes as quoted key
// "[name=… uuid=… loc=…]" (name and uuid first, the others sorted by key;
// a namespace is rendered as a quoted {"…"} prefix of the element or
// attribute name) and non-whitespace element text as a quoted " = …";
// comments become a quoted "# …" line. Only the attributes of
// volatilePANOSAttrs (PAN-OS change metadata: admin, dirtyId, time) are
// dropped. Children are sorted by element name, attributes and text, except
// under the elements of orderedPANOSContainers. All device text is
// Go-quoted, so a newline or quote in it cannot forge a line.
//
// The input must pass netdevcontract.CheckXML with MaxRedactedConfigBytes
// (depth, element, text limits, no DTD) and the rendered text must stay
// within MaxNormalizedConfigBytes and netdevcontract.MaxConfigLines lines
// (the line bound of a CBS config, so a diff costs no more than one of
// CBS); otherwise ok is false and the caller diffs the stored lines.
func NormalizePANOSConfig(text string) (lines []string, ok bool) {
	data := []byte(text)
	if netdevcontract.CheckXML(data, netdevcontract.MaxRedactedConfigBytes) != nil {
		return nil, false
	}
	roots, err := parsePANOS(data)
	if err != nil {
		return nil, false
	}
	r := panosRenderer{}
	for _, n := range sortedPANOS(roots, false) {
		if !r.render(n, 0) {
			return nil, false
		}
	}
	return r.lines, true
}

// parsePANOS builds the element tree of data, which CheckXML has bounded.
func parsePANOS(data []byte) ([]*panosNode, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.CharsetReader = func(label string, _ io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("netdevinventory: XML charset %q refused", label)
	}
	var roots []*panosNode
	var stack []*panosNode
	add := func(n *panosNode) {
		if len(stack) == 0 {
			roots = append(roots, n)
		} else {
			p := stack[len(stack)-1]
			p.children = append(p.children, n)
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &panosNode{tag: panosName(t.Name), local: t.Name.Local}
			for _, a := range t.Attr {
				if a.Name.Space == "" && volatilePANOSAttrs[a.Name.Local] {
					continue
				}
				n.attrs = append(n.attrs, panosAttr{key: panosName(a.Name), value: a.Value})
			}
			slices.SortFunc(n.attrs, comparePANOSAttrs)
			add(n)
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("netdevinventory: unbalanced XML")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.text = append(p.text, t...)
			}
		case xml.Comment:
			add(&panosNode{comment: true, text: bytes.Clone(t)})
		}
	}
	return roots, nil
}

// elementText is the element's text, or empty when it is only whitespace
// (indentation between child elements).
func (n *panosNode) elementText() string {
	if len(bytes.TrimSpace(n.text)) == 0 {
		return ""
	}
	return string(n.text)
}

func sortedPANOS(ns []*panosNode, ordered bool) []*panosNode {
	if ordered {
		return ns
	}
	out := slices.Clone(ns)
	slices.SortStableFunc(out, func(a, b *panosNode) int {
		if a.comment != b.comment {
			if a.comment {
				return 1
			}
			return -1
		}
		if c := strings.Compare(a.tag, b.tag); c != 0 {
			return c
		}
		if c := slices.CompareFunc(a.attrs, b.attrs, comparePANOSAttrs); c != 0 {
			return c
		}
		return strings.Compare(a.elementText(), b.elementText())
	})
	return out
}

type panosRenderer struct {
	lines []string
	bytes int
}

func (r *panosRenderer) render(n *panosNode, depth int) bool {
	var b strings.Builder
	b.WriteString(strings.Repeat("  ", depth))
	if n.comment {
		b.WriteString("# ")
		b.WriteString(strconv.Quote(string(n.text)))
	} else {
		b.WriteString(n.tag)
		sep := "["
		for _, a := range n.attrs {
			b.WriteString(sep + a.key + "=" + strconv.Quote(a.value))
			sep = " "
		}
		if sep == " " {
			b.WriteByte(']')
		}
		if t := n.elementText(); t != "" {
			b.WriteString(" = ")
			b.WriteString(strconv.Quote(t))
		}
	}
	r.bytes += b.Len() + 1
	if r.bytes > MaxNormalizedConfigBytes || len(r.lines) >= netdevcontract.MaxConfigLines {
		return false
	}
	r.lines = append(r.lines, b.String())
	for _, c := range sortedPANOS(n.children, orderedPANOSContainers[n.local]) {
		if !r.render(c, depth+1) {
			return false
		}
	}
	return true
}
