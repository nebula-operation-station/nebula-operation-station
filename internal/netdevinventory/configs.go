// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

// Config versions and diffs (ADR 0010 D4 "Config versions, diff and
// drift", plan ND-17 part 1). The executor returns each configuration read
// as redacted text with a keyed raw_digest; the server stores one version
// per distinct raw_digest of a (device, config) and only advances
// last_seen on an identical read. Diffs between two versions run
// internal/textdiff over the redacted text; a PAN-OS configuration is
// normalized first (one element per line, stable sibling order outside the
// rulebase, volatile attributes dropped) so the diff is readable. Retention
// is Prune's (retention.go); the baseline flag and change binding are set
// by the executor-mirroring code of ND-17 part 2 and never by a read.
//
// Every stored line is device text: validated with the netdevcontract
// limits, stored verbatim and rendered as text only.

import (
	"bytes"
	"cmp"
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
	if err := s.touchDevice(ctx, tx, deviceID, obs, nowM); err != nil {
		return RecordConfigResult{}, err
	}
	return RecordConfigResult{VersionID: id, New: true}, nil
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
// orders them), at most MaxListedConfigVersions.
func (s *Store) ListConfigVersions(ctx context.Context, deviceID string, config ConfigKind) ([]ConfigVersion, error) {
	if !validConfigKind(config) {
		return nil, ErrUnknownConfig
	}
	if _, err := s.GetDevice(ctx, deviceID); err != nil {
		return nil, err
	}
	rs, err := s.db.QueryContext(ctx, `SELECT `+configVersionCols+` FROM netdev_config_versions
		WHERE device_id = ? AND config = ? ORDER BY last_seen DESC, id DESC LIMIT ?`,
		deviceID, string(config), MaxListedConfigVersions)
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
// document order in NormalizePANOSConfig: rule order in a rulebase is the
// policy. Every other element's children are sorted.
var orderedPANOSContainers = map[string]bool{"rules": true}

// panosNode is one element (or comment) of a parsed PAN-OS configuration.
type panosNode struct {
	tag, name, uuid string
	text            []byte
	comment         bool
	children        []*panosNode
}

// NormalizePANOSConfig renders redacted PAN-OS XML text as one element per
// line for a readable diff (ADR 0010 D4): each line is the element name
// indented two spaces per depth, the name and uuid attributes as quoted
// key "[name=… uuid=…]" and non-whitespace element text as a quoted
// " = …"; comments become a quoted "# …" line. Other attributes (PAN-OS
// change metadata such as admin, dirtyId and time) are dropped. Children
// are sorted by element name, name attribute and text, except under the
// elements of orderedPANOSContainers. All device text is Go-quoted, so a
// newline or quote in it cannot forge a line.
//
// The input must pass netdevcontract.CheckXML with MaxRedactedConfigBytes
// (depth, element, text limits, no DTD) and the rendered text must stay
// within MaxNormalizedConfigBytes; otherwise ok is false and the caller
// diffs the stored lines.
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
			n := &panosNode{tag: t.Name.Local}
			for _, a := range t.Attr {
				switch {
				case a.Name.Space != "":
				case a.Name.Local == "name":
					n.name = a.Value
				case a.Name.Local == "uuid":
					n.uuid = a.Value
				}
			}
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
		return cmp.Or(strings.Compare(a.tag, b.tag), strings.Compare(a.name, b.name),
			strings.Compare(a.uuid, b.uuid), strings.Compare(a.elementText(), b.elementText()))
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
		if n.name != "" || n.uuid != "" {
			b.WriteByte('[')
			sep := ""
			if n.name != "" {
				b.WriteString("name=" + strconv.Quote(n.name))
				sep = " "
			}
			if n.uuid != "" {
				b.WriteString(sep + "uuid=" + strconv.Quote(n.uuid))
			}
			b.WriteByte(']')
		}
		if t := n.elementText(); t != "" {
			b.WriteString(" = ")
			b.WriteString(strconv.Quote(t))
		}
	}
	r.bytes += b.Len() + 1
	if r.bytes > MaxNormalizedConfigBytes {
		return false
	}
	r.lines = append(r.lines, b.String())
	for _, c := range sortedPANOS(n.children, orderedPANOSContainers[n.tag]) {
		if !r.render(c, depth+1) {
			return false
		}
	}
	return true
}
