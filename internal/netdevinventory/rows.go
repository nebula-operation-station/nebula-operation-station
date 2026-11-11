// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// Rows is the payload of one read. The concrete types below are the only
// implementations.
type Rows interface {
	// Read names the read the rows belong to.
	Read() Read
	tableRows() ([]rowSet, error)
	payload() any
}

// FactsRows is the payload of a facts read.
type FactsRows struct{ Facts netdevcontract.Facts }

// PortRows is the payload of a CBS ports read.
type PortRows []netdevcontract.Port

// VLANRows is the payload of a CBS VLAN read.
type VLANRows []netdevcontract.VLAN

// MACRows is the payload of a CBS MAC table read.
type MACRows []netdevcontract.MACEntry

// LLDPRows is the payload of a CBS LLDP neighbor read.
type LLDPRows []netdevcontract.LLDPNeighbor

// PolicyRows is the payload of a PAN-OS firewall policy read.
type PolicyRows struct{ Policy netdevcontract.FirewallPolicy }

// HitCountRows is the payload of a PAN-OS hit count read.
type HitCountRows []netdevcontract.HitCount

// Read implements Rows.
func (FactsRows) Read() Read { return ReadFacts }

// Read implements Rows.
func (PortRows) Read() Read { return ReadPorts }

// Read implements Rows.
func (VLANRows) Read() Read { return ReadVLANs }

// Read implements Rows.
func (MACRows) Read() Read { return ReadMACTable }

// Read implements Rows.
func (LLDPRows) Read() Read { return ReadLLDPNeighbors }

// Read implements Rows.
func (PolicyRows) Read() Read { return ReadFirewallPolicy }

// Read implements Rows.
func (HitCountRows) Read() Read { return ReadHitCounts }

func (r FactsRows) payload() any    { return r.Facts }
func (r PortRows) payload() any     { return nonNil(r) }
func (r VLANRows) payload() any     { return nonNil(r) }
func (r MACRows) payload() any      { return nonNil(r) }
func (r LLDPRows) payload() any     { return nonNil(r) }
func (r PolicyRows) payload() any   { return r.Policy }
func (r HitCountRows) payload() any { return nonNil(normalizeHits(r)) }

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// normalizeHits returns the hit counts with their times in UTC at
// microsecond precision, the stored form, so the payload digest does not
// depend on the zone the caller used.
func normalizeHits(hs []netdevcontract.HitCount) []netdevcontract.HitCount {
	out := make([]netdevcontract.HitCount, len(hs))
	norm := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		v := fromMicros(micros(*t))
		return &v
	}
	for i, h := range hs {
		out[i] = h
		out[i].FirstHit = norm(h.FirstHit)
		out[i].LastHit = norm(h.LastHit)
		out[i].ResetAt = norm(h.ResetAt)
	}
	return out
}

// validateRows checks rows with the netdevcontract observation rules and
// limits, the same checks the executor and the collector apply.
func validateRows(deviceID string, family netdevcontract.Family, gen uint64, observedAt time.Time, incomplete bool, rows Rows) error {
	o := netdevcontract.Observation{
		DeviceID:        deviceID,
		Family:          family,
		TrustGeneration: gen,
		ObservedAt:      observedAt,
	}
	switch r := rows.(type) {
	case FactsRows:
		o.Facts = wrap(r.Facts, incomplete)
		if r.Facts.UptimeSeconds != nil && *r.Facts.UptimeSeconds > math.MaxInt64 {
			return fmt.Errorf("%w: uptime_seconds out of range", ErrInvalidRows)
		}
	case PortRows:
		o.Ports = wrap([]netdevcontract.Port(r), incomplete)
	case VLANRows:
		o.VLANs = wrap([]netdevcontract.VLAN(r), incomplete)
	case MACRows:
		o.MACTable = wrap([]netdevcontract.MACEntry(r), incomplete)
	case LLDPRows:
		o.LLDPNeighbors = wrap([]netdevcontract.LLDPNeighbor(r), incomplete)
	case PolicyRows:
		o.FirewallPolicy = wrap(r.Policy, incomplete)
	case HitCountRows:
		o.HitCounts = wrap([]netdevcontract.HitCount(r), incomplete)
		for i, h := range r {
			if h.Hits > math.MaxInt64 {
				return fmt.Errorf("%w: hit_counts %d: hits out of range", ErrInvalidRows, i)
			}
		}
	default:
		return ErrRowsMismatch
	}
	if _, err := netdevcontract.ValidateObservation(o); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRows, err)
	}
	return nil
}

func wrap[T any](v T, incomplete bool) *netdevcontract.Dataset[T] {
	if incomplete {
		return netdevcontract.IncompleteDataset(v)
	}
	return netdevcontract.AvailableDataset(v)
}

// payloadSHA256 is the lowercase hex SHA-256 of the JSON encoding of the
// normalized payload.
func payloadSHA256(rows Rows) (string, error) {
	b, err := encodeJSON(rows.payload())
	if err != nil {
		return "", fmt.Errorf("netdevinventory: encode payload: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// encodeJSON encodes v without HTML escaping, so device text is stored in
// list columns as it was read.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// jsonList renders a list column; a nil list is [].
func jsonList[T any](s []T) string {
	b, err := encodeJSON(nonNil(s))
	if err != nil {
		// Slices of strings and integers always encode.
		return "[]"
	}
	return string(b)
}

func jsonKey(parts ...string) string { return jsonList(parts) }

// table describes one typed row table.
type table struct {
	name string
	cols []string
	// carryCap bounds the rows carried over into one dataset, so absent
	// rows of a churning device cannot grow a dataset without bound. The
	// most recently seen rows are kept.
	carryCap int
}

var (
	tblFacts = &table{"netdev_facts", []string{"model", "firmware_version", "serial", "hostname",
		"uptime_seconds", "management_addresses"}, 1}
	tblVLANs      = &table{"netdev_vlans", []string{"vlan_id", "name"}, netdevcontract.MaxVLANsPerDevice}
	tblInterfaces = &table{"netdev_interfaces", []string{"kind", "name", "admin_state", "oper_state", "speed_mbps",
		"mode", "access_vlan", "native_vlan", "allowed_vlans", "description", "vlan_tag", "addresses", "zone"},
		max(netdevcontract.MaxInterfacesPerDevice, netdevcontract.MaxFirewallInterfaces)}
	tblMAC  = &table{"netdev_mac_entries", []string{"vlan", "mac", "port", "type"}, netdevcontract.MaxMACEntriesPerDevice}
	tblLLDP = &table{"netdev_lldp_neighbors", []string{"local_port", "chassis_id", "port_id", "system_name",
		"management_address", "capabilities"}, netdevcontract.MaxLLDPNeighborsPerDevice}
	tblFWRules = &table{"netdev_fw_rules", []string{"name", "uuid", "from_zones", "to_zones", "sources",
		"destinations", "source_users", "applications", "services", "categories", "action", "disabled",
		"description", "tags"}, netdevcontract.MaxSecurityRules}
	tblNATRules = &table{"netdev_nat_rules", []string{"name", "uuid", "from_zones", "to_zones", "sources",
		"destinations", "service", "source_translation", "destination_translation", "disabled", "description",
		"tags"}, netdevcontract.MaxNATRules}
	tblObjects = &table{"netdev_objects", []string{"kind", "name", "address_type", "value", "protocol", "port",
		"source_port", "static_members", "dynamic_filter", "interfaces", "description", "tags"},
		netdevcontract.MaxAddressObjects + netdevcontract.MaxAddressGroups + netdevcontract.MaxServiceObjects +
			netdevcontract.MaxServiceGroups + netdevcontract.MaxZones}
	tblHits = &table{"netdev_rule_hits", []string{"rule_name", "hits", "first_hit", "last_hit", "reset_at"},
		netdevcontract.MaxHitCountEntries}
)

// readTables lists the tables a read writes.
func readTables(r Read) []*table {
	switch r {
	case ReadFacts:
		return []*table{tblFacts}
	case ReadPorts:
		return []*table{tblInterfaces}
	case ReadVLANs:
		return []*table{tblVLANs}
	case ReadMACTable:
		return []*table{tblMAC}
	case ReadLLDPNeighbors:
		return []*table{tblLLDP}
	case ReadFirewallPolicy:
		return []*table{tblFWRules, tblNATRules, tblObjects, tblInterfaces}
	case ReadHitCounts:
		return []*table{tblHits}
	}
	return nil
}

// row is one typed row: its natural key and the values of table.cols.
type row struct {
	key  string
	vals []any
}

type rowSet struct {
	table *table
	rows  []row
}

func optU16(v *uint16) any {
	if v == nil {
		return nil
	}
	return int64(*v)
}

func optU64(v *uint64) any {
	if v == nil {
		return nil
	}
	return int64(*v) // range checked in validateRows or by the contract
}

func optTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return micros(*t)
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func (r FactsRows) tableRows() ([]rowSet, error) {
	f := r.Facts
	return []rowSet{{tblFacts, []row{{"facts", []any{f.Model, f.FirmwareVersion, f.Serial, f.Hostname,
		optU64(f.UptimeSeconds), jsonList(f.ManagementAddresses)}}}}}, nil
}

func (r PortRows) tableRows() ([]rowSet, error) {
	out := make([]row, len(r))
	for i, p := range r {
		out[i] = row{p.Name, []any{"port", p.Name, string(p.AdminState), string(p.OperState), optU64(p.SpeedMbps),
			string(p.Mode), optU16(p.AccessVLAN), optU16(p.NativeVLAN), jsonList(p.AllowedVLANs), p.Description,
			nil, "[]", ""}}
	}
	return []rowSet{{tblInterfaces, out}}, nil
}

func (r VLANRows) tableRows() ([]rowSet, error) {
	out := make([]row, len(r))
	for i, v := range r {
		out[i] = row{strconv.Itoa(int(v.ID)), []any{int64(v.ID), v.Name}}
	}
	return []rowSet{{tblVLANs, out}}, nil
}

func (r MACRows) tableRows() ([]rowSet, error) {
	out := make([]row, len(r))
	for i, e := range r {
		out[i] = row{strconv.Itoa(int(e.VLAN)) + "/" + e.MAC, []any{int64(e.VLAN), e.MAC, e.Port, string(e.Type)}}
	}
	return []rowSet{{tblMAC, out}}, nil
}

func (r LLDPRows) tableRows() ([]rowSet, error) {
	out := make([]row, len(r))
	for i, n := range r {
		caps := make([]string, len(n.Capabilities))
		for j, c := range n.Capabilities {
			caps[j] = string(c)
		}
		out[i] = row{jsonKey(n.LocalPort, n.ChassisID, n.PortID), []any{n.LocalPort, n.ChassisID, n.PortID,
			n.SystemName, n.ManagementAddress, jsonList(caps)}}
	}
	return []rowSet{{tblLLDP, out}}, nil
}

func (r PolicyRows) tableRows() ([]rowSet, error) {
	p := r.Policy
	rules := make([]row, len(p.SecurityRules))
	for i, x := range p.SecurityRules {
		rules[i] = row{x.Name, []any{x.Name, x.UUID, jsonList(x.From), jsonList(x.To), jsonList(x.Source),
			jsonList(x.Destination), jsonList(x.SourceUser), jsonList(x.Application), jsonList(x.Service),
			jsonList(x.Category), string(x.Action), boolInt(x.Disabled), x.Description, jsonList(x.Tags)}}
	}
	nat := make([]row, len(p.NATRules))
	for i, x := range p.NATRules {
		nat[i] = row{x.Name, []any{x.Name, x.UUID, jsonList(x.From), jsonList(x.To), jsonList(x.Source),
			jsonList(x.Destination), x.Service, x.SourceTranslation, x.DestinationTranslation, boolInt(x.Disabled),
			x.Description, jsonList(x.Tags)}}
	}
	var objs []row
	obj := func(kind, name string, addrType any, value, proto, port, srcPort string, static []string,
		filter string, ifs []string, desc string, tags []string) {
		objs = append(objs, row{jsonKey(kind, name), []any{kind, name, addrType, value, proto, port, srcPort,
			jsonList(static), filter, jsonList(ifs), desc, jsonList(tags)}})
	}
	for _, a := range p.Addresses {
		obj("address", a.Name, string(a.Type), a.Value, "", "", "", nil, "", nil, a.Description, a.Tags)
	}
	for _, g := range p.AddressGroups {
		obj("address_group", g.Name, nil, "", "", "", "", g.Static, g.DynamicFilter, nil, g.Description, g.Tags)
	}
	for _, s := range p.Services {
		obj("service", s.Name, nil, "", s.Protocol, s.Port, s.SourcePort, nil, "", nil, s.Description, s.Tags)
	}
	for _, g := range p.ServiceGroups {
		obj("service_group", g.Name, nil, "", "", "", "", g.Static, "", nil, g.Description, g.Tags)
	}
	for _, z := range p.Zones {
		obj("zone", z.Name, nil, "", "", "", "", nil, "", z.Interfaces, "", nil)
	}
	ifs := make([]row, len(p.Interfaces))
	for i, x := range p.Interfaces {
		ifs[i] = row{x.Name, []any{"firewall", x.Name, nil, nil, nil, nil, nil, nil, "[]", "",
			optU16(x.VLANTag), jsonList(x.Addresses), x.Zone}}
	}
	return []rowSet{{tblFWRules, rules}, {tblNATRules, nat}, {tblObjects, objs}, {tblInterfaces, ifs}}, nil
}

func (r HitCountRows) tableRows() ([]rowSet, error) {
	out := make([]row, len(r))
	for i, h := range r {
		if h.Hits > math.MaxInt64 {
			return nil, fmt.Errorf("%w: hit_counts %d: hits out of range", ErrInvalidRows, i)
		}
		out[i] = row{h.RuleName, []any{h.RuleName, int64(h.Hits), optTime(h.FirstHit), optTime(h.LastHit),
			optTime(h.ResetAt)}}
	}
	return []rowSet{{tblHits, out}}, nil
}

// insertRows writes the rows of one read into its dataset. A natural key
// that repeats within one read (possible for LLDP, whose triple is not
// unique by contract) gets an occurrence suffix "#n" so no row is lost;
// no natural key can contain '#' or end a JSON array before it.
func insertRows(ctx context.Context, tx *sql.Tx, datasetID int64, set rowSet) error {
	if len(set.rows) == 0 {
		return nil
	}
	t := set.table
	q := "INSERT INTO " + t.name + " (dataset_id, row_key, seq, seen_at, absent, " + strings.Join(t.cols, ", ") +
		") VALUES (?, ?, ?, NULL, 0" + strings.Repeat(", ?", len(t.cols)) + ")"
	stmt, err := tx.PrepareContext(ctx, q)
	if err != nil {
		return fmt.Errorf("netdevinventory: prepare %s: %w", t.name, err)
	}
	defer stmt.Close()
	seen := make(map[string]int, len(set.rows))
	args := make([]any, 0, 3+len(t.cols))
	for i, r := range set.rows {
		key := r.key
		if n := seen[r.key]; n > 0 {
			key = r.key + "#" + strconv.Itoa(n+1)
		}
		seen[r.key]++
		args = append(args[:0], datasetID, key, int64(i))
		args = append(args, r.vals...)
		if _, err := stmt.ExecContext(ctx, args...); err != nil {
			return fmt.Errorf("netdevinventory: insert %s row %d: %w", t.name, i, err)
		}
	}
	return nil
}

// carryOver copies the rows of the previous dataset that the new one does
// not contain. After a complete read they are absent; after a partial read
// they keep their absent flag. A carried row keeps the time it was last
// seen (the previous dataset's observed_at for a row present there). Rows
// last seen before cutoff have passed retention and are not carried; at
// most t.carryCap rows, the most recently seen, are carried.
func carryOver(ctx context.Context, tx *sql.Tx, t *table, prevID, prevObs, newID int64, complete bool, cutoff int64) (int, error) {
	cols := strings.Join(t.cols, ", ")
	absent := "absent"
	if complete {
		absent = "1"
	}
	q := "INSERT INTO " + t.name + " (dataset_id, row_key, seq, seen_at, absent, " + cols + ")" +
		" SELECT ?, row_key, NULL, COALESCE(seen_at, ?), " + absent + ", " + cols +
		" FROM " + t.name + " WHERE dataset_id = ?" +
		" AND row_key NOT IN (SELECT row_key FROM " + t.name + " WHERE dataset_id = ?)" +
		" AND COALESCE(seen_at, ?) >= ?" +
		" ORDER BY COALESCE(seen_at, ?) DESC, row_key LIMIT ?"
	res, err := tx.ExecContext(ctx, q, newID, prevObs, prevID, newID, prevObs, cutoff, prevObs, t.carryCap)
	if err != nil {
		return 0, fmt.Errorf("netdevinventory: carry over %s: %w", t.name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("netdevinventory: carry over %s: %w", t.name, err)
	}
	return int(n), nil
}
