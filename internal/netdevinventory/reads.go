// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// MaxListDevices bounds the devices one ListDevices call returns.
const MaxListDevices = 1000

// deviceSelect lists the columns scanDevice reads, in order.
const deviceSelect = `SELECT device_id, family, label, trust_generation, last_seen, state, created_at,
	origin, spool_name, spool_sha256, reported_at FROM netdev_devices_seen`

// ListDevices returns at most limit devices in device ID order. limit must be
// between 1 and MaxListDevices. Each device is returned with the same state
// rules as GetDevice.
func (s *Store) ListDevices(ctx context.Context, limit int) ([]Device, error) {
	if limit < 1 || limit > MaxListDevices {
		return nil, fmt.Errorf("netdevinventory: list devices: limit %d outside 1..%d", limit, MaxListDevices)
	}
	rs, err := s.db.QueryContext(ctx, deviceSelect+` ORDER BY device_id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("netdevinventory: list devices: %w", err)
	}
	defer rs.Close()
	now := s.now()
	var out []Device
	for rs.Next() {
		d, err := scanDevice(rs, now)
		if err != nil {
			return nil, fmt.Errorf("netdevinventory: scan device: %w", err)
		}
		out = append(out, d)
	}
	if err := rs.Err(); err != nil {
		return nil, fmt.Errorf("netdevinventory: list devices: %w", err)
	}
	return out, nil
}

// beginCurrent opens the read transaction of one device read and finds the
// ID of its current dataset. Reads of one device run in one transaction, so
// a replacement between two queries cannot show a mix of two datasets. It
// returns ErrDatasetNotFound, with the transaction already closed, when no
// dataset is stored. The caller must roll the transaction back when it is
// done (a no-op after commit).
func (s *Store) beginCurrent(ctx context.Context, deviceID string, read Read) (*sql.Tx, int64, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("netdevinventory: begin %s read: %w", read, err)
	}
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM netdev_datasets
		WHERE device_id = ? AND read = ? AND current = 1`, deviceID, string(read)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return nil, 0, ErrDatasetNotFound
	}
	if err != nil {
		_ = tx.Rollback()
		return nil, 0, fmt.Errorf("netdevinventory: load current %s dataset: %w", read, err)
	}
	return tx, id, nil
}

// listRows lists the present rows of dataset id in t that match where (an
// extra SQL condition on t, with its arguments; "" for none). Present rows
// are the rows the latest read contained and the ones an incomplete read
// carried over; absent rows are left out. Rows come in stored order (seq,
// with carried rows, which have no seq, last). It returns at most limit rows
// from offset and the number of present rows that match.
func listRows[T any](ctx context.Context, tx *sql.Tx, t *table, cols string, id int64, where string, args []any,
	offset, limit int, scan func(rowScanner) (T, error)) ([]T, int, error) {
	cond := " WHERE dataset_id = ? AND absent = 0"
	if where != "" {
		cond += " AND " + where
	}
	base := append([]any{id}, args...)
	var total int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+t.name+cond, base...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("netdevinventory: count %s rows: %w", t.name, err)
	}
	q := "SELECT " + cols + " FROM " + t.name + cond + " ORDER BY seq IS NULL, seq, row_key LIMIT ? OFFSET ?"
	rs, err := tx.QueryContext(ctx, q, append(base, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("netdevinventory: list %s rows: %w", t.name, err)
	}
	defer rs.Close()
	var out []T
	for rs.Next() {
		v, err := scan(rs)
		if err != nil {
			return nil, 0, fmt.Errorf("netdevinventory: scan %s row: %w", t.name, err)
		}
		out = append(out, v)
	}
	if err := rs.Err(); err != nil {
		return nil, 0, fmt.Errorf("netdevinventory: list %s rows: %w", t.name, err)
	}
	return out, total, nil
}

// listAll is listRows for the reads that return a whole table: at most limit
// rows, none from an offset. Rows beyond limit are not returned. Stored rows
// are validated against the contract maximum on write, so only carried rows
// of an incomplete read can exceed it.
func listAll[T any](ctx context.Context, tx *sql.Tx, t *table, cols string, id int64, where string, args []any,
	limit int, scan func(rowScanner) (T, error)) ([]T, error) {
	out, _, err := listRows(ctx, tx, t, cols, id, where, args, 0, limit, scan)
	return out, err
}

// vlanOf converts a stored VLAN number. A NULL is no VLAN (nil, no error); a
// value outside uint16 is refused.
func vlanOf(v sql.NullInt64) (*uint16, error) {
	if !v.Valid {
		return nil, nil
	}
	if v.Int64 < 0 || v.Int64 > math.MaxUint16 {
		return nil, fmt.Errorf("netdevinventory: stored vlan %d out of range", v.Int64)
	}
	u := uint16(v.Int64)
	return &u, nil
}

// decodeStrings decodes a stored JSON list of strings. An empty column is
// no list.
func decodeStrings(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("netdevinventory: stored list: %w", err)
	}
	return out, nil
}

// Facts returns the current device facts. It returns ErrDatasetNotFound when
// no facts are stored.
func (s *Store) Facts(ctx context.Context, deviceID string) (netdevcontract.Facts, error) {
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadFacts)
	if err != nil {
		return netdevcontract.Facts{}, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, _, err := listRows(ctx, tx, tblFacts, strings.Join(tblFacts.cols, ", "), id, "", nil, 0, 1,
		func(sc rowScanner) (netdevcontract.Facts, error) {
			var f netdevcontract.Facts
			var uptime sql.NullInt64
			var addrs string
			if err := sc.Scan(&f.Model, &f.FirmwareVersion, &f.Serial, &f.Hostname, &uptime, &addrs); err != nil {
				return netdevcontract.Facts{}, err
			}
			if uptime.Valid {
				if uptime.Int64 < 0 {
					return netdevcontract.Facts{}, fmt.Errorf("netdevinventory: stored uptime %d out of range", uptime.Int64)
				}
				u := uint64(uptime.Int64)
				f.UptimeSeconds = &u
			}
			list, err := decodeStrings(addrs)
			f.ManagementAddresses = list
			return f, err
		})
	if err != nil {
		return netdevcontract.Facts{}, err
	}
	if len(rows) == 0 {
		return netdevcontract.Facts{}, fmt.Errorf("netdevinventory: facts of %s: current dataset has no row", deviceID)
	}
	return rows[0], nil
}

// VLANs returns the current VLAN list of a CBS device, at most
// netdevcontract.MaxVLANsPerDevice entries. ErrDatasetNotFound when none is
// stored.
func (s *Store) VLANs(ctx context.Context, deviceID string) ([]netdevcontract.VLAN, error) {
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadVLANs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return listAll(ctx, tx, tblVLANs, "vlan_id, name", id, "", nil, netdevcontract.MaxVLANsPerDevice,
		func(sc rowScanner) (netdevcontract.VLAN, error) {
			var vlan sql.NullInt64
			var v netdevcontract.VLAN
			if err := sc.Scan(&vlan, &v.Name); err != nil {
				return netdevcontract.VLAN{}, err
			}
			p, err := vlanOf(vlan)
			if err != nil {
				return netdevcontract.VLAN{}, err
			}
			if p == nil {
				return netdevcontract.VLAN{}, errors.New("netdevinventory: stored vlan without id")
			}
			v.ID = *p
			return v, nil
		})
}

// Ports returns the current switch ports of a CBS device, at most
// netdevcontract.MaxInterfacesPerDevice entries. ErrDatasetNotFound when none
// is stored.
func (s *Store) Ports(ctx context.Context, deviceID string) ([]netdevcontract.Port, error) {
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadPorts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return listAll(ctx, tx, tblInterfaces,
		"name, admin_state, oper_state, speed_mbps, mode, access_vlan, native_vlan, allowed_vlans, description",
		id, "kind = 'port'", nil, netdevcontract.MaxInterfacesPerDevice,
		func(sc rowScanner) (netdevcontract.Port, error) {
			var p netdevcontract.Port
			var admin, oper, mode, allowed string
			var speed, access, native sql.NullInt64
			if err := sc.Scan(&p.Name, &admin, &oper, &speed, &mode, &access, &native, &allowed, &p.Description); err != nil {
				return netdevcontract.Port{}, err
			}
			p.AdminState = netdevcontract.LinkState(admin)
			p.OperState = netdevcontract.LinkState(oper)
			p.Mode = netdevcontract.PortMode(mode)
			if speed.Valid {
				if speed.Int64 < 0 {
					return netdevcontract.Port{}, fmt.Errorf("netdevinventory: stored speed %d out of range", speed.Int64)
				}
				u := uint64(speed.Int64)
				p.SpeedMbps = &u
			}
			var err error
			if p.AccessVLAN, err = vlanOf(access); err != nil {
				return netdevcontract.Port{}, err
			}
			if p.NativeVLAN, err = vlanOf(native); err != nil {
				return netdevcontract.Port{}, err
			}
			if allowed != "" {
				if err := json.Unmarshal([]byte(allowed), &p.AllowedVLANs); err != nil {
					return netdevcontract.Port{}, fmt.Errorf("netdevinventory: stored allowed vlans: %w", err)
				}
			}
			return p, nil
		})
}

// HitCounts returns the current rule hit counts of a PAN-OS device in stored
// order, at most netdevcontract.MaxHitCountEntries entries. Times are in UTC;
// a time the device did not report is nil. ErrDatasetNotFound when none is
// stored.
func (s *Store) HitCounts(ctx context.Context, deviceID string) ([]netdevcontract.HitCount, error) {
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadHitCounts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return listAll(ctx, tx, tblHits, "rule_name, hits, first_hit, last_hit, reset_at", id, "", nil,
		netdevcontract.MaxHitCountEntries,
		func(sc rowScanner) (netdevcontract.HitCount, error) {
			var h netdevcontract.HitCount
			var hits int64
			var first, last, reset sql.NullInt64
			if err := sc.Scan(&h.RuleName, &hits, &first, &last, &reset); err != nil {
				return netdevcontract.HitCount{}, err
			}
			if hits < 0 {
				return netdevcontract.HitCount{}, fmt.Errorf("netdevinventory: stored hits %d out of range", hits)
			}
			h.Hits = uint64(hits)
			h.FirstHit = optFromMicros(first)
			h.LastHit = optFromMicros(last)
			h.ResetAt = optFromMicros(reset)
			return h, nil
		})
}

// optFromMicros converts a nullable stored time; NULL is nil.
func optFromMicros(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromMicros(v.Int64)
	return &t
}

// MACEntries returns the MAC table entries of a CBS device from offset, in
// stored order, at most limit of them, and the total number of entries. offset
// must not be negative and limit must be between 1 and
// netdevcontract.MaxMACEntriesPerDevice. ErrDatasetNotFound when none is
// stored.
func (s *Store) MACEntries(ctx context.Context, deviceID string, offset, limit int) ([]netdevcontract.MACEntry, int, error) {
	if offset < 0 || limit < 1 || limit > netdevcontract.MaxMACEntriesPerDevice {
		return nil, 0, fmt.Errorf("netdevinventory: mac entries: offset %d or limit %d out of range", offset, limit)
	}
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadMACTable)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	return listRows(ctx, tx, tblMAC, "vlan, mac, port, type", id, "", nil, offset, limit,
		func(sc rowScanner) (netdevcontract.MACEntry, error) {
			var vlan sql.NullInt64
			var e netdevcontract.MACEntry
			var typ string
			if err := sc.Scan(&vlan, &e.MAC, &e.Port, &typ); err != nil {
				return netdevcontract.MACEntry{}, err
			}
			p, err := vlanOf(vlan)
			if err != nil {
				return netdevcontract.MACEntry{}, err
			}
			if p == nil {
				return netdevcontract.MACEntry{}, errors.New("netdevinventory: stored mac entry without vlan")
			}
			e.VLAN = *p
			e.Type = netdevcontract.MACType(typ)
			return e, nil
		})
}

// LLDPNeighbors returns the current LLDP neighbors of a CBS device, at most
// netdevcontract.MaxLLDPNeighborsPerDevice entries. ErrDatasetNotFound when
// none is stored.
func (s *Store) LLDPNeighbors(ctx context.Context, deviceID string) ([]netdevcontract.LLDPNeighbor, error) {
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadLLDPNeighbors)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	return listAll(ctx, tx, tblLLDP,
		"local_port, chassis_id, port_id, system_name, management_address, capabilities",
		id, "", nil, netdevcontract.MaxLLDPNeighborsPerDevice,
		func(sc rowScanner) (netdevcontract.LLDPNeighbor, error) {
			var n netdevcontract.LLDPNeighbor
			var caps string
			if err := sc.Scan(&n.LocalPort, &n.ChassisID, &n.PortID, &n.SystemName, &n.ManagementAddress, &caps); err != nil {
				return netdevcontract.LLDPNeighbor{}, err
			}
			names, err := decodeStrings(caps)
			if err != nil {
				return netdevcontract.LLDPNeighbor{}, err
			}
			for _, c := range names {
				n.Capabilities = append(n.Capabilities, netdevcontract.LLDPCapability(c))
			}
			return n, nil
		})
}

// FirewallPolicy returns the current PAN-OS policy of a device: its security
// rules and NAT rules in stored order, its address and service objects and
// groups, zones and interfaces, each cut at the contract maximum of its kind.
// ErrDatasetNotFound when none is stored.
func (s *Store) FirewallPolicy(ctx context.Context, deviceID string) (netdevcontract.FirewallPolicy, error) {
	tx, id, err := s.beginCurrent(ctx, deviceID, ReadFirewallPolicy)
	if err != nil {
		return netdevcontract.FirewallPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var p netdevcontract.FirewallPolicy
	if p.SecurityRules, err = listAll(ctx, tx, tblFWRules, fwRuleCols, id, "", nil,
		netdevcontract.MaxSecurityRules, scanSecurityRule); err != nil {
		return netdevcontract.FirewallPolicy{}, err
	}
	if p.NATRules, err = listAll(ctx, tx, tblNATRules, natRuleCols, id, "", nil,
		netdevcontract.MaxNATRules, scanNATRule); err != nil {
		return netdevcontract.FirewallPolicy{}, err
	}
	if err := listObjects(ctx, tx, id, &p); err != nil {
		return netdevcontract.FirewallPolicy{}, err
	}
	if p.Interfaces, err = listAll(ctx, tx, tblInterfaces, "name, vlan_tag, addresses, zone", id,
		"kind = 'firewall'", nil, netdevcontract.MaxFirewallInterfaces, scanFirewallInterface); err != nil {
		return netdevcontract.FirewallPolicy{}, err
	}
	return p, nil
}

// policyObjectKinds lists the stored object kinds of the objects table with
// the contract maximum of each. Each kind is cut at its own maximum, so a
// kind cannot push another out of the policy.
var policyObjectKinds = []struct {
	kind string
	max  int
}{
	{"address", netdevcontract.MaxAddressObjects},
	{"address_group", netdevcontract.MaxAddressGroups},
	{"service", netdevcontract.MaxServiceObjects},
	{"service_group", netdevcontract.MaxServiceGroups},
	{"zone", netdevcontract.MaxZones},
}

const (
	fwRuleCols = "name, uuid, from_zones, to_zones, sources, destinations, source_users, applications, services, " +
		"categories, action, disabled, description, tags"
	natRuleCols = "name, uuid, from_zones, to_zones, sources, destinations, service, source_translation, " +
		"destination_translation, disabled, description, tags"
	objectCols = "kind, name, address_type, value, protocol, port, source_port, static_members, dynamic_filter, " +
		"interfaces, description, tags"
)

// scanLists decodes the stored list columns cols into the matching dst.
func scanLists(dst []*[]string, cols []string) error {
	for i, c := range cols {
		l, err := decodeStrings(c)
		if err != nil {
			return err
		}
		*dst[i] = l
	}
	return nil
}

func scanSecurityRule(sc rowScanner) (netdevcontract.SecurityRule, error) {
	var r netdevcontract.SecurityRule
	var from, to, src, dst, users, apps, svcs, cats, tags string
	var action string
	var disabled int64
	if err := sc.Scan(&r.Name, &r.UUID, &from, &to, &src, &dst, &users, &apps, &svcs, &cats,
		&action, &disabled, &r.Description, &tags); err != nil {
		return netdevcontract.SecurityRule{}, err
	}
	r.Action = netdevcontract.RuleAction(action)
	r.Disabled = disabled != 0
	err := scanLists([]*[]string{&r.From, &r.To, &r.Source, &r.Destination, &r.SourceUser, &r.Application,
		&r.Service, &r.Category, &r.Tags}, []string{from, to, src, dst, users, apps, svcs, cats, tags})
	return r, err
}

func scanNATRule(sc rowScanner) (netdevcontract.NATRule, error) {
	var r netdevcontract.NATRule
	var from, to, src, dst, tags string
	var disabled int64
	if err := sc.Scan(&r.Name, &r.UUID, &from, &to, &src, &dst, &r.Service, &r.SourceTranslation,
		&r.DestinationTranslation, &disabled, &r.Description, &tags); err != nil {
		return netdevcontract.NATRule{}, err
	}
	r.Disabled = disabled != 0
	err := scanLists([]*[]string{&r.From, &r.To, &r.Source, &r.Destination, &r.Tags},
		[]string{from, to, src, dst, tags})
	return r, err
}

func scanFirewallInterface(sc rowScanner) (netdevcontract.FirewallInterface, error) {
	var f netdevcontract.FirewallInterface
	var tag sql.NullInt64
	var addrs string
	if err := sc.Scan(&f.Name, &tag, &addrs, &f.Zone); err != nil {
		return netdevcontract.FirewallInterface{}, err
	}
	var err error
	if f.VLANTag, err = vlanOf(tag); err != nil {
		return netdevcontract.FirewallInterface{}, err
	}
	err = scanLists([]*[]string{&f.Addresses}, []string{addrs})
	return f, err
}

// policyObject is one stored row of the objects table.
type policyObject struct {
	kind, name, addrType, value, proto, port, srcPort string
	static, interfaces, tags                          []string
	filter, desc                                      string
}

func scanPolicyObject(sc rowScanner) (policyObject, error) {
	var o policyObject
	var addrType sql.NullString
	var static, ifs, tags string
	if err := sc.Scan(&o.kind, &o.name, &addrType, &o.value, &o.proto, &o.port, &o.srcPort,
		&static, &o.filter, &ifs, &o.desc, &tags); err != nil {
		return policyObject{}, err
	}
	o.addrType = addrType.String
	err := scanLists([]*[]string{&o.static, &o.interfaces, &o.tags}, []string{static, ifs, tags})
	return o, err
}

// listObjects reads the address and service objects, groups and zones of the
// policy into p, split by their stored kind. Each kind is read with its own
// contract maximum. A row of an unknown kind is refused, not dropped.
func listObjects(ctx context.Context, tx *sql.Tx, id int64, p *netdevcontract.FirewallPolicy) error {
	var unknown string
	err := tx.QueryRowContext(ctx, `SELECT kind FROM netdev_objects WHERE dataset_id = ? AND absent = 0
		AND kind NOT IN ('address', 'address_group', 'service', 'service_group', 'zone') LIMIT 1`, id).Scan(&unknown)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("netdevinventory: check object kinds: %w", err)
	default:
		return fmt.Errorf("netdevinventory: stored object kind %q unknown", unknown)
	}
	for _, k := range policyObjectKinds {
		objs, err := listAll(ctx, tx, tblObjects, objectCols, id, "kind = ?", []any{k.kind}, k.max,
			scanPolicyObject)
		if err != nil {
			return err
		}
		for _, o := range objs {
			appendPolicyObject(p, o)
		}
	}
	return nil
}

// appendPolicyObject adds one object to the list of its kind.
func appendPolicyObject(p *netdevcontract.FirewallPolicy, o policyObject) {
	switch o.kind {
	case "address":
		p.Addresses = append(p.Addresses, netdevcontract.AddressObject{Name: o.name,
			Type: netdevcontract.AddressType(o.addrType), Value: o.value, Description: o.desc, Tags: o.tags})
	case "address_group":
		p.AddressGroups = append(p.AddressGroups, netdevcontract.Group{Name: o.name, Static: o.static,
			DynamicFilter: o.filter, Description: o.desc, Tags: o.tags})
	case "service":
		p.Services = append(p.Services, netdevcontract.ServiceObject{Name: o.name, Protocol: o.proto,
			Port: o.port, SourcePort: o.srcPort, Description: o.desc, Tags: o.tags})
	case "service_group":
		p.ServiceGroups = append(p.ServiceGroups, netdevcontract.Group{Name: o.name, Static: o.static,
			DynamicFilter: o.filter, Description: o.desc, Tags: o.tags})
	case "zone":
		p.Zones = append(p.Zones, netdevcontract.Zone{Name: o.name, Interfaces: o.interfaces})
	}
}
