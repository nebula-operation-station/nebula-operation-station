// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// spoolJSON encodes msg the way the collector spools it.
func spoolJSON(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func u32p(v uint32) *uint32 { return &v }
func u64p(v uint64) *uint64 { return &v }
func i64p(v int64) *int64   { return &v }
func u16p(v uint16) *uint16 { return &v }

type ingestCase struct {
	name   string
	read   pb.NetDeviceRead
	msg    proto.Message
	device string
	want   Rows
}

func ingestCases() []ingestCase {
	first := time.Unix(1_700_000_000, 0).UTC()
	last := time.Unix(1_700_000_600, 0).UTC()
	return []ingestCase{
		{"cbs_version", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION,
			&pb.NetDevCBSVersion{Model: "CBS350-24P", Firmware: "3.4.0.17", Serial: "PSZ1234"}, "sw-core",
			FactsRows{Facts: netdevcontract.Facts{Model: "CBS350-24P", FirmwareVersion: "3.4.0.17", Serial: "PSZ1234"}}},
		{"cbs_vlans", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS,
			&pb.NetDevVLANs{Vlans: []*pb.NetDevVLAN{{Id: 1, Name: "default"}, {Id: 20, Name: "<lab>"}}}, "sw-core",
			VLANRows{{ID: 1, Name: "default"}, {ID: 20, Name: "<lab>"}}},
		{"cbs_interfaces", pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES,
			&pb.NetDevPorts{Ports: []*pb.NetDevPort{{Name: "gi1", AdminState: pb.NetDevLinkState_NET_DEV_LINK_STATE_UP,
				OperState: pb.NetDevLinkState_NET_DEV_LINK_STATE_DOWN, SpeedMbps: u64p(1000),
				Mode: pb.NetDevPortMode_NET_DEV_PORT_MODE_TRUNK, NativeVlan: u32p(1), AllowedVlans: []uint32{1, 20},
				Description: "uplink"}}}, "sw-core",
			PortRows{{Name: "gi1", AdminState: netdevcontract.LinkUp, OperState: netdevcontract.LinkDown,
				SpeedMbps: u64p(1000), Mode: netdevcontract.ModeTrunk, NativeVLAN: u16p(1), AllowedVLANs: []uint16{1, 20},
				Description: "uplink"}}},
		{"cbs_mac_table", pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE,
			&pb.NetDevMACTable{Entries: []*pb.NetDevMACEntry{{Vlan: 20, Mac: "aa:bb:cc:dd:ee:ff", Port: "gi1",
				Type: pb.NetDevMACType_NET_DEV_MAC_TYPE_DYNAMIC}}}, "sw-core",
			MACRows{{VLAN: 20, MAC: "aa:bb:cc:dd:ee:ff", Port: "gi1", Type: netdevcontract.MACDynamic}}},
		{"cbs_lldp", pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP,
			&pb.NetDevLLDPNeighbors{Neighbors: []*pb.NetDevLLDPNeighbor{{LocalPort: "gi1", ChassisId: "aa:bb:cc:00:00:01",
				PortId: "eth0", SystemName: "ap1", Capabilities: []pb.NetDevLLDPCapability{
					pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_BRIDGE,
					pb.NetDevLLDPCapability_NET_DEV_LLDP_CAPABILITY_WLAN_ACCESS_POINT}}}}, "sw-core",
			LLDPRows{{LocalPort: "gi1", ChassisID: "aa:bb:cc:00:00:01", PortID: "eth0", SystemName: "ap1",
				Capabilities: []netdevcontract.LLDPCapability{netdevcontract.CapBridge, netdevcontract.CapWLANAP}}}},
		{"panos_zones", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_ZONES,
			&pb.NetDevZones{Zones: []*pb.NetDevZone{{Name: "trust", Type: pb.NetDevZoneType_NET_DEV_ZONE_TYPE_LAYER3,
				Interfaces: []string{"ethernet1/1"}}}}, "fw-edge",
			PolicyPartRows{Part: PolicyZones, Policy: netdevcontract.FirewallPolicy{
				Zones: []netdevcontract.Zone{{Name: "trust", Interfaces: []string{"ethernet1/1"}}}}}},
		{"panos_objects", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS,
			&pb.NetDevObjects{
				Addresses: []*pb.NetDevAddressObject{{Name: "web", Type: pb.NetDevAddressType_NET_DEV_ADDRESS_TYPE_IP_NETMASK,
					Value: "10.0.0.5/32", Tags: []string{"prod"}}},
				AddressGroups: []*pb.NetDevGroup{{Name: "servers", StaticMembers: []string{"web"}}},
				Services:      []*pb.NetDevServiceObject{{Name: "https-alt", Protocol: "tcp", Port: "8443"}},
				ServiceGroups: []*pb.NetDevGroup{{Name: "webs", StaticMembers: []string{"https-alt"}}},
				Tags:          []string{"prod"},
			}, "fw-edge",
			PolicyPartRows{Part: PolicyObjects, Policy: netdevcontract.FirewallPolicy{
				Addresses: []netdevcontract.AddressObject{{Name: "web", Type: netdevcontract.AddressNetmask,
					Value: "10.0.0.5/32", Tags: []string{"prod"}}},
				AddressGroups: []netdevcontract.Group{{Name: "servers", Static: []string{"web"}}},
				Services:      []netdevcontract.ServiceObject{{Name: "https-alt", Protocol: "tcp", Port: "8443"}},
				ServiceGroups: []netdevcontract.Group{{Name: "webs", Static: []string{"https-alt"}}},
			}}},
		{"panos_security_rules", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES,
			&pb.NetDevSecurityRules{Rules: []*pb.NetDevSecurityRule{{Name: "allow-web", FromZones: []string{"untrust"},
				ToZones: []string{"trust"}, Source: []string{"any"}, Destination: []string{"web"},
				Application: []string{"ssl"}, Service: []string{"application-default"},
				Action: pb.NetDevRuleAction_NET_DEV_RULE_ACTION_ALLOW}}}, "fw-edge",
			PolicyPartRows{Part: PolicySecurityRules, Policy: netdevcontract.FirewallPolicy{
				SecurityRules: []netdevcontract.SecurityRule{{Name: "allow-web", From: []string{"untrust"},
					To: []string{"trust"}, Source: []string{"any"}, Destination: []string{"web"},
					Application: []string{"ssl"}, Service: []string{"application-default"},
					Action: netdevcontract.ActionAllow}}}}},
		{"panos_nat_rules", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_NAT_RULES,
			&pb.NetDevNATRules{Rules: []*pb.NetDevNATRule{{Name: "snat", FromZones: []string{"trust"},
				ToZones: []string{"untrust"}, Source: []string{"any"}, Destination: []string{"any"},
				SourceTranslation: "dynamic-ip-and-port interface ethernet1/2"}}}, "fw-edge",
			PolicyPartRows{Part: PolicyNATRules, Policy: netdevcontract.FirewallPolicy{
				NATRules: []netdevcontract.NATRule{{Name: "snat", From: []string{"trust"}, To: []string{"untrust"},
					Source: []string{"any"}, Destination: []string{"any"},
					SourceTranslation: "dynamic-ip-and-port interface ethernet1/2"}}}}},
		{"panos_rule_hit_counts", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS,
			&pb.NetDevRuleHitCounts{Entries: []*pb.NetDevRuleHitCount{
				{RuleName: "allow-web", Hits: 42, FirstHitUnix: i64p(first.Unix()), LastHitUnix: i64p(last.Unix())},
				{RuleName: "deny-all"}}}, "fw-edge",
			HitCountRows{{RuleName: "allow-web", Hits: 42, FirstHit: &first, LastHit: &last}, {RuleName: "deny-all"}}},
	}
}

// TestDecodePayloadMapsEveryReadAndStoresIt covers the happy path of every
// read kind: decode, map to typed rows, store; complete reads are fresh,
// incomplete ones partial (facts cannot be incomplete by contract).
func TestDecodePayloadMapsEveryReadAndStoresIt(t *testing.T) {
	for _, tc := range ingestCases() {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := DecodePayload(tc.read, spoolJSON(t, tc.msg))
			if err != nil {
				t.Fatalf("DecodePayload: %v", err)
			}
			if !reflect.DeepEqual(rows, tc.want) {
				t.Fatalf("rows = %#v\nwant %#v", rows, tc.want)
			}
			for _, incomplete := range []bool{false, true} {
				if incomplete && rows.Read() == ReadFacts {
					continue
				}
				s, _, _ := newTestStore(t)
				addDevice(t, s, cbsDevice())
				addDevice(t, s, panosDevice())
				mustReplace(t, s, tc.device, rows.Read(), testBase, incomplete, rows)
				ds, err := s.GetDataset(context.Background(), tc.device, rows.Read())
				if err != nil {
					t.Fatalf("GetDataset: %v", err)
				}
				want := StateFresh
				if incomplete {
					want = StatePartial
				}
				if ds.State != want || ds.Incomplete != incomplete {
					t.Fatalf("incomplete=%v: state %s incomplete %v, want %s", incomplete, ds.State, ds.Incomplete, want)
				}
			}
		})
	}
}

func TestIncompleteFactsAreRefused(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	rows, err := DecodePayload(pb.NetDeviceRead_NET_DEVICE_READ_CBS_VERSION,
		spoolJSON(t, &pb.NetDevCBSVersion{Model: "CBS350", Firmware: "3.4"}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ReplaceDataset(context.Background(), "sw-core", ReadFacts, 2, testBase, true, rows)
	if !errors.Is(err, ErrInvalidRows) {
		t.Fatalf("err = %v, want ErrInvalidRows", err)
	}
}

func TestDecodePayloadRejectsMalformedPayloads(t *testing.T) {
	big := `{"vlans":[` + strings.Repeat(`{"id":1},`, MaxIngestPayloadBytes/9) + `{"id":1}]}`
	cases := []struct {
		name    string
		read    pb.NetDeviceRead
		payload string
		want    error
	}{
		{"unknown field", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS, `{"vlans":[],"evil":1}`, ErrInvalidPayload},
		{"not json", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS, `vlans`, ErrInvalidPayload},
		{"invalid utf8", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS, "{\"vlans\":[{\"id\":1,\"name\":\"\xff\"}]}", ErrInvalidPayload},
		{"oversize", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS, big, ErrInvalidPayload},
		{"vlan overflow", pb.NetDeviceRead_NET_DEVICE_READ_CBS_VLANS, `{"vlans":[{"id":65536}]}`, ErrInvalidPayload},
		{"allowed vlan overflow", pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES,
			`{"ports":[{"name":"gi1","admin_state":"NET_DEV_LINK_STATE_UP","oper_state":"NET_DEV_LINK_STATE_UP","mode":"NET_DEV_PORT_MODE_TRUNK","allowed_vlans":[70000]}]}`, ErrInvalidPayload},
		{"unspecified link state", pb.NetDeviceRead_NET_DEVICE_READ_CBS_INTERFACES,
			`{"ports":[{"name":"gi1","oper_state":"NET_DEV_LINK_STATE_UP","mode":"NET_DEV_PORT_MODE_ACCESS"}]}`, ErrInvalidPayload},
		{"unspecified mac type", pb.NetDeviceRead_NET_DEVICE_READ_CBS_MAC_TABLE,
			`{"entries":[{"vlan":1,"mac":"aa:bb:cc:dd:ee:ff"}]}`, ErrInvalidPayload},
		{"unspecified lldp capability", pb.NetDeviceRead_NET_DEVICE_READ_CBS_LLDP,
			`{"neighbors":[{"local_port":"gi1","chassis_id":"x","port_id":"y","capabilities":["NET_DEV_LLDP_CAPABILITY_UNSPECIFIED"]}]}`, ErrInvalidPayload},
		{"unspecified address type", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_OBJECTS,
			`{"addresses":[{"name":"a","value":"10.0.0.1"}]}`, ErrInvalidPayload},
		{"unspecified action", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_SECURITY_RULES,
			`{"rules":[{"name":"r"}]}`, ErrInvalidPayload},
		{"hit time out of range", pb.NetDeviceRead_NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS,
			`{"entries":[{"rule_name":"r","hits":"1","last_hit_unix":"9223372036854775807"}]}`, ErrInvalidPayload},
		{"unspecified read", pb.NetDeviceRead_NET_DEVICE_READ_UNSPECIFIED, `{}`, ErrUnknownRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodePayload(tc.read, []byte(tc.payload))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "evil") {
				t.Fatalf("error quotes the payload: %v", err)
			}
		})
	}
}

func TestPolicyPartWithForeignRowsIsRefused(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	rows := PolicyPartRows{Part: PolicyZones, Policy: netdevcontract.FirewallPolicy{
		Zones:         []netdevcontract.Zone{{Name: "trust"}},
		SecurityRules: []netdevcontract.SecurityRule{{Name: "r", Action: netdevcontract.ActionAllow}},
	}}
	_, err := s.ReplaceDataset(context.Background(), "fw-edge", ReadFirewallPolicy, 1, testBase, false, rows)
	if !errors.Is(err, ErrRowsMismatch) {
		t.Fatalf("err = %v, want ErrRowsMismatch", err)
	}
	bad := PolicyPartRows{Part: "interfaces"}
	if _, err := s.ReplaceDataset(context.Background(), "fw-edge", ReadFirewallPolicy, 1, testBase, false, bad); !errors.Is(err, ErrRowsMismatch) {
		t.Fatalf("unknown part: err = %v, want ErrRowsMismatch", err)
	}
}

// TestPolicyPartOnlyMarksItsOwnRowsAbsent checks that a complete part read
// marks only its own missing rows absent and carries every other part's
// rows unchanged, and that an incomplete part marks nothing absent.
func TestPolicyPartOnlyMarksItsOwnRowsAbsent(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	rules := func(names ...string) PolicyPartRows {
		var p netdevcontract.FirewallPolicy
		for _, n := range names {
			p.SecurityRules = append(p.SecurityRules, netdevcontract.SecurityRule{Name: n, Action: netdevcontract.ActionAllow})
		}
		return PolicyPartRows{Part: PolicySecurityRules, Policy: p}
	}
	zones := PolicyPartRows{Part: PolicyZones, Policy: netdevcontract.FirewallPolicy{
		Zones: []netdevcontract.Zone{{Name: "trust"}, {Name: "untrust"}}}}
	objects := PolicyPartRows{Part: PolicyObjects, Policy: netdevcontract.FirewallPolicy{
		Addresses: []netdevcontract.AddressObject{{Name: "web", Type: netdevcontract.AddressNetmask, Value: "10.0.0.5/32"}}}}

	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, rules("a", "b"))
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(time.Minute), false, zones)
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(2*time.Minute), false, objects)
	// Zones re-read without "untrust": only that zone becomes absent.
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(3*time.Minute), false, PolicyPartRows{Part: PolicyZones,
		Policy: netdevcontract.FirewallPolicy{Zones: []netdevcontract.Zone{{Name: "trust"}}}})
	// An incomplete rules read without "b" marks nothing absent.
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(4*time.Minute), true, rules("a"))

	absent := func(tbl, key string) (bool, bool) {
		t.Helper()
		var a int
		err := db.QueryRow(`SELECT absent FROM `+tbl+` WHERE row_key = ? AND dataset_id =
			(SELECT id FROM netdev_datasets WHERE device_id = 'fw-edge' AND read = 'firewall_policy' AND current = 1)`, key).Scan(&a)
		if err != nil {
			return false, false
		}
		return a == 1, true
	}
	for _, c := range []struct {
		tbl, key   string
		wantAbsent bool
	}{
		{"netdev_fw_rules", "a", false},
		{"netdev_fw_rules", "b", false},
		{"netdev_objects", `["zone","trust"]`, false},
		{"netdev_objects", `["zone","untrust"]`, true},
		{"netdev_objects", `["address","web"]`, false},
	} {
		got, ok := absent(c.tbl, c.key)
		if !ok {
			t.Fatalf("%s %s missing from the current dataset", c.tbl, c.key)
		}
		if got != c.wantAbsent {
			t.Fatalf("%s %s absent = %v, want %v", c.tbl, c.key, got, c.wantAbsent)
		}
	}

	// A complete rules read without "b" marks only "b" absent.
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(5*time.Minute), false, rules("a"))
	if got, _ := absent("netdev_fw_rules", "b"); !got {
		t.Fatal("rule b not absent after a complete rules read")
	}
	if got, _ := absent("netdev_objects", `["address","web"]`); got {
		t.Fatal("a rules read marked an address object absent")
	}
	ds, err := s.GetDataset(context.Background(), "fw-edge", ReadFirewallPolicy)
	if err != nil || ds.State != StateFresh {
		t.Fatalf("dataset state = %v, %v; want fresh", ds.State, err)
	}
}
