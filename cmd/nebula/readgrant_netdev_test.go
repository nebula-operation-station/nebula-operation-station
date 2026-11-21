// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/schedgrant"
)

// testNetDeviceGrantDoc builds a device read lease document (rate profile
// "netdevice") with the given device targets, as the executor holds it.
func testNetDeviceGrantDoc(t *testing.T, targets []permit.NetDeviceTarget) []byte {
	t.Helper()
	doc := permit.ReadGrantDoc{
		Grant: "read-grant-v2", ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Issuer: "alice",
		CreatedUnix: 1800000000, ExpiryUnix: testRGExpiry, Trigger: "scheduled",
		MinIntervalS: 900, RunBudget: 24, RateProfile: schedgrant.NetDeviceReadProfile,
		NetDeviceTargets: targets,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// approveScreen runs "read-grant approve" against one pending grant with
// the given canonical document, answers the prompt with answer, and returns
// the output shown before the prompt and the fake executor.
func approveScreen(t *testing.T, raw []byte, answer string) (string, *fakeReadGrants) {
	t.Helper()
	f := &fakeReadGrants{pending: []*pb.PendingReadGrant{{GrantDigest: testRGDigest, CanonicalGrant: raw, ApprovalExpiryUnix: 1800000300}}}
	var out bytes.Buffer
	err := readGrantCmd(context.Background(), f, []string{"approve", testRGDigest}, strings.NewReader(answer), &out)
	if answer == "yes\n" && err != nil {
		t.Fatal(err)
	}
	got := out.String()
	prompt := strings.Index(got, "Type 'yes' to approve")
	if prompt < 0 {
		t.Fatalf("no prompt:\n%s", got)
	}
	return got[:prompt], f
}

func TestReadGrantApproveShowsEveryNetDeviceAndReadBeforePrompt(t *testing.T) {
	targets := []permit.NetDeviceTarget{
		{
			DeviceID: "11111111-1111-4111-8111-111111111111", TrustPin: "SHA256:pin-switch-a", TrustGeneration: 3, CredentialVersion: 7,
			Reads: []string{schedgrant.NetDeviceReadCBSVersion, schedgrant.NetDeviceReadCBSVLANs, schedgrant.NetDeviceReadCBSLLDP},
		},
		{
			DeviceID: "22222222-2222-4222-8222-222222222222", TrustPin: "SHA256:pin-firewall-b", TrustGeneration: 1, CredentialVersion: 42,
			Reads: []string{schedgrant.NetDeviceReadPANOSZones, schedgrant.NetDeviceReadPANOSSecurityRules},
		},
	}
	before, f := approveScreen(t, testNetDeviceGrantDoc(t, targets), "yes\n")
	if len(f.approved) != 1 || f.approved[0] != testRGDigest {
		t.Fatalf("approved = %v", f.approved)
	}

	lines := []string{
		"  network devices (2):",
		"    11111111-1111-4111-8111-111111111111  trust pin SHA256:pin-switch-a generation 3  credential version 7  reads (3): cbs_version, cbs_vlans, cbs_lldp",
		"    22222222-2222-4222-8222-222222222222  trust pin SHA256:pin-firewall-b generation 1  credential version 42  reads (2): panos_zones, panos_security_rules",
	}
	last := -1
	for _, l := range lines {
		i := strings.Index(before, l+"\n")
		if i < 0 {
			t.Fatalf("approval screen lacks line %q before the prompt:\n%s", l, before)
		}
		if i <= last {
			t.Errorf("line %q is out of document order:\n%s", l, before)
		}
		last = i
	}
	// The device section comes before the complete canonical document.
	if canon := strings.Index(before, "canonical grant (complete):"); canon < last {
		t.Errorf("device lines not before the canonical grant:\n%s", before)
	}
	for _, tg := range targets {
		for _, r := range tg.Reads {
			if strings.Count(before, r) < 2 { // device line and canonical grant
				t.Errorf("read %q missing from the device lines", r)
			}
		}
	}
}

func TestReadGrantApproveNetDeviceOrderFollowsDocument(t *testing.T) {
	// Not sorted: the CLI shows the executor's document order.
	targets := []permit.NetDeviceTarget{
		{DeviceID: "zz-device", TrustPin: "pin-z", TrustGeneration: 1, CredentialVersion: 1, Reads: []string{schedgrant.NetDeviceReadCBSMACTable, schedgrant.NetDeviceReadCBSVersion}},
		{DeviceID: "aa-device", TrustPin: "pin-a", TrustGeneration: 2, CredentialVersion: 2, Reads: []string{schedgrant.NetDeviceReadCBSInterfaces}},
	}
	before, _ := approveScreen(t, testNetDeviceGrantDoc(t, targets), "no\n")
	z := strings.Index(before, "    zz-device  ")
	a := strings.Index(before, "    aa-device  ")
	if z < 0 || a < 0 || z > a {
		t.Fatalf("devices not in document order (zz=%d aa=%d):\n%s", z, a, before)
	}
	if !strings.Contains(before, "reads (2): cbs_mac_table, cbs_version\n") {
		t.Errorf("reads not in document order:\n%s", before)
	}
}

func TestReadGrantApproveNetDeviceEscapesControlCharacters(t *testing.T) {
	targets := []permit.NetDeviceTarget{{
		DeviceID: "dev\x1b[2Jice", TrustPin: "pin\rspoof", TrustGeneration: 1, CredentialVersion: 1,
		Reads: []string{"cbs_version\n    11111111-fake  trust pin x", "cbs‮vlans", "cbs_lldp\x00"},
	}}
	before, f := approveScreen(t, testNetDeviceGrantDoc(t, targets), "no\n")
	if len(f.approved) != 0 {
		t.Fatalf("approved without yes: %v", f.approved)
	}
	for _, raw := range []string{"\x1b", "\r", "\x00", "‮", "cbs_version\n"} {
		if strings.Contains(before, raw) {
			t.Errorf("raw %q in output:\n%q", raw, before)
		}
	}
	for _, want := range []string{
		"    dev\\u001b[2Jice  trust pin pin\\u000dspoof generation 1  credential version 1  reads (3): " +
			"cbs_version\\u000a    11111111-fake  trust pin x, cbs\\u202evlans, cbs_lldp\\u0000\n",
	} {
		if !strings.Contains(before, want) {
			t.Errorf("escaped device line %q missing:\n%s", want, before)
		}
	}
}

func TestReadGrantApproveWithoutNetDevicesHasNoDeviceSection(t *testing.T) {
	before, _ := approveScreen(t, testReadGrantDoc(t, 2), "no\n")
	if strings.Contains(before, "network devices") {
		t.Errorf("host grant shows a device section:\n%s", before)
	}
}
