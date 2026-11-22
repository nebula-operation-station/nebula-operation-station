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
	rlo := string(rune(0x202e)) // right-to-left override, a format character
	targets := []permit.NetDeviceTarget{{
		DeviceID: "dev\x1b[2Jice", TrustPin: "pin\rspoof", TrustGeneration: 1, CredentialVersion: 1,
		Reads: []string{"cbs_version\n    11111111-fake  trust pin x", "cbs" + rlo + "vlans", "cbs_lldp\x00"},
	}}
	before, f := approveScreen(t, testNetDeviceGrantDoc(t, targets), "no\n")
	if len(f.approved) != 0 {
		t.Fatalf("approved without yes: %v", f.approved)
	}
	for _, raw := range []string{"\x1b", "\r", "\x00", rlo, "cbs_version\n"} {
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
	assertCanonicalLineEscaped(t, before, []string{"\x1b", "\r", "\x00", rlo, "\n"},
		// JSON escapes for the control characters, displaySafe's for the RLO.
		[]string{`dev\u001b[2Jice`, `pin\rspoof`, `cbs_version\n    11111111-fake`, "cbs\\u202evlans", `cbs_lldp\u0000`})
}

// assertCanonicalLineEscaped checks the display path of the complete
// canonical document on its own: it is exactly one line after its heading,
// holds none of the raw characters and shows every escaped form.
func assertCanonicalLineEscaped(t *testing.T, before string, raws, escaped []string) {
	t.Helper()
	const heading = "  canonical grant (complete):\n"
	h := strings.Index(before, heading)
	if h < 0 {
		t.Fatalf("no canonical grant heading:\n%s", before)
	}
	rest := before[h+len(heading):]
	end := strings.IndexByte(rest, '\n')
	if end < 0 || !strings.HasPrefix(rest[end+1:], "It lets the server") {
		t.Fatalf("canonical grant is not exactly one line before the closing text:\n%q", rest)
	}
	line := rest[:end]
	if !strings.HasPrefix(line, "    {") || !strings.HasSuffix(line, "}") {
		t.Errorf("canonical grant line is not the complete document:\n%q", line)
	}
	for _, raw := range raws {
		if strings.Contains(line, raw) {
			t.Errorf("raw %q in the canonical grant line:\n%q", raw, line)
		}
	}
	for _, e := range escaped {
		if !strings.Contains(line, e) {
			t.Errorf("escaped %q missing from the canonical grant line:\n%s", e, line)
		}
	}
}

const testRegCfgDigest = "5555555555555555555555555555555555555555555555555555555555555555"

// testRegistryGrantDoc builds a registry read lease document (rate profile
// "registry") with the given registry targets, as the executor holds it.
func testRegistryGrantDoc(t *testing.T, targets []permit.RegistryTarget) []byte {
	t.Helper()
	doc := permit.ReadGrantDoc{
		Grant: "read-grant-v2", ID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Issuer: "alice",
		CreatedUnix: 1800000000, ExpiryUnix: testRGExpiry, Trigger: "on-demand",
		MinIntervalS: 900, RunBudget: 24, RateProfile: schedgrant.RegistryReadProfile,
		RegistryTargets: targets,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadGrantApproveShowsEveryRegistryRepositoryAndMethodBeforePrompt(t *testing.T) {
	targets := []permit.RegistryTarget{
		{
			RegistryID: "harbor", ConfigDigest: testRegCfgDigest, ConfigVersion: 3,
			CredentialID: "0123456789abcdef0123456789abcdef", CredentialVersion: 2,
			Repositories: []string{"team/worker", "team/app"},
			Methods:      []string{schedgrant.RegistryReadTagDigest, schedgrant.RegistryReadListTags},
		},
		{
			RegistryID: "ghcr-mirror", ConfigDigest: testRegCfgDigest, ConfigVersion: 1,
			CredentialID: "fedcba9876543210fedcba9876543210", CredentialVersion: 9,
			Repositories: []string{"infra/base"},
			Methods:      []string{schedgrant.RegistryReadTagDigest},
		},
	}
	before, f := approveScreen(t, testRegistryGrantDoc(t, targets), "yes\n")
	if len(f.approved) != 1 || f.approved[0] != testRGDigest {
		t.Fatalf("approved = %v", f.approved)
	}
	lines := []string{
		"  rate profile  registry",
		"  registries (2):",
		"    harbor  config version 3 sha256:" + testRegCfgDigest + "  credential 0123456789abcdef0123456789abcdef version 2",
		"      repositories (2): team/worker, team/app",
		"      methods (2): tag_digest, list_tags",
		"    ghcr-mirror  config version 1 sha256:" + testRegCfgDigest + "  credential fedcba9876543210fedcba9876543210 version 9",
		"      repositories (1): infra/base",
		"      methods (1): tag_digest",
		"  canonical grant (complete):",
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
}

func TestReadGrantApproveRegistryEscapesControlCharacters(t *testing.T) {
	rlo := string(rune(0x202e))
	targets := []permit.RegistryTarget{{
		RegistryID: "har\x1b[2Jbor", ConfigDigest: "dig\rest", ConfigVersion: 1,
		CredentialID: "cred" + rlo + "id", CredentialVersion: 1,
		Repositories: []string{"team/app\n    methods (1): fake"},
		Methods:      []string{"tag_digest\x00"},
	}}
	before, f := approveScreen(t, testRegistryGrantDoc(t, targets), "no\n")
	if len(f.approved) != 0 {
		t.Fatalf("approved without yes: %v", f.approved)
	}
	for _, raw := range []string{"\x1b", "\r", "\x00", rlo, "team/app\n"} {
		if strings.Contains(before, raw) {
			t.Errorf("raw %q in output:\n%q", raw, before)
		}
	}
	for _, want := range []string{
		"    har\\u001b[2Jbor  config version 1 sha256:dig\\u000dest  credential cred\\u202eid version 1\n",
		"      repositories (1): team/app\\u000a    methods (1): fake\n",
		"      methods (1): tag_digest\\u0000\n",
	} {
		if !strings.Contains(before, want) {
			t.Errorf("escaped registry line %q missing:\n%s", want, before)
		}
	}
	assertCanonicalLineEscaped(t, before, []string{"\x1b", "\r", "\x00", rlo, "\n"},
		[]string{`har\u001b[2Jbor`, `dig\rest`, "cred\\u202eid", `team/app\n    methods (1): fake`, `tag_digest\u0000`})
}

func TestReadGrantApproveWithoutRegistriesHasNoRegistrySection(t *testing.T) {
	before, _ := approveScreen(t, testReadGrantDoc(t, 2), "no\n")
	if strings.Contains(before, "registries") {
		t.Errorf("host grant shows a registry section:\n%s", before)
	}
}

func TestReadGrantApproveWithoutNetDevicesHasNoDeviceSection(t *testing.T) {
	before, _ := approveScreen(t, testReadGrantDoc(t, 2), "no\n")
	if strings.Contains(before, "network devices") {
		t.Errorf("host grant shows a device section:\n%s", before)
	}
}
