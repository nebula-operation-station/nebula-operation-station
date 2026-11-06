// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract

import (
	"bytes"
	"strings"
	"testing"
)

const mixedCaseNode = "ProxmoxBAI"

func TestValidNodeNameAcceptsPVENames(t *testing.T) {
	label63 := strings.Repeat("A", 63)
	cases := []string{
		"pve1",
		mixedCaseNode,
		"proxmoxbai",
		"PVE",
		"Z",
		"7",
		"Node-1",
		"ProxmoxBAI.lab.Example",
		label63,
		label63 + "." + label63 + "." + label63 + "." + strings.Repeat("A", 61), // 253 bytes
	}
	for _, name := range cases {
		if !ValidNodeName(name) {
			t.Errorf("ValidNodeName(%q) = false, want true", name)
		}
	}
}

func TestValidNodeNameRefusesMalformedNames(t *testing.T) {
	cases := map[string]string{
		"empty":               "",
		"dot":                 ".",
		"dot dot":             "..",
		"parent path":         "../x",
		"parent path upper":   "../X",
		"slash":               "a/b",
		"slash upper":         "A/B",
		"backslash":           `a\b`,
		"leading slash":       "/ProxmoxBAI",
		"leading hyphen":      "-a",
		"leading hyphen up":   "-A",
		"trailing hyphen":     "a-",
		"trailing hyphen up":  "A-",
		"leading dot":         ".ProxmoxBAI",
		"trailing dot":        "ProxmoxBAI.",
		"empty label":         "Proxmox..BAI",
		"underscore":          "Proxmox_BAI",
		"space":               "Proxmox BAI",
		"newline":             "ProxmoxBAI\n",
		"nul":                 "Proxmox\x00BAI",
		"percent escape":      "a%2Fb",
		"non ascii":           "ProxmöxBAI",
		"non ascii kelvin":    "Kelvin",
		"64 byte label":       strings.Repeat("a", 64),
		"64 byte label upper": strings.Repeat("A", 64),
		"64 byte inner label": "a." + strings.Repeat("A", 64) + ".b",
		"254 bytes": strings.Repeat("A", 63) + "." + strings.Repeat("A", 63) + "." +
			strings.Repeat("A", 63) + "." + strings.Repeat("A", 62),
	}
	for name, node := range cases {
		t.Run(name, func(t *testing.T) {
			if ValidNodeName(node) {
				t.Errorf("ValidNodeName(%q) = true, want false", node)
			}
		})
	}
}

// Endpoint hosts are DNS names, not node names: the node-name pattern must
// not widen them.
func TestEndpointHostStaysLowerCase(t *testing.T) {
	if validEndpointHost(mixedCaseNode) {
		t.Errorf("validEndpointHost(%q) = true, want false", mixedCaseNode)
	}
	if !validEndpointHost("pve1.lab.example") {
		t.Error("validEndpointHost rejected a lower-case DNS name")
	}
}

func TestObservationKeepsMixedCaseNode(t *testing.T) {
	raw := bytes.ReplaceAll(mustMarshal(t, baseObservation()), []byte(`"node":"poxmox"`), []byte(`"node":"`+mixedCaseNode+`"`))
	if !bytes.Contains(raw, []byte(mixedCaseNode)) {
		t.Fatal("fixture does not contain the mixed-case node")
	}
	got, err := DecodeObservation(raw)
	if err != nil {
		t.Fatalf("DecodeObservation: %v", err)
	}
	if n := got.Nodes.Value[0].Node; n != mixedCaseNode {
		t.Errorf("node = %q, want %q", n, mixedCaseNode)
	}
	if n := got.Guests.Value[0].Node; n != mixedCaseNode {
		t.Errorf("guest node = %q, want %q", n, mixedCaseNode)
	}
	out, err := MarshalObservation(got)
	if err != nil {
		t.Fatalf("MarshalObservation: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Errorf("round trip changed the observation:\n got %s\nwant %s", out, raw)
	}
}

func TestObservationTreatsNodeCaseVariantsAsDifferentNodes(t *testing.T) {
	o := baseObservation()
	upper := o.Nodes.Value[0]
	upper.Node = mixedCaseNode
	lower := o.Nodes.Value[0]
	lower.Node = strings.ToLower(mixedCaseNode)
	o.Nodes = AvailableDataset([]NodeObservation{upper, lower})
	got, err := ValidateObservation(o)
	if err != nil {
		t.Fatalf("ValidateObservation: %v", err)
	}
	if got.Nodes.Value[0].Node != mixedCaseNode || got.Nodes.Value[1].Node != "proxmoxbai" {
		t.Errorf("nodes = %q, %q", got.Nodes.Value[0].Node, got.Nodes.Value[1].Node)
	}
}

func TestObservationRefusesMalformedNodes(t *testing.T) {
	for _, node := range []string{"", "..", "../x", "a/b", "-a", strings.Repeat("A", 64)} {
		o := baseObservation()
		o.Nodes.Value[0].Node = node
		if _, err := ValidateObservation(o); err == nil {
			t.Errorf("ValidateObservation accepted node %q", node)
		}
	}
}

func TestLiveWantKeepsMixedCaseNode(t *testing.T) {
	want := mkLiveWant(1000, 1030,
		LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: mixedCaseNode},
		LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: "proxmoxbai"},
	)
	got, err := ValidateLiveWant(want)
	if err != nil {
		t.Fatalf("ValidateLiveWant: %v", err)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("targets = %+v, want both case variants as different nodes", got.Targets)
	}
	seen := map[string]bool{got.Targets[0].Node: true, got.Targets[1].Node: true}
	if !seen[mixedCaseNode] || !seen["proxmoxbai"] {
		t.Errorf("targets = %+v, want the exact names", got.Targets)
	}
}

func TestLiveSamplesKeepMixedCaseNode(t *testing.T) {
	got, err := ValidateLiveSamples(mkLiveSamples("remote-a", 1000, mkLiveSample(LiveKindNode, mixedCaseNode, 0, 0.5)))
	if err != nil {
		t.Fatalf("ValidateLiveSamples: %v", err)
	}
	if n := got.Samples[0].Node; n != mixedCaseNode {
		t.Errorf("sample node = %q, want %q", n, mixedCaseNode)
	}
}

func TestLiveTargetsRefuseMalformedNodes(t *testing.T) {
	for _, node := range []string{"", ".", "..", "../x", "a/b", "-a", strings.Repeat("A", 64)} {
		if _, err := ValidateLiveWant(mkLiveWant(1000, 1030, LiveTarget{Remote: "remote-a", Kind: LiveKindNode, Node: node})); err == nil {
			t.Errorf("ValidateLiveWant accepted node %q", node)
		}
		if _, err := ValidateLiveSamples(mkLiveSamples("remote-a", 1000, mkLiveSample(LiveKindNode, node, 0, 0.5))); err == nil {
			t.Errorf("ValidateLiveSamples accepted node %q", node)
		}
	}
}
