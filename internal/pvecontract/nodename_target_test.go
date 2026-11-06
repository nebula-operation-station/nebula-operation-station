// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecontract_test

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

// The telemetry targets and metrics grants take their node rule from
// pvecontract; these tests hold them to it from outside the package.

func telemetryTarget(node string) pvecollect.TelemetryTarget {
	return pvecollect.TelemetryTarget{
		Source: pvecollect.TelemetryProvider, RemoteID: "remote-a", TrustPin: strings.Repeat("a", 64),
		TrustGeneration: 1, Node: node, Kind: pvecollect.TelemetryKindNode,
	}
}

func metricsTarget(node string) permit.ProviderMetricsTarget {
	return permit.ProviderMetricsTarget{Node: node, Kind: permit.MetricsKindNode}
}

func TestTargetsAcceptMixedCaseNode(t *testing.T) {
	if !telemetryTarget("ProxmoxBAI").Valid() {
		t.Error("telemetry target refused ProxmoxBAI")
	}
	if !metricsTarget("ProxmoxBAI").Valid() {
		t.Error("metrics target refused ProxmoxBAI")
	}
}

func TestTargetsRefuseMalformedNodes(t *testing.T) {
	for _, node := range []string{"", ".", "..", "../x", "a/b", "-a", strings.Repeat("A", 64)} {
		if telemetryTarget(node).Valid() {
			t.Errorf("telemetry target accepted node %q", node)
		}
		if metricsTarget(node).Valid() {
			t.Errorf("metrics target accepted node %q", node)
		}
	}
}

// A grant must bind the exact name: case variants are different targets.
func TestMetricsTargetKeyKeepsNodeCase(t *testing.T) {
	upper, lower := metricsTarget("ProxmoxBAI"), metricsTarget("proxmoxbai")
	if upper.Key() == lower.Key() {
		t.Errorf("Key() = %q for both case variants", upper.Key())
	}
	if !strings.HasPrefix(upper.Key(), "ProxmoxBAI/") {
		t.Errorf("Key() = %q, want the exact node name", upper.Key())
	}
}
