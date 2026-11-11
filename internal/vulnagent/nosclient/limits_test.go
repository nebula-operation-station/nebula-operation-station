// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
)

// The client mirrors the server's limits without linking the server; they
// must stay equal.
func TestClientLimitsMatchTheServer(t *testing.T) {
	checks := []struct {
		name         string
		client, serv int64
	}{
		{"MaxExportRequests", MaxExportRequests, api.MaxExportRequests},
		{"ExportWindow", int64(ExportWindow), int64(api.ExportWindow)},
		{"MaxWriteRequests", MaxWriteRequests, api.MaxWriteRequests},
		{"WriteWindow", int64(WriteWindow), int64(api.WriteWindow)},
		{"MaxSubjectsPerPage", MaxSubjectsPerPage, api.MaxSubjectsPerPage},
		{"MaxExportBytes", MaxExportBytes, api.MaxExportBytes},
		{"MaxExportSubjects", MaxExportSubjects, api.MaxExportSubjects},
		{"MaxHostPackages", MaxHostPackages, api.MaxHostPackages},
		{"MaxImagePackages", MaxImagePackages, api.MaxImagePackages},
		{"MaxBinariesPerComponent", MaxBinariesPerComponent, vulnfinding.MaxBinaries},
		{"MaxBatchBytes", MaxBatchBytes, api.MaxBatchBytes},
		{"MaxFindingsPerBatch", MaxFindingsPerBatch, vulnstore.MaxFindingsPerBatch},
		{"MaxCoveredPerBatch", MaxCoveredPerBatch, vulnstore.MaxCoveredPerBatch},
		{"MaxFindingsPerRun", MaxFindingsPerRun, vulnstore.MaxFindingsPerRun},
		{"MaxBatchSeq", MaxBatchSeq, api.MaxBatchSeq},
		{"MaxRunDuration", int64(MaxRunDuration), int64(vulnstore.MaxRunDuration)},
		{"InventoryFormat", int64(len(InventoryFormat)), int64(len(api.VulnInventoryFormat))},
	}
	for _, c := range checks {
		if c.client != c.serv {
			t.Errorf("%s: client %d, server %d", c.name, c.client, c.serv)
		}
	}
	if InventoryFormat != api.VulnInventoryFormat {
		t.Errorf("format %q, server %q", InventoryFormat, api.VulnInventoryFormat)
	}
	if MaxRunSources < len(testSources) {
		t.Errorf("MaxRunSources below the test source list")
	}
}
