// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// Server limits (ADR 0011 D3, D5). They mirror internal/web/api and
// internal/vulnstore, which the agent does not link; the tests check that
// they are equal.
const (
	// MaxExportRequests per ExportWindow: 60 inventory pages per hour.
	MaxExportRequests = 60
	ExportWindow      = time.Hour
	// MaxWriteRequests per WriteWindow: 60 run requests per minute.
	MaxWriteRequests = 60
	WriteWindow      = time.Minute

	// MaxSubjectsPerPage and MaxExportBytes bound one export page.
	MaxSubjectsPerPage = 1000
	MaxExportBytes     = 4 << 20
	// MaxExportSubjects bounds the subjects of one snapshot.
	MaxExportSubjects = 10000
	// MaxHostPackages and MaxImagePackages bound one subject's components
	// over all its parts.
	MaxHostPackages  = 20000
	MaxImagePackages = 5000
	// MaxBinariesPerComponent bounds the binaries of one component.
	MaxBinariesPerComponent = vulnfinding.MaxBinaries

	// MaxBatchBytes bounds a findings batch body (1 MiB).
	MaxBatchBytes = 1 << 20
	// MaxFindingsPerBatch and MaxCoveredPerBatch bound one batch.
	MaxFindingsPerBatch = 1000
	MaxCoveredPerBatch  = MaxFindingsPerBatch
	// MaxFindingsPerRun bounds the findings of one run.
	MaxFindingsPerRun = 200000
	// MaxBatchSeq is the highest batch_seq (exact in a JSON double).
	MaxBatchSeq = 1<<53 - 1
	// MaxStartBytes bounds a run start body.
	MaxStartBytes = 64 << 10
	// MaxRunDuration: a run not completed within 6 h is aborted.
	MaxRunDuration = 6 * time.Hour
)

// Client-side bounds the server does not state as such.
const (
	// MaxExportPages bounds the pages of one snapshot the client reads.
	MaxExportPages = 1000
	// maxCursorBytes bounds an export cursor (the server refuses longer).
	maxCursorBytes = 512
	// MaxRunSources bounds the sources named in one run start; the
	// server's fixed list is shorter.
	MaxRunSources = 64
)
