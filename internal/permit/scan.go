// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/scanner"
)

// The Safety Scanner is the third source of the executor's minimum risk
// (spec 10: effective risk = max(declared, scanner, trust floor)). It can
// only raise the floor. The executor scans artifact bytes it hashed itself:
// at proposal when the caller sends them (ObserveArtifact), and at every
// host run, where the bytes are always present. A proposal without the
// bytes is approved without the scanner's floor; its runs are then refused
// (risk_above_approval) if the scan raises the floor above the approval.

// maxScans bounds the scan cache (artifact SHA-256 -> result).
const maxScans = 1024

var scanSlots = make(chan struct{}, 2)

type scanResult struct {
	risk       canonical.Risk
	categories []string
}

// ObserveArtifact scans artifact bytes and remembers the result under
// their SHA-256, which it returns.
func (a *Authority) ObserveArtifact(artifact []byte) (string, error) {
	if len(artifact) == 0 || len(artifact) > MaxArtifactSize {
		return "", fail(CodeArtifactMismatch, "artifact size %d outside 1..%d", len(artifact), MaxArtifactSize)
	}
	sum := sha256.Sum256(artifact)
	a.observe(sum, artifact)
	return hex.EncodeToString(sum[:]), nil
}

// observe scans artifact (whose SHA-256 the caller computed) unless its
// result is cached.
func (a *Authority) observe(sum [32]byte, artifact []byte) {
	key := hex.EncodeToString(sum[:])
	a.scanMu.Lock()
	_, ok := a.scans[key]
	a.scanMu.Unlock()
	if ok {
		return
	}
	// At most two scans run at once, so concurrent requests cannot take
	// all of the executor's CPU (review m71 F1).
	findings, risk := func() ([]scanner.Finding, canonical.Risk) {
		scanSlots <- struct{}{}
		defer func() { <-scanSlots }()
		return scanner.Scan(artifact)
	}()
	r := scanResult{risk: risk, categories: scanner.Categories(findings)}
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	if len(a.scans) >= maxScans {
		clear(a.scans)
	}
	a.scans[key] = r
}

// floor is the executor's minimum risk for r on targets: the risk policy's
// floor, raised by the scanner's result for r's artifact when it is known.
func (a *Authority) floor(r canonical.Request, targets []canonical.Target) (canonical.Risk, string, error) {
	f, why, err := a.risk.MinimumRisk(r, targets)
	if err != nil {
		return f, why, err
	}
	a.scanMu.Lock()
	s, ok := a.scans[r.ArtifactSHA256]
	a.scanMu.Unlock()
	if ok && s.risk.Rank() > f.Rank() {
		f, why = s.risk, "safety scanner ("+scanner.Version+"): "+strings.Join(s.categories, ", ")
	}
	return f, why, nil
}
