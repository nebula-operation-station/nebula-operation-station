// SPDX-License-Identifier: AGPL-3.0-or-later

package permit

import (
	"bytes"
	"context"
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

// Preview limits for the artifact shown to the approver: the first
// previewMaxLines lines, at most previewMaxBytes bytes.
const (
	previewMaxLines = 40
	previewMaxBytes = 4 << 10
)

var scanSlots = make(chan struct{}, 2)

// scanLimited runs the Safety Scanner under the executor-wide scan limit.
func scanLimited(artifact []byte) ([]scanner.Finding, canonical.Risk) {
	scanSlots <- struct{}{}
	defer func() { <-scanSlots }()
	return scanner.Scan(artifact)
}

// ScanBounded runs the Safety Scanner under the same executor-wide limit of
// two concurrent scans that ordinary permit proposals use, so other
// authorities (batch approval) cannot bypass it. It gives up when ctx ends
// while waiting for a slot.
func ScanBounded(ctx context.Context, artifact []byte) ([]scanner.Finding, canonical.Risk, error) {
	select {
	case scanSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
	defer func() { <-scanSlots }()
	f, r := scanner.Scan(artifact)
	return f, r, nil
}

type scanResult struct {
	risk       canonical.Risk
	categories []string
	// findings is what the approver sees (at most scanner.MaxFindings);
	// preview is the artifact's first lines for the approval screen.
	findings []scanner.Finding
	preview  []byte
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
	findings, risk := scanLimited(artifact)
	r := scanResult{risk: risk, categories: scanner.Categories(findings), findings: findings, preview: artifactPreview(artifact)}
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	if len(a.scans) >= maxScans {
		clear(a.scans)
	}
	a.scans[key] = r
}

// artifactPreview returns the first previewMaxLines lines of b, at most
// previewMaxBytes bytes, for the approval screen.
func artifactPreview(b []byte) []byte {
	if len(b) > previewMaxBytes {
		b = b[:previewMaxBytes]
	}
	off := 0
	for i := 0; i < previewMaxLines; i++ {
		j := bytes.IndexByte(b[off:], '\n')
		if j < 0 {
			// Fewer than previewMaxLines lines: keep the rest.
			return b
		}
		off += j + 1 // keep the newline
	}
	return b[:off]
}

// ScanInfo returns the Safety Scanner findings and the display preview the
// executor computed for an artifact it has seen (its SHA-256 in hex). ok is
// false when the executor has not scanned these bytes, so a caller must not
// present "no findings" in that case.
func (a *Authority) ScanInfo(sha256hex string) (findings []scanner.Finding, preview []byte, ok bool) {
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	s, ok := a.scans[sha256hex]
	if !ok {
		return nil, nil, false
	}
	return s.findings, s.preview, true
}

// floor is the executor's minimum risk for r on targets: the risk policy's
// floor, raised by the scanner's result for r's artifact when it is known
// and by the use of vault secrets in params (nil: not known here).
func (a *Authority) floor(r canonical.Request, targets []canonical.Target, params []byte) (canonical.Risk, string, error) {
	f, why, err := a.risk.MinimumRisk(r, targets)
	if err != nil {
		return f, why, err
	}
	if sf, ok := secretFloor(params); ok && sf.Rank() > f.Rank() {
		f, why = sf, "the run uses vault secrets"
	}
	a.scanMu.Lock()
	s, ok := a.scans[r.ArtifactSHA256]
	a.scanMu.Unlock()
	if ok && s.risk.Rank() > f.Rank() {
		f, why = s.risk, "safety scanner ("+scanner.Version+"): "+strings.Join(s.categories, ", ")
	}
	return f, why, nil
}
