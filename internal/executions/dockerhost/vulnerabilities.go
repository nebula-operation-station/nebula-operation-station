// SPDX-License-Identifier: AGPL-3.0-or-later
package dockerhost

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// image-vulns-v1 is the result document the host-side scan script reports
// for image.vulnerabilities. Unlike docker.list and docker.stats the raw
// scanner output never reaches the server: the script reduces it on the
// host to unique CVE counts by severity plus the top-N CVEs with fixed
// versions, and only that bounded summary is transferred (ADR 0006 P1-30).
const vulnsFormat = "image-vulns-v1"

// Scan statuses. ok is a completed scan (fresh or from the 24 h cache);
// every other status is "unknown" and must never be rendered as zero CVEs.
const (
	VulnsOK          = "ok"
	VulnsAbsent      = "absent"      // no Trivy on the host
	VulnsStale       = "stale"       // database missing or older than 24 h
	VulnsNotLocal    = "notlocal"    // image not present in the local store
	VulnsBusy        = "busy"        // another scan runs on the host
	VulnsFailed      = "failed"      // trivy exited non-zero
	VulnsTruncated   = "truncated"   // scanner output exceeded the bound
	VulnsUnsupported = "unsupported" // output not the expected pretty-printed JSON
)

// Severity levels reported by Trivy, in display order.
var vulnSeverityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

var vulnSeveritySet = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "UNKNOWN": true,
}

var vulnStatusSet = map[string]bool{
	VulnsOK: true, VulnsAbsent: true, VulnsStale: true, VulnsNotLocal: true,
	VulnsBusy: true, VulnsFailed: true, VulnsTruncated: true, VulnsUnsupported: true,
}

// vulnIDRe bounds one CVE identifier (CVE-…, GHSA-…, RHEL-… style).
var vulnIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{1,63}$`)

// ErrImageVulnsFormat is returned when a result is not a valid
// image.vulns-v1 document.
var ErrImageVulnsFormat = errors.New("dockerhost: not an image.vulnerabilities result")

const (
	// maxVulnsSummary is the decoded summary size bound.
	maxVulnsSummary = 1 << 20
	// maxVulnsTop is the top-N list bound (N = 25).
	maxVulnsTop = 25
	// maxVulnsCount bounds one severity count and the total.
	maxVulnsCount = 1000000
	// maxVulnsTargets bounds the number of scanned targets (coverage).
	maxVulnsTargets = 1000
	// maxVulnsDBAgeH bounds the reported database age in whole hours.
	maxVulnsDBAgeH = 100000
	// maxVulnsFixed bounds a fixed version string.
	maxVulnsFixed = 200
)

// ImageVuln is one CVE of the top-N list.
type ImageVuln struct {
	ID       string // e.g. "CVE-2024-28085"
	Severity string // one of CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	Fixed    string // fixed version, "" when unfixed/unknown
}

// ImageVulns is a parsed image.vulnerabilities result. When Status is not
// VulnsOK, Present/Trivy/DBVersion/DBAgeH/Platform may carry what the host
// reported and Severity/Total/Targets/Top are empty: the observation is
// "unknown", never zero.
type ImageVulns struct {
	Phase     string // "done" or "precheck"
	Reason    string // fixed reason for precheck
	Present   bool   // the host has Trivy
	Status    string // one of the Vulns* statuses
	Trivy     string // trivy version
	DBVersion string // vulnerability database version
	DBAgeH    *int   // database age in whole hours, nil when unknown
	Image     string // digest reference that was requested
	Platform  string // os/arch(/variant) of the scanned image, "" for index digests
	Cached    bool   // result served from the 24 h host cache
	Severity  map[string]int
	Total     int
	Targets   int
	Top       []ImageVuln
}

type vulnsDoc struct {
	Format    string   `json:"format"`
	Phase     string   `json:"phase"`
	Reason    string   `json:"reason"`
	Present   *bool    `json:"present"`
	Status    string   `json:"status"`
	Trivy     string   `json:"trivy"`
	DBVersion string   `json:"dbver"`
	DBAge     *float64 `json:"dbage"`
	Image     string   `json:"image"`
	Platform  string   `json:"platform"`
	Cached    *bool    `json:"cached"`
	Summary   string   `json:"summary"`
}

type vulnsSummary struct {
	Severity map[string]int `json:"severity"`
	Total    int            `json:"total"`
	Targets  int            `json:"targets"`
	Top      []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Fixed    string `json:"fixed"`
	} `json:"top"`
}

// vulnText bounds and sanitizes one host-provided text field: printable
// ASCII only, everything else dropped. The result is rendered as text.
func vulnText(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// decodeVulnsField decodes one base64 host-text field with a size bound
// and a printable check (one line, no unsafe runes).
func decodeVulnsField(s string, max int) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || !printable(string(b), max) {
		return "", errors.New("bad field")
	}
	return string(b), nil
}

// ParseImageVulns parses and validates an image.vulns-v1 result document.
// Every field is untrusted host data: statuses, ids, versions and counts
// are checked against explicit bounds, and a summary is only accepted for
// a completed scan (status ok) — a stale/failed/absent result can never
// carry CVE numbers.
func ParseImageVulns(result []byte) (ImageVulns, error) {
	var doc vulnsDoc
	if err := json.Unmarshal(result, &doc); err != nil {
		return ImageVulns{}, fmt.Errorf("%w: %v", ErrImageVulnsFormat, err)
	}
	if doc.Format != vulnsFormat {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	out := ImageVulns{}
	switch doc.Phase {
	case "done":
		out.Phase = "done"
	case "precheck":
		out.Phase = "precheck"
		// json.Unmarshal replaces invalid UTF-8 with U+FFFD instead of
		// failing; a reason that lost bytes is hostile input, not text.
		if strings.ContainsRune(doc.Reason, '\uFFFD') {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		out.Reason = vulnText(doc.Reason, 300)
		return out, nil
	default:
		return ImageVulns{}, ErrImageVulnsFormat
	}
	if !vulnStatusSet[doc.Status] {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	out.Status = doc.Status
	if doc.Present != nil {
		out.Present = *doc.Present
	}
	if doc.Trivy != "" {
		t, err := decodeVulnsField(doc.Trivy, 100)
		if err != nil {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		out.Trivy = t
	}
	if doc.DBVersion != "" {
		d, err := decodeVulnsField(doc.DBVersion, 20)
		if err != nil || !dbVersionRe.MatchString(d) {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		out.DBVersion = d
	}
	if doc.DBAge != nil {
		if *doc.DBAge < 0 || *doc.DBAge > maxVulnsDBAgeH || *doc.DBAge != float64(int(*doc.DBAge)) {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		h := int(*doc.DBAge)
		out.DBAgeH = &h
	}
	if doc.Image != "" {
		if !digestRe.MatchString(doc.Image) {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		out.Image = doc.Image
	}
	if doc.Platform != "" {
		p, err := decodeVulnsField(doc.Platform, 100)
		if err != nil {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		parts := strings.Split(p, "/")
		if len(parts) != 2 && len(parts) != 3 {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		variant := ""
		if len(parts) == 3 {
			variant = parts[2]
		}
		platform := platformFrom(parts[0], parts[1], variant)
		if platform == "" {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		out.Platform = platform
	}
	if doc.Cached != nil {
		out.Cached = *doc.Cached
	}
	if out.Status != VulnsOK {
		// Unknown states never carry findings, even if the host sent some.
		return out, nil
	}
	summary, err := base64.StdEncoding.DecodeString(doc.Summary)
	if err != nil || len(summary) == 0 || len(summary) > maxVulnsSummary {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	var sum vulnsSummary
	if err := json.Unmarshal(summary, &sum); err != nil {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	if len(sum.Severity) != len(vulnSeverityOrder) {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	out.Severity = make(map[string]int, len(vulnSeverityOrder))
	total := 0
	for _, sev := range vulnSeverityOrder {
		n, ok := sum.Severity[sev]
		if !ok || n < 0 || n > maxVulnsCount {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		out.Severity[sev] = n
		total += n
	}
	if sum.Total != total || sum.Total > maxVulnsCount {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	if sum.Targets < 0 || sum.Targets > maxVulnsTargets {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	if len(sum.Top) > maxVulnsTop {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	seen := make(map[string]bool, len(sum.Top))
	for _, tv := range sum.Top {
		if !vulnIDRe.MatchString(tv.ID) || !vulnSeveritySet[tv.Severity] {
			return ImageVulns{}, ErrImageVulnsFormat
		}
		if seen[tv.ID] {
			continue // keep the first occurrence; the host must dedupe
		}
		seen[tv.ID] = true
		fixed := vulnText(tv.Fixed, maxVulnsFixed)
		out.Top = append(out.Top, ImageVuln{ID: tv.ID, Severity: tv.Severity, Fixed: fixed})
	}
	if len(out.Top) > sum.Total {
		return ImageVulns{}, ErrImageVulnsFormat
	}
	out.Total = sum.Total
	out.Targets = sum.Targets
	return out, nil
}

var dbVersionRe = regexp.MustCompile(`^[0-9]{1,20}$`)
