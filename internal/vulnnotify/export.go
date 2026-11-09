// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Export formats.
const (
	FormatCSV  = "csv"
	FormatJSON = "json"
)

// AuditKindExport is the audit log kind of an export.
const AuditKindExport = "vuln.export"

// Export limits.
const (
	// MaxExportFindings bounds one export.
	MaxExportFindings = 200_000
	// maxCell bounds one exported text value (runes).
	maxCell = 256
	// maxAliases bounds the aliases exported per finding.
	maxAliases = 16
)

// ErrExport is returned for a refused export (bad format, missing actor,
// too many findings). It wraps no secret.
var ErrExport = errors.New("vulnerability export refused")

// advisoryIDRe is the D2 vulnerability ID pattern; only such IDs get a
// NOS-built advisory link.
var advisoryIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._-]{1,63}$`)

// Auditor records an export; *auditlog.Store implements it.
type Auditor interface {
	Append(ctx context.Context, kind string, attrs map[string]string) error
}

// ExportRequest is one admin export. The caller has checked that Actor is
// an admin (D9: admin only).
type ExportRequest struct {
	Format   string
	Actor    string
	Findings []vulnstore.Finding
}

// ExportRow is one exported finding: structured fields only. It carries no
// assessment text, admin reasons, host labels, addresses, tokens or other
// inventory data beyond the subject ID.
type ExportRow struct {
	FindingKey       string   `json:"finding_key"`
	SubjectKind      string   `json:"subject_kind"`
	SubjectID        string   `json:"subject_id"`
	ImageDigest      string   `json:"image_digest,omitempty"`
	State            string   `json:"state"`
	ClosedBy         string   `json:"closed_by,omitempty"`
	StateLabel       string   `json:"state_label"`
	VulnID           string   `json:"vuln_id"`
	Aliases          []string `json:"aliases,omitempty"`
	Ecosystem        string   `json:"ecosystem"`
	Component        string   `json:"component"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	FixState         string   `json:"fix_state"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	Tier             string   `json:"tier"`
	CVSSScore        string   `json:"cvss_score,omitempty"`
	KEV              bool     `json:"kev"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	// FixFlow names the NOS flow that fixes the finding (os_update,
	// container_update, vendor_advisory); empty without a fixed version.
	FixFlow string `json:"fix_flow,omitempty"`
	// AdvisoryLink is a NOS-built advisory link for the vulnerability ID.
	AdvisoryLink string `json:"advisory_link,omitempty"`
}

var csvHeader = []string{"finding_key", "subject_kind", "subject_id", "image_digest", "state", "closed_by", "state_label",
	"vuln_id", "aliases", "ecosystem", "component", "installed_version", "fix_state", "fixed_version", "tier",
	"cvss_score", "kev", "first_seen", "last_seen", "fix_flow", "advisory_link"}

func (r ExportRow) csvRecord() []string {
	return []string{r.FindingKey, r.SubjectKind, r.SubjectID, r.ImageDigest, r.State, r.ClosedBy, r.StateLabel,
		r.VulnID, strings.Join(r.Aliases, " "), r.Ecosystem, r.Component, r.InstalledVersion, r.FixState, r.FixedVersion,
		r.Tier, r.CVSSScore, strconv.FormatBool(r.KEV), r.FirstSeen, r.LastSeen, r.FixFlow, r.AdvisoryLink}
}

// stateLabel renders the D6 state; hermes_unconfirmed closures are never
// shown as plainly fixed.
func stateLabel(f vulnstore.Finding) string {
	if f.State == vulnstore.StateFixed {
		switch f.ClosedBy {
		case vulnstore.ClosedByHermesUnconfirmed:
			return "closed by Hermes, not confirmed by NOS"
		case vulnstore.ClosedByNOSInventory:
			return "fixed (confirmed by NOS inventory)"
		case vulnstore.ClosedBySubjectRemoved:
			return "fixed (subject removed)"
		case vulnstore.ClosedByAdminConfirmed:
			return "fixed (confirmed by admin)"
		}
	}
	return plain(string(f.State), maxCell)
}

// AdvisoryLink returns the NOS-built advisory link for a vulnerability ID,
// or "" when the ID does not match the D2 pattern.
func AdvisoryLink(id string) string {
	if !advisoryIDRe.MatchString(id) {
		return ""
	}
	return "https://osv.dev/vulnerability/" + url.PathEscape(id)
}

func fixFlow(f vulnstore.Finding) string {
	if f.Record.Fix.State != vulnfinding.FixFixed {
		return ""
	}
	switch f.Subject.Kind {
	case vulnfinding.SubjectHost:
		return "os_update"
	case vulnfinding.SubjectImage:
		return "container_update"
	case vulnfinding.SubjectDevice:
		return "vendor_advisory"
	}
	return ""
}

func timeCell(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Row builds the export row of f. Every string from Hermes or a feed is
// reduced to bounded printable text.
func Row(f vulnstore.Finding) ExportRow {
	return row(f, func(s string) string { return plain(s, maxCell) })
}

// csvCell is the CSV form of an untrusted value: the formula prefix is
// decided on the raw value too, because plain turns tab, CR and NBSP into
// '?'.
func csvCell(s string) string {
	c := plain(s, maxCell)
	if formulaLike(s) || formulaLike(c) {
		return "'" + c
	}
	return c
}

func row(f vulnstore.Finding, p func(string) string) ExportRow {
	r := f.Record
	row := ExportRow{
		FindingKey: f.Key.String(), SubjectKind: p(string(f.Subject.Kind)), SubjectID: p(f.Subject.ID),
		ImageDigest: p(f.Subject.ImageDigest), State: p(string(f.State)), ClosedBy: p(string(f.ClosedBy)),
		StateLabel: stateLabel(f), VulnID: p(r.Vuln.ID), Ecosystem: p(r.Ecosystem),
		FixState: p(string(r.Fix.State)), FixedVersion: p(r.Fix.Version), Tier: TierName(f.EpisodePeakTier),
		KEV: kevListed(f), FirstSeen: timeCell(f.FirstSeen), LastSeen: timeCell(f.LastSeen),
		FixFlow: fixFlow(f), AdvisoryLink: AdvisoryLink(r.Vuln.ID),
	}
	if r.Component.SourcePackage != "" {
		row.Component, row.InstalledVersion = p(r.Component.SourcePackage), p(r.Component.SourceVersion)
	} else {
		row.Component, row.InstalledVersion = p(r.Component.Model), p(r.Component.Firmware)
	}
	for i, a := range r.Vuln.Aliases {
		if i == maxAliases {
			break
		}
		row.Aliases = append(row.Aliases, p(a))
	}
	if c := r.Scores.CVSS; c != nil {
		row.CVSSScore = strconv.FormatFloat(c.BaseScore, 'f', 1, 64)
	}
	return row
}

// formulaLike reports whether a spreadsheet may read s as a formula: it
// starts with tab or CR, or its first character after leading whitespace
// (including NBSP and other Unicode spaces) is '=', '+', '-' or '@'.
func formulaLike(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '\t' || s[0] == '\r' {
		return true
	}
	t := strings.TrimLeftFunc(s, unicode.IsSpace)
	return t != "" && strings.ContainsRune("=+-@", rune(t[0]))
}

// csvSafe neutralises spreadsheet formulas (D9): a formula-like cell (see
// formulaLike) gets a leading "'".
func csvSafe(s string) string {
	if formulaLike(s) {
		return "'" + s
	}
	return s
}

// Export audits the export and writes the findings to w as CSV or JSON.
// The audit entry is written first; when it fails nothing is exported.
func Export(ctx context.Context, a Auditor, w io.Writer, req ExportRequest) error {
	if req.Format != FormatCSV && req.Format != FormatJSON {
		return fmt.Errorf("vulnnotify: export format: %w", ErrExport)
	}
	if strings.TrimSpace(req.Actor) == "" || a == nil {
		return fmt.Errorf("vulnnotify: export without actor or audit log: %w", ErrExport)
	}
	if len(req.Findings) > MaxExportFindings {
		return fmt.Errorf("vulnnotify: export of %d findings exceeds %d: %w", len(req.Findings), MaxExportFindings, ErrExport)
	}
	if err := a.Append(ctx, AuditKindExport, map[string]string{"user": plain(req.Actor, 64), "format": req.Format,
		"findings": strconv.Itoa(len(req.Findings))}); err != nil {
		return fmt.Errorf("vulnnotify: audit export: %w", err)
	}
	if req.Format == FormatJSON {
		if err := exportJSON(w, req.Findings); err != nil {
			return fmt.Errorf("vulnnotify: write json export: %w", err)
		}
		return nil
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return fmt.Errorf("vulnnotify: write csv export: %w", err)
	}
	for _, f := range req.Findings {
		rec := row(f, csvCell).csvRecord()
		for i := range rec {
			rec[i] = csvSafe(rec[i])
		}
		if err := cw.Write(rec); err != nil {
			return fmt.Errorf("vulnnotify: write csv export: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("vulnnotify: write csv export: %w", err)
	}
	return nil
}

// exportJSON streams {"format":"nos-vuln-findings-v1","findings":[...]}
// to w one row at a time, so memory stays bounded by one row.
func exportJSON(w io.Writer, fs []vulnstore.Finding) error {
	if _, err := io.WriteString(w, `{"format":"nos-vuln-findings-v1","findings":[`); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	for i, f := range fs {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if err := enc.Encode(Row(f)); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "]}\n")
	return err
}
