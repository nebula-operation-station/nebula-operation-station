// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfeed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Limits of the FIRST EPSS daily CSV (ADR 0011 D4).
const (
	// MaxEPSSBytes caps the decompressed CSV (about 10 MiB in 2024).
	MaxEPSSBytes = 256 << 20
	// MaxEPSSRows caps the score rows.
	MaxEPSSRows = 2_000_000
	// MaxEPSSLineBytes caps one line, including the metadata line.
	MaxEPSSLineBytes = 512
)

var (
	// epssNumberRe is a plain decimal probability or percentile.
	epssNumberRe = regexp.MustCompile(`^[0-9]{1,2}(\.[0-9]{1,16})?([eE]-[0-9]{1,2})?$`)
	// epssModelRe is the model version, e.g. "v2023.03.01".
	epssModelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

// epssHeader is the column header the parser accepts.
const epssHeader = "cve,epss,percentile"

// EPSSScore is one CVE's exploit probability on the score date.
type EPSSScore struct {
	// CVE is the CVE ID.
	CVE string
	// Probability is the EPSS score, 0 to 1.
	Probability float64
	// Percentile is the score percentile, 0 to 1.
	Percentile float64
}

// EPSSScores is a parsed EPSS file.
type EPSSScores struct {
	// Model is the model_version of the metadata line.
	Model string
	// Date is the score_date: the content date of the file (D4) and the
	// date of every score in it.
	Date time.Time
	// Scores are the rows in input order.
	Scores []EPSSScore
}

// epssDateLayouts are the score_date forms seen in EPSS files.
var epssDateLayouts = []string{"2006-01-02T15:04:05-0700", time.RFC3339Nano, "2006-01-02"}

// ParseEPSS parses a decompressed EPSS CSV: a metadata line
// "#model_version:<v>,score_date:<date>", the header "cve,epss,percentile"
// and one row per CVE. Rows must have exactly three fields, values in
// [0, 1] and unique CVEs. Use DecompressGzip for the .csv.gz download.
func ParseEPSS(ctx context.Context, r io.Reader) (EPSSScores, error) {
	var out EPSSScores
	br := newBoundedReader(r, MaxEPSSBytes)
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, MaxEPSSLineBytes), MaxEPSSLineBytes)
	seen := make(map[string]struct{})
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSuffix(sc.Text(), "\r")
		switch {
		case line == 1:
			if err := parseEPSSMeta(s, &out); err != nil {
				return EPSSScores{}, fmt.Errorf("epss line 1: %w", err)
			}
			continue
		case line == 2:
			if s != epssHeader {
				return EPSSScores{}, fmt.Errorf("epss line 2: header: %w", ErrFeedMalformed)
			}
			continue
		case s == "":
			continue
		}
		if line%8192 == 0 {
			if err := ctx.Err(); err != nil {
				return EPSSScores{}, fmt.Errorf("epss: %w", err)
			}
		}
		row, err := parseEPSSRow(s)
		if err != nil {
			return EPSSScores{}, fmt.Errorf("epss line %d: %w", line, err)
		}
		if _, dup := seen[row.CVE]; dup {
			return EPSSScores{}, fmt.Errorf("epss %s: duplicate: %w", row.CVE, ErrFeedMalformed)
		}
		seen[row.CVE] = struct{}{}
		if len(out.Scores) >= MaxEPSSRows {
			return EPSSScores{}, fmt.Errorf("epss: more than %d rows: %w", MaxEPSSRows, ErrFeedLimit)
		}
		out.Scores = append(out.Scores, row)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return EPSSScores{}, fmt.Errorf("epss line %d: %w", line+1, ErrFeedLimit)
		}
		return EPSSScores{}, br.fail("epss", err)
	}
	if line < 2 {
		return EPSSScores{}, fmt.Errorf("epss: missing metadata or header: %w", ErrFeedMalformed)
	}
	return out, nil
}

// parseEPSSMeta parses "#model_version:<v>,score_date:<date>". Both keys
// are required; unknown keys are skipped, duplicates rejected.
func parseEPSSMeta(s string, out *EPSSScores) error {
	rest, ok := strings.CutPrefix(s, "#")
	if !ok {
		return fmt.Errorf("metadata line: %w", ErrFeedMalformed)
	}
	if err := checkToken(rest, MaxEPSSLineBytes); err != nil {
		return fmt.Errorf("metadata line: %w", err)
	}
	seen := make(map[string]struct{})
	for _, kv := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(kv, ":")
		if !ok || k == "" {
			return fmt.Errorf("metadata pair: %w", ErrFeedMalformed)
		}
		if _, dup := seen[k]; dup {
			return fmt.Errorf("metadata key repeated: %w", ErrFeedMalformed)
		}
		seen[k] = struct{}{}
		switch k {
		case "model_version":
			if !epssModelRe.MatchString(v) {
				return fmt.Errorf("model_version: %w", ErrFeedMalformed)
			}
			out.Model = v
		case "score_date":
			d, err := parseFeedTime(v, epssDateLayouts...)
			if err != nil {
				return fmt.Errorf("score_date: %w", err)
			}
			out.Date = d
		}
	}
	if out.Model == "" || out.Date.IsZero() {
		return fmt.Errorf("metadata without model_version or score_date: %w", ErrFeedMalformed)
	}
	return nil
}

// parseEPSSRow parses "CVE-YYYY-NNNN,<epss>,<percentile>".
func parseEPSSRow(s string) (EPSSScore, error) {
	f := strings.Split(s, ",")
	if len(f) != 3 {
		return EPSSScore{}, fmt.Errorf("row must have 3 fields: %w", ErrFeedMalformed)
	}
	if !cveIDRe.MatchString(f[0]) {
		return EPSSScore{}, fmt.Errorf("cve: %w", ErrFeedMalformed)
	}
	p, err := parseUnitFloat(f[1])
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s epss: %w", f[0], err)
	}
	q, err := parseUnitFloat(f[2])
	if err != nil {
		return EPSSScore{}, fmt.Errorf("%s percentile: %w", f[0], err)
	}
	return EPSSScore{CVE: f[0], Probability: p, Percentile: q}, nil
}

// parseUnitFloat parses a decimal in [0, 1].
func parseUnitFloat(s string) (float64, error) {
	if !epssNumberRe.MatchString(s) {
		return 0, fmt.Errorf("number: %w", ErrFeedMalformed)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || v < 0 || v > 1 {
		return 0, fmt.Errorf("number out of range: %w", ErrFeedMalformed)
	}
	return v, nil
}
