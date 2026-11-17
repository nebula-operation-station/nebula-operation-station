// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsdigest builds the optional daily digest (spec 13, ADR 0016 D10).
//
// The digest carries counts only. It holds no host name, label, path,
// finding text, log line or model output: every number comes from the
// caller and every word comes from a fixed template in this package. The
// only other text is one NOS link, which the caller validates and passes
// in. The package is a library: it sends nothing and starts no timer.
package opsdigest

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// MaxDigestBytes is the upper bound for the digest text in bytes.
const MaxDigestBytes = 1024

// MaxLinkBytes bounds the NOS link the caller passes in.
const MaxLinkBytes = 256

// Lang selects the fixed text of the digest.
type Lang string

// Supported languages. German is the default of the product (ADR 0016).
const (
	LangDE Lang = "de"
	LangEN Lang = "en"
)

// Sentinel errors. Callers branch on them with errors.Is.
var (
	ErrUnknownLang   = errors.New("opsdigest: unknown language")
	ErrInvalidCount  = errors.New("opsdigest: count must not be negative")
	ErrInvalidLink   = errors.New("opsdigest: invalid NOS link")
	ErrNothingToSend = errors.New("opsdigest: nothing open and empty digests are skipped")
	ErrMissingSource = errors.New("opsdigest: source not set")
	ErrInvalidTime   = errors.New("opsdigest: invalid send time")
	ErrNoLocation    = errors.New("opsdigest: no time zone")
)

// Findings holds the open vulnerability findings per tier and the number of
// them that are on the KEV list. Tiers follow ADR 0011.
type Findings struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	// KEV counts open findings that are KEV-listed.
	KEV int
}

// Input is everything the digest shows. It holds counts only.
type Input struct {
	// OpenUpdates is the number of open update items.
	OpenUpdates int
	// RebootsPending is the number of hosts that wait for a reboot.
	RebootsPending int
	// HostsNotReady is the number of managed hosts that are not READY.
	HostsNotReady int
	// GrantsExpiring is the number of read leases and schedule grants that
	// expire within 7 days.
	GrantsExpiring int
	// Findings holds the open findings per tier and the KEV count.
	Findings Findings
	// FailedRuns24h is the number of failed executions of the last 24 hours.
	FailedRuns24h int
}

// Options controls how the digest is built.
type Options struct {
	// Lang selects the text. Required; there is no implicit default.
	Lang Lang
	// NOSLink is the link into the NOS UI. It must pass validation (see
	// validLink); Build rejects anything else.
	NOSLink string
	// SkipEmpty suppresses the digest on a day with every count at zero.
	// Build then returns ErrNothingToSend.
	SkipEmpty bool
}

// counts returns every number of the input in a fixed order.
func (in Input) counts() []int {
	f := in.Findings
	return []int{
		in.OpenUpdates, in.RebootsPending, in.HostsNotReady, in.GrantsExpiring,
		f.Critical, f.High, f.Medium, f.Low, f.Unknown, f.KEV,
		in.FailedRuns24h,
	}
}

// validate rejects negative counts. A negative count means a broken source.
func (in Input) validate() error {
	for _, n := range in.counts() {
		if n < 0 {
			return ErrInvalidCount
		}
	}
	return nil
}

// empty reports whether every count is zero.
func (in Input) empty() bool {
	for _, n := range in.counts() {
		if n != 0 {
			return false
		}
	}
	return true
}

// Build returns the digest text. The text is plain: no Markdown, no HTML and
// only the one link passed in Options.NOSLink. If the input is empty and
// Options.SkipEmpty is set, Build returns ErrNothingToSend and no text.
func Build(in Input, opt Options) (string, error) {
	if err := in.validate(); err != nil {
		return "", err
	}
	if err := validLink(opt.NOSLink); err != nil {
		return "", err
	}
	empty := in.empty()
	if empty && opt.SkipEmpty {
		return "", ErrNothingToSend
	}
	var b strings.Builder
	switch opt.Lang {
	case LangDE:
		writeDE(&b, in, empty)
	case LangEN:
		writeEN(&b, in, empty)
	default:
		return "", fmt.Errorf("build digest %q: %w", opt.Lang, ErrUnknownLang)
	}
	writeLine(&b, opt.NOSLink)
	if b.Len() > MaxDigestBytes {
		// Unreachable with the fixed templates and a validated link; the
		// check guards the limit if a template ever grows.
		return "", fmt.Errorf("build digest: %d bytes, limit %d", b.Len(), MaxDigestBytes)
	}
	return b.String(), nil
}

func writeDE(b *strings.Builder, in Input, empty bool) {
	if empty {
		writeLine(b, "NOS Tagesübersicht: nichts offen.")
		return
	}
	f := in.Findings
	writeLine(b, "NOS Tagesübersicht")
	writeCount(b, "Offene Updates", in.OpenUpdates)
	writeCount(b, "Neustarts ausstehend", in.RebootsPending)
	writeCount(b, "Hosts nicht READY", in.HostsNotReady)
	writeCount(b, "Grants mit Ablauf in 7 Tagen", in.GrantsExpiring)
	writeLine(b, "Offene Findings: kritisch "+strconv.Itoa(f.Critical)+
		", hoch "+strconv.Itoa(f.High)+
		", mittel "+strconv.Itoa(f.Medium)+
		", niedrig "+strconv.Itoa(f.Low)+
		", unbekannt "+strconv.Itoa(f.Unknown))
	writeCount(b, "Davon in KEV", f.KEV)
	writeCount(b, "Fehlgeschlagene Ausführungen (24 h)", in.FailedRuns24h)
}

func writeEN(b *strings.Builder, in Input, empty bool) {
	if empty {
		writeLine(b, "NOS daily digest: nothing open.")
		return
	}
	f := in.Findings
	writeLine(b, "NOS daily digest")
	writeCount(b, "Open updates", in.OpenUpdates)
	writeCount(b, "Reboots pending", in.RebootsPending)
	writeCount(b, "Hosts not READY", in.HostsNotReady)
	writeCount(b, "Grants expiring within 7 days", in.GrantsExpiring)
	writeLine(b, "Open findings: critical "+strconv.Itoa(f.Critical)+
		", high "+strconv.Itoa(f.High)+
		", medium "+strconv.Itoa(f.Medium)+
		", low "+strconv.Itoa(f.Low)+
		", unknown "+strconv.Itoa(f.Unknown))
	writeCount(b, "Of which KEV", f.KEV)
	writeCount(b, "Failed runs (24 h)", in.FailedRuns24h)
}

// writeLine appends one line of the digest; lines are separated by "\n".
func writeLine(b *strings.Builder, s string) {
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	b.WriteString(s)
}

// writeCount appends "label: n" as one line.
func writeCount(b *strings.Builder, label string, n int) {
	writeLine(b, label+": "+strconv.Itoa(n))
}

// validLink accepts an absolute http or https URL without user info and
// without spaces, control characters or markup characters. The caller checks
// that it points at NOS; this only keeps the text plain.
func validLink(link string) error {
	if link == "" || len(link) > MaxLinkBytes {
		return fmt.Errorf("link length %d: %w", len(link), ErrInvalidLink)
	}
	for _, r := range link {
		if r <= ' ' || r == 0x7f || strings.ContainsRune("<>\"'`[]\\", r) {
			return fmt.Errorf("link has a forbidden character: %w", ErrInvalidLink)
		}
	}
	u, err := url.Parse(link)
	if err != nil {
		return fmt.Errorf("link does not parse: %w", ErrInvalidLink)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("link scheme %q: %w", u.Scheme, ErrInvalidLink)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("link needs a host and no user info: %w", ErrInvalidLink)
	}
	return nil
}
