// SPDX-License-Identifier: AGPL-3.0-or-later

package opsdigest

import (
	"context"
	"fmt"
)

// CountSource returns one count. The caller implements it on top of its
// store; the digest only ever sees the number.
type CountSource interface {
	Count(ctx context.Context) (int, error)
}

// FindingSource returns the open findings per tier and the KEV count.
type FindingSource interface {
	Findings(ctx context.Context) (Findings, error)
}

// Sources holds one source per digest number. All fields are required;
// Collect fails if one is nil.
type Sources struct {
	Updates        CountSource
	Reboots        CountSource
	NotReady       CountSource
	GrantsExpiring CountSource
	Findings       FindingSource
	FailedRuns     CountSource
}

// Collect reads every source and returns the digest input. It fails closed:
// if one source fails, no partial digest is returned, so the caller sends
// nothing rather than a wrong number.
func Collect(ctx context.Context, s Sources) (Input, error) {
	var in Input
	if s.Updates == nil || s.Reboots == nil || s.NotReady == nil ||
		s.GrantsExpiring == nil || s.Findings == nil || s.FailedRuns == nil {
		return Input{}, ErrMissingSource
	}
	var err error
	if in.OpenUpdates, err = readCount(ctx, "open updates", s.Updates); err != nil {
		return Input{}, err
	}
	if in.RebootsPending, err = readCount(ctx, "reboots pending", s.Reboots); err != nil {
		return Input{}, err
	}
	if in.HostsNotReady, err = readCount(ctx, "hosts not READY", s.NotReady); err != nil {
		return Input{}, err
	}
	if in.GrantsExpiring, err = readCount(ctx, "grants expiring", s.GrantsExpiring); err != nil {
		return Input{}, err
	}
	if in.Findings, err = s.Findings.Findings(ctx); err != nil {
		return Input{}, fmt.Errorf("count open findings: %w", err)
	}
	if in.FailedRuns24h, err = readCount(ctx, "failed runs", s.FailedRuns); err != nil {
		return Input{}, err
	}
	if err := in.validate(); err != nil {
		return Input{}, fmt.Errorf("collect digest input: %w", err)
	}
	return in, nil
}

// readCount reads one count and wraps the error with what it was counting.
func readCount(ctx context.Context, what string, src CountSource) (int, error) {
	n, err := src.Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count %s: %w", what, err)
	}
	return n, nil
}
