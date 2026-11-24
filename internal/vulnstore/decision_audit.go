// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"fmt"
)

// Audit kinds of the maintainer decisions (ADR 0011 Q4). Each decision
// method writes exactly one line of its kind in the transaction that
// writes the decision.
const (
	// AuditVulnAcceptedRisk: a finding was set to accepted_risk.
	AuditVulnAcceptedRisk = "vuln.accepted_risk_set"
	// AuditVulnFalsePositive: a finding was set to false_positive.
	AuditVulnFalsePositive = "vuln.false_positive_set"
	// AuditVulnHoldConfirmed: a held closure was confirmed (closure path 6).
	AuditVulnHoldConfirmed = "vuln.hold_confirmed"
	// AuditVulnHoldSuperseded: a confirm found the hold superseded and
	// dropped it; the finding is unchanged.
	AuditVulnHoldSuperseded = "vuln.hold_superseded"
	// AuditVulnHoldDiscarded: a held closure was discarded (closure path 7).
	AuditVulnHoldDiscarded = "vuln.hold_discarded"
	// AuditVulnMarkReset: a source's high-water mark was reset (D5).
	AuditVulnMarkReset = "vuln.feed_mark_reset"
)

// DecisionAuditor runs a maintainer decision in a write transaction that
// also carries its audit line: fn writes the decision through tx and the
// line through appendLine, and the auditor commits both or neither. It has
// the shape of AgentAuditor; the server passes its audit log
// (auditlog.Store.WithTx), whose transaction must run on the store's
// database (server.db). A transaction on another database fails at the
// store's write lock, because it has no vulnstore tables.
type DecisionAuditor interface {
	WithTx(ctx context.Context, fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error
}

// decisionTx runs fn under the store's lock in audit's transaction, after
// taking the store's write lock in it, as writeTx does for the store's own
// transactions. When fn, the audit line or the commit fails, nothing of
// the decision is stored.
func (s *Store) decisionTx(ctx context.Context, audit DecisionAuditor, fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error {
	if audit == nil {
		return fmt.Errorf("auditor is required: %w", ErrInvalidInput)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return audit.WithTx(ctx, func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error {
		if _, err := tx.ExecContext(ctx, `UPDATE vuln_store_state SET lock_counter = lock_counter + 1 WHERE id = 1`); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		return fn(tx, appendLine)
	})
}

// appendDecision writes one decision audit line; actor is both the actor
// and the audit user.
func appendDecision(appendLine func(kind string, attrs map[string]string) error, kind, actor string, attrs map[string]string) error {
	attrs["actor"] = actor
	attrs["user"] = actor
	if err := appendLine(kind, attrs); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}
