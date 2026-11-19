// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import "github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"

// logEntry maps an event to the notification log's kind and state codes
// (ADR 0016 D10). ok is false only when the event kind is not one of the
// kinds this package sends (a kind with no code cannot be stored, so it is
// logged at debug level and not recorded). Every kind this package sends has
// a code: TestEveryNotifyKindHasLogCode keeps this table complete. The log
// only accepts codes from its closed sets, so an event is mapped to the code
// that describes it, never to a free-text value such as a vulnerability tier.
func logEntry(e Event) (kind notifylog.KindCode, state notifylog.StateCode, ok bool) {
	switch e.Kind {
	case kindVulnKEVNew, kindVulnCriticalNew:
		// The event's state is the tier; the log records that a new finding
		// was reported.
		return notifylog.KindCode(e.Kind), notifylog.StateNew, true
	case kindVulnHermesStale, kindVulnFeedStale:
		return notifylog.KindCode(e.Kind), notifylog.StateStale, true
	case kindVulnFeedRegressed:
		return notifylog.KindCode(e.Kind), notifylog.StateRegressed, true
	case kindVulnFeedMarkReset:
		return notifylog.KindCode(e.Kind), notifylog.StateReset, true
	case KindLeaseExpiring:
		return notifylog.KindLeaseExpiring, notifylog.StateExpiring, true
	case KindLeaseRunFailed:
		return notifylog.KindLeaseRunFailed, notifylog.StateFailed, true
	case KindDailyDigest, kindVulnDigest, KindIntegrityDigest:
		// Both are summaries of held or open events; the log has one digest
		// kind for them.
		return notifylog.KindDigest, notifylog.StateSummary, true
	case KindExecution:
		return notifylog.KindExecution, executionState(e.State), true
	case KindOpsState:
		// The event reports the host's new ops state; the log records that
		// the state changed (the state text is not stored).
		return notifylog.KindOpsState, notifylog.StateChanged, true
	case KindHostKeyMismatch:
		return notifylog.KindHostKeyMismatch, notifylog.StateMismatch, true
	case KindOpsAgentSettingsChanged:
		return notifylog.KindOpsSettingsChanged, notifylog.StateChanged, true
	case KindTest:
		return notifylog.KindTest, notifylog.StateTest, true
	case KindExecutorLocked:
		return notifylog.KindExecutorLocked, notifylog.StateLocked, true
	}
	switch IntegrityKind(e.Kind) {
	case IntegrityNOSMismatch:
		return notifylog.KindCode(e.Kind), notifylog.StateMismatch, true
	case IntegrityHostChange:
		return notifylog.KindCode(e.Kind), notifylog.StateChanged, true
	case IntegrityScanIncomplete:
		return notifylog.KindCode(e.Kind), notifylog.StateIncomplete, true
	case IntegrityBaselineTamper:
		return notifylog.KindCode(e.Kind), notifylog.StateTamper, true
	case IntegrityReferenceConflict:
		return notifylog.KindIntegrityReferenceConflict, notifylog.StateConflict, true
	}
	return "", "", false
}

// executionState maps the state of an execution event to a log state. The
// executions package sends WAITING, WARNING (some hosts failed) or FAILED;
// any other text is logged as "other" rather than dropped.
func executionState(s string) notifylog.StateCode {
	switch s {
	case "WAITING":
		return notifylog.StateWaiting
	case "WARNING":
		return notifylog.StatePartial
	case "FAILED":
		return notifylog.StateFailed
	}
	return notifylog.StateOther
}

// newRecord builds the log record of e without an outcome. ok is false when
// logEntry has no code for e.
func newRecord(e Event) (r notifylog.Record, ok bool) {
	kind, state, ok := logEntry(e)
	if !ok {
		return notifylog.Record{}, false
	}
	return notifylog.Record{
		Kind:        kind,
		Host:        logHost(e.Host),
		State:       state,
		ExecutionID: logExecutionID(e.ExecutionID),
		Link:        e.logLink,
	}, true
}
