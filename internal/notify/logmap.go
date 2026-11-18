// SPDX-License-Identifier: AGPL-3.0-or-later

package notify

import "github.com/nebula-operation-station/nebula-operation-station/internal/notifylog"

// logEntry maps an event to the notification log's kind and state codes
// (ADR 0016 D10). ok is false when the log's closed sets have no code for the
// event kind; such an event is sent as before and not recorded. The log only
// accepts codes from its closed sets, so an event is mapped to the code that
// describes it, never to a free-text value such as a vulnerability tier.
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
	case kindVulnDigest, KindIntegrityDigest:
		// Both are summaries of held or open events; the log has one digest
		// kind for them.
		return notifylog.KindDigest, notifylog.StateSummary, true
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
	}
	return "", "", false
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
		Host:        logLabel(e.Host, notifylog.MaxHost),
		State:       state,
		ExecutionID: logLabel(e.ExecutionID, notifylog.MaxExecutionID),
		Link:        e.logLink,
	}, true
}
