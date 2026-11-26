// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/notify"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Integrity notifications of the server (IG-08, decisions (e) option 2 in
// docs/implementation/integrity-wiring-decisions.md). The server is the only
// caller of notify.NewIntegrityGate. This file wires the gate to the
// notifier and feeds it the executor's open I2 baseline tamper findings
// (`integrity.baseline_tamper`). Messages carry fixed text, the host label
// and the class code only; no host path and no digest reaches them.
const (
	// integrityNotifyInterval is the period of the executor read that feeds
	// the gate. The gate's hourly limit and digest decide what is sent.
	integrityNotifyInterval = 5 * time.Minute
	// integrityTamperClass is the class code of an I2 baseline tamper message.
	// The integritystore class is "baseline-digest-mismatch"; the gate accepts
	// only a-z, 0-9 and '_' in a class, so the underscore form is sent.
	integrityTamperClass = "baseline_digest_mismatch"
	// integrityTamperSeverity is the severity of that class (integritystore
	// table: ClassBaselineDigestMismatch is high).
	integrityTamperSeverity = notify.SeverityHigh
	// integrityNotifyRefusedMsg is the fixed log message for an event the gate
	// refused. The event text is never logged: it may carry host data.
	integrityNotifyRefusedMsg = "integrity notify: event refused by the gate"
)

func init() {
	registerServerFeature(serverFeature{name: "integrity-notify", pages: wireIntegrityNotify})
}

// wireIntegrityNotify starts the integrity notification loop. Without a
// notifier that has a provider there is nothing to send, and the server starts
// without the loop. An invalid public origin is an error: the gate needs an
// absolute URL to build finding links.
func wireIntegrityNotify(d serverDeps, _ *http.ServeMux) error {
	if d.notifier == nil || !d.notifier.Enabled() {
		return nil
	}
	gate, err := notify.NewIntegrityGate(d.notifier, d.cfg.PublicOrigin, time.Now)
	if err != nil {
		return fmt.Errorf("integrity notifications: %w", err)
	}
	var read integrityStatusReader
	if d.exec != nil {
		read = lazyIntegrityStatus(d.exec)
	}
	if err := d.run(func(ctx context.Context) { runIntegrityNotify(ctx, gate, read, d.log) }); err != nil {
		return fmt.Errorf("start integrity notifications: %w", err)
	}
	return nil
}

// runIntegrityNotify syncs the gate with the executor's status every
// integrityNotifyInterval until ctx ends. The gate's digest is flushed first
// so a quiet hour still gets its summary.
func runIntegrityNotify(ctx context.Context, g *notify.IntegrityGate, read integrityStatusReader, log *slog.Logger) {
	ticker := time.NewTicker(integrityNotifyInterval)
	defer ticker.Stop()
	var open map[notify.IntegrityKey]bool
	for {
		g.Flush(ctx)
		var err error
		open, err = syncIntegrityTamper(ctx, g, read, open, log)
		if err != nil {
			log.Warn(integrityReadFailedMsg)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// syncIntegrityTamper submits every open baseline tamper finding of the
// executor to g and returns the keys that are open now. A finding that was open
// in prev and is not open now is forgotten by the gate, so it notifies again if
// it opens later. A failed read returns prev unchanged and an error: nothing is
// forgotten on a read failure.
func syncIntegrityTamper(ctx context.Context, g *notify.IntegrityGate, read integrityStatusReader, prev map[notify.IntegrityKey]bool, log *slog.Logger) (map[notify.IntegrityKey]bool, error) {
	if read == nil {
		return prev, nil
	}
	rctx, cancel := context.WithTimeout(ctx, integrityExecutorTimeout)
	defer cancel()
	resp, err := read(rctx, &pb.GetIntegrityStatusRequest{})
	if err != nil {
		return prev, fmt.Errorf("read executor status: %w", err)
	}
	cur := make(map[notify.IntegrityKey]bool, len(resp.GetBaselineTamperFindings()))
	for _, f := range resp.GetBaselineTamperFindings() {
		key := notify.NewIntegrityKey(f.GetHostId(), integrityTamperClass, "")
		// Open at the executor counts as open here, even if the send fails
		// or the gate refuses the event: it must not be forgotten.
		cur[key] = true
		ev := notify.IntegrityEvent{
			Kind:     notify.IntegrityBaselineTamper,
			Host:     f.GetHostId(),
			Class:    integrityTamperClass,
			Severity: integrityTamperSeverity,
			Count:    int(f.GetCount()),
		}
		if _, err := g.Submit(ctx, ev, key); err != nil {
			log.Warn(integrityNotifyRefusedMsg)
		}
	}
	for k := range prev {
		if !cur[k] {
			g.Forget(k)
		}
	}
	return cur, nil
}
