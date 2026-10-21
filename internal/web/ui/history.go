// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// History (M10-1): the executor's signed events, verified here with the
// key the executor reports, and the server's own audit lines.

// EventSource reads the executor's event chain.
type EventSource interface {
	ListEvents(ctx context.Context, in *pb.ListEventsRequest, opts ...grpc.CallOption) (*pb.ListEventsResponse, error)
}

// AuditStore lists the server's audit lines (internal/auditlog.Store).
type AuditStore interface {
	List(ctx context.Context, before int64, limit int, kind string) ([]auditlog.Entry, error)
	VerifyHead(ctx context.Context) (int, []byte, error)
}

const historyPage = 100

var kindRe = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

type historyRow struct {
	Seq                    int64
	Time, Kind, User, Text string
}

type historyData struct {
	EventsUnavailable bool
	EventsVerified    bool
	EventsError       string
	Fingerprint       string
	EventsHead        int64
	// KeyChanges counts how often the event key changed (restores onto a
	// new machine).
	KeyChanges       int
	Events           []historyRow
	Audit            []historyRow
	AuditUnavailable bool
	Chain            string
	Kind             string
	Older            int64
}

func attrsText(m map[string]string, skip ...string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		skipped := false
		for _, s := range skip {
			skipped = skipped || k == s
		}
		if !skipped {
			parts = append(parts, k+"="+m[k])
		}
	}
	return strings.Join(parts, " ")
}

func (h *Handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	if h.events == nil && h.auditLog == nil {
		h.render(w, r, pageData{Title: "History", Active: "history", Content: "empty"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	d := &historyData{}
	if k := r.URL.Query().Get("kind"); kindRe.MatchString(k) {
		d.Kind = k
	}
	var before int64
	if b, err := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64); err == nil && b > 0 {
		before = b
	}
	if h.events != nil && before == 0 {
		resp, err := h.events.ListEvents(ctx, &pb.ListEventsRequest{Newest: true, Limit: historyPage})
		if err != nil {
			h.log.Error("list executor events", "error", err)
			d.EventsUnavailable = true
		} else {
			pub := ed25519.PublicKey(resp.GetPublicKey())
			d.Fingerprint, d.EventsHead = events.Fingerprint(pub), resp.GetHeadSeq()
			var recs []events.Record
			for _, e := range resp.GetEvents() {
				recs = append(recs, events.Record{Seq: e.GetSeq(), Body: e.GetBody(), PrevHash: e.GetPrevHash(), Hash: e.GetHash(), Sig: e.GetSignature()})
			}
			var keys []events.Key
			for _, k := range resp.GetKeys() {
				keys = append(keys, events.Key{FirstSeq: k.GetFirstSeq(), PublicKey: k.GetPublicKey()})
			}
			if len(keys) > 1 {
				d.KeyChanges = len(keys) - 1
			}
			if err := events.VerifyKeys(events.KeysOr(keys, pub), recs, nil); err != nil {
				d.EventsError = err.Error()
			} else {
				d.EventsVerified = true
			}
			for i := len(recs) - 1; i >= 0; i-- {
				var b events.Body
				if err := json.Unmarshal(recs[i].Body, &b); err != nil {
					continue
				}
				if d.Kind != "" && b.Kind != d.Kind {
					continue
				}
				d.Events = append(d.Events, historyRow{Seq: recs[i].Seq, Time: b.Time, Kind: b.Kind, Text: attrsText(b.Attrs, "level")})
			}
		}
	}
	if h.auditLog != nil {
		list, err := h.auditLog.List(ctx, before, historyPage, d.Kind)
		if err != nil {
			h.log.Error("list audit log", "error", err)
			d.AuditUnavailable = true
		}
		chained := false
		for _, e := range list {
			chained = chained || e.Chained
			d.Audit = append(d.Audit, historyRow{Seq: e.Seq, Time: e.At.UTC().Format("2006-01-02 15:04:05 MST"), Kind: e.Kind, User: e.User,
				Text: attrsText(e.Attrs, "user")})
		}
		if len(list) == historyPage {
			d.Older = list[len(list)-1].Seq
		}
		if chained {
			if n, head, err := h.auditLog.VerifyHead(ctx); err != nil {
				d.Chain = "hash chain broken: " + err.Error()
			} else {
				// The head hash lets an operator notice a chain rewritten
				// from the start: note it down elsewhere and compare.
				d.Chain = "hash chain intact (" + strconv.Itoa(n) + " chained lines, head " + hex.EncodeToString(head) + ")"
			}
		}
	}
	h.render(w, r, pageData{Title: "History", Active: "history", Content: "history", History: d})
}
