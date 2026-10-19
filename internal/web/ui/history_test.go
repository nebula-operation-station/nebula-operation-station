// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

type memEvents struct{ recs []events.Record }

func (m *memEvents) LastEvent() (int64, []byte, error) {
	if len(m.recs) == 0 {
		return 0, nil, nil
	}
	return m.recs[len(m.recs)-1].Seq, m.recs[len(m.recs)-1].Hash, nil
}
func (m *memEvents) InsertEvent(r events.Record) error { m.recs = append(m.recs, r); return nil }

type fakeEvents struct {
	pub  ed25519.PublicKey
	recs []events.Record
}

func (f *fakeEvents) ListEvents(context.Context, *pb.ListEventsRequest, ...grpc.CallOption) (*pb.ListEventsResponse, error) {
	r := &pb.ListEventsResponse{PublicKey: f.pub, HeadSeq: int64(len(f.recs))}
	for _, e := range f.recs {
		r.Events = append(r.Events, &pb.Event{Seq: e.Seq, Body: e.Body, PrevHash: e.PrevHash, Hash: e.Hash, Signature: e.Sig})
	}
	return r, nil
}

func TestHistoryPage(t *testing.T) {
	st := &memEvents{}
	ch := events.NewChain(st, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)))
	_, _ = ch.Append("unlocked", map[string]string{"by": "axel"})
	_, _ = ch.Append("login_failed", map[string]string{"user": "<script>alert(1)</script>"})
	ev := &fakeEvents{pub: ch.PublicKey(), recs: st.recs}

	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	audit := auditlog.New(db, true)
	log := slog.New(auditlog.NewHandler(slog.DiscardHandler, audit))
	log.Info("audit", "kind", "host_created", "host", "<b>web</b>", "user", "axel")

	h := newTestHandler(t, ui.Options{PublicOrigin: "https://nebula.example.org", Events: ev, Audit: audit}).Handler()
	page := getBody(t, h, "/history")
	for _, want := range []string{events.Fingerprint(ch.PublicKey()), "the newest page verified", "unlocked", "host_created", "hash chain intact (1 chained lines)"} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in %s", want, page[strings.Index(page, "Server audit"):])
		}
	}
	if strings.Contains(page, "<script>alert") || strings.Contains(page, "<b>web</b>") {
		t.Fatal("markup rendered")
	}
	if p := getBody(t, h, "/history?kind=unlocked"); strings.Contains(p, "<td>login_failed</td>") || strings.Contains(p, "<td>host_created</td>") || !strings.Contains(p, "<td>unlocked</td>") {
		t.Fatal("kind filter")
	}
	// A changed event is reported.
	ev.recs[0].Body = bytes.Replace(ev.recs[0].Body, []byte("axel"), []byte("eve!"), 1)
	if !strings.Contains(getBody(t, h, "/history"), "verification failed") {
		t.Fatal("tampering not shown")
	}
}
