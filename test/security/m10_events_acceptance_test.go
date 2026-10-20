// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func records(es []*pb.Event) []events.Record {
	out := make([]events.Record, 0, len(es))
	for _, e := range es {
		out = append(out, events.Record{Seq: e.GetSeq(), Body: e.GetBody(), PrevHash: e.GetPrevHash(), Hash: e.GetHash(), Sig: e.GetSignature()})
	}
	return out
}

// M10-1: security-relevant executor steps end up in the signed chain, and
// the chain survives a restart with the same key.
func TestExecutorEventsAreSignedAndChained(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	h.openSession()
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	resp, err := h.client.ListEvents(h.ctx(), &pb.ListEventsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(resp.GetPublicKey())
	recs := records(resp.GetEvents())
	if len(recs) == 0 || int64(len(recs)) != resp.GetHeadSeq() {
		t.Fatalf("%d events, head %d", len(recs), resp.GetHeadSeq())
	}
	if err := events.Verify(pub, recs, nil); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range recs {
		var b events.Body
		if err := json.Unmarshal(r.Body, &b); err != nil {
			t.Fatal(err)
		}
		kinds[b.Kind] = true
	}
	if !kinds["unlocked"] {
		t.Fatalf("no unlock event: %v", kinds)
	}

	// A restart continues the same chain with the same key.
	dir, id := h.dataDir, h.id
	h.stop()
	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	h2.unlock()
	resp2, err := h2.client.ListEvents(h2.ctx(), &pb.ListEventsRequest{AfterSeq: resp.GetHeadSeq() - 1})
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.PublicKey(resp2.GetPublicKey()).Equal(pub) {
		t.Fatal("the event key changed across a restart")
	}
	more := records(resp2.GetEvents())
	if len(more) < 2 {
		t.Fatalf("%d events after restart", len(more))
	}
	if err := events.Verify(pub, more, recs[len(recs)-2].Hash); err != nil {
		t.Fatal(err)
	}
	newest, err := h2.client.ListEvents(h2.ctx(), &pb.ListEventsRequest{Newest: true, Limit: 2})
	if err != nil || len(newest.GetEvents()) != 2 || newest.GetEvents()[1].GetSeq() != newest.GetHeadSeq() {
		t.Fatalf("%v %v", newest, err)
	}
	if _, err := h2.client.ListEvents(h2.ctx(), &pb.ListEventsRequest{Limit: 5000}); err == nil {
		t.Fatal("oversized page accepted")
	} else {
		wantCode(t, err, codes.InvalidArgument, "limit")
	}
}
