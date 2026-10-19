// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

type eventStore struct{ recs []events.Record }

func (s *eventStore) LastEvent() (int64, []byte, error) {
	if len(s.recs) == 0 {
		return 0, nil, nil
	}
	return s.recs[len(s.recs)-1].Seq, s.recs[len(s.recs)-1].Hash, nil
}

func (s *eventStore) InsertEvent(r events.Record) error { s.recs = append(s.recs, r); return nil }

type eventsClient struct {
	pb.ExecutorServiceClient
	pub  ed25519.PublicKey
	recs []events.Record
}

func (c *eventsClient) ListEvents(_ context.Context, in *pb.ListEventsRequest, _ ...grpc.CallOption) (*pb.ListEventsResponse, error) {
	limit := int(in.GetLimit())
	after := in.GetAfterSeq()
	if in.GetNewest() {
		after = max(int64(len(c.recs)-limit), 0)
	}
	r := &pb.ListEventsResponse{PublicKey: c.pub, HeadSeq: int64(len(c.recs))}
	for _, e := range c.recs {
		if e.Seq > after && len(r.Events) < limit {
			r.Events = append(r.Events, &pb.Event{Seq: e.Seq, Body: e.Body, PrevHash: e.PrevHash, Hash: e.Hash, Signature: e.Sig})
		}
	}
	return r, nil
}

func chainClient(t *testing.T, n int) *eventsClient {
	t.Helper()
	st := &eventStore{}
	ch := events.NewChain(st, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)))
	for i := 0; i < n; i++ {
		if _, err := ch.Append("login_succeeded", map[string]string{"user": "axel\x1b[2J"}); err != nil {
			t.Fatal(err)
		}
	}
	return &eventsClient{pub: ch.PublicKey(), recs: st.recs}
}

func TestEventsVerifyAndList(t *testing.T) {
	c := chainClient(t, 1500)
	var out bytes.Buffer
	if err := eventsCmd(context.Background(), c, []string{"verify"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "verified    1500 events") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := eventsCmd(context.Background(), c, []string{"--limit", "3"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  1500  ") || strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "(3 of 1500 events") {
		t.Fatal(out.String())
	}
	out.Reset()
	if err := eventsCmd(context.Background(), c, []string{"list", "--after", "0", "--limit", "1", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), `{"body":{"attrs":`) || !strings.Contains(out.String(), `"seq":1`) {
		t.Fatal(out.String())
	}
	// A changed event fails verification.
	c.recs[700].Body = bytes.Replace(c.recs[700].Body, []byte("axel"), []byte("eve!"), 1)
	if err := eventsCmd(context.Background(), c, []string{"verify"}, &out); err == nil {
		t.Fatal("tampering not detected")
	}
	// A dropped event between pages fails too.
	c = chainClient(t, 1200)
	c.recs = append(c.recs[:1000], c.recs[1001:]...)
	if err := eventsCmd(context.Background(), c, []string{"verify"}, &out); err == nil {
		t.Fatal("gap not detected")
	}
}
