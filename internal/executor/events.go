// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Event listing limits.
const (
	defaultEventPage = 100
	maxEventPage     = 1000
)

// SetEventKey sets the public key ListEvents returns (the chain itself is
// written by the log handler of internal/events).
func (s *Service) SetEventKey(pub ed25519.PublicKey) { s.eventKey = pub }

// ListEvents returns a page of the signed event chain (M10-1).
func (s *Service) ListEvents(_ context.Context, req *pb.ListEventsRequest) (*pb.ListEventsResponse, error) {
	if len(s.eventKey) != ed25519.PublicKeySize {
		return nil, status.Error(codes.FailedPrecondition, "the event chain is not set up")
	}
	limit := int(req.GetLimit())
	switch {
	case limit == 0:
		limit = defaultEventPage
	case limit < 0 || limit > maxEventPage:
		return nil, status.Errorf(codes.InvalidArgument, "limit must be 1 to %d", maxEventPage)
	}
	after := req.GetAfterSeq()
	if after < 0 {
		return nil, status.Error(codes.InvalidArgument, "after_seq must not be negative")
	}
	head, _, err := s.db.LastEvent()
	if err != nil {
		s.log.Error("list events", "error", err)
		return nil, status.Error(codes.Internal, "events unavailable")
	}
	if req.GetNewest() {
		after = max(head-int64(limit), 0)
	}
	recs, err := s.db.Events(after, limit)
	if err != nil {
		s.log.Error("list events", "error", err)
		return nil, status.Error(codes.Internal, "events unavailable")
	}
	keys, err := s.db.EventKeys()
	if err != nil {
		s.log.Error("list events", "error", err)
		return nil, status.Error(codes.Internal, "events unavailable")
	}
	resp := &pb.ListEventsResponse{PublicKey: append([]byte(nil), s.eventKey...), HeadSeq: head}
	for _, k := range keys {
		resp.Keys = append(resp.Keys, &pb.EventKey{FirstSeq: k.FirstSeq, PublicKey: k.PublicKey})
	}
	for _, r := range recs {
		resp.Events = append(resp.Events, &pb.Event{Seq: r.Seq, Body: r.Body, PrevHash: r.PrevHash, Hash: r.Hash, Signature: r.Sig})
	}
	return resp, nil
}
