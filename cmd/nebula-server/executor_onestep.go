// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// lazyExecutor implements the one-step enrollment dialog's executor calls
// (ADR 0013, EN-10). Each one passes the request through unchanged, like
// ProposeEnroll; the executor checks it. Before the executor is connected
// each returns errNotConnected.

// The dialog takes its executor from Options.Enroll; without these methods
// it answers 404.
var _ ui.EnrollOffers = (*lazyExecutor)(nil)

// CreateEnrollOffer passes a one-step enrollment offer creation through.
func (l *lazyExecutor) CreateEnrollOffer(ctx context.Context, in *pb.CreateEnrollOfferRequest, opts ...grpc.CallOption) (*pb.CreateEnrollOfferResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CreateEnrollOffer(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// FetchEnrollScript passes the download route's script release through.
func (l *lazyExecutor) FetchEnrollScript(ctx context.Context, in *pb.FetchEnrollScriptRequest, opts ...grpc.CallOption) (*pb.FetchEnrollScriptResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.FetchEnrollScript(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// ShowEnrollScript passes the placeholder script rendering through.
func (l *lazyExecutor) ShowEnrollScript(ctx context.Context, in *pb.ShowEnrollScriptRequest, opts ...grpc.CallOption) (*pb.ShowEnrollScriptResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.ShowEnrollScript(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// DownloadEnrollScript passes the browser download's script release through.
func (l *lazyExecutor) DownloadEnrollScript(ctx context.Context, in *pb.DownloadEnrollScriptRequest, opts ...grpc.CallOption) (*pb.DownloadEnrollScriptResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.DownloadEnrollScript(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// SubmitPairingCode passes an offer's pairing code and endpoint through.
func (l *lazyExecutor) SubmitPairingCode(ctx context.Context, in *pb.SubmitPairingCodeRequest, opts ...grpc.CallOption) (*pb.SubmitPairingCodeResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.SubmitPairingCode(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// CommitPairedEnroll passes the commit of an approved paired enrollment
// through.
func (l *lazyExecutor) CommitPairedEnroll(ctx context.Context, in *pb.CommitPairedEnrollRequest, opts ...grpc.CallOption) (*pb.CommitPairedEnrollResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.CommitPairedEnroll(ctx, in, opts...)
	}
	return nil, errNotConnected
}

// RevokeEnrollOffer passes the revocation of a non-final offer through.
func (l *lazyExecutor) RevokeEnrollOffer(ctx context.Context, in *pb.RevokeEnrollOfferRequest, opts ...grpc.CallOption) (*pb.RevokeEnrollOfferResponse, error) {
	if c := l.c.Load(); c != nil {
		return c.RevokeEnrollOffer(ctx, in, opts...)
	}
	return nil, errNotConnected
}
