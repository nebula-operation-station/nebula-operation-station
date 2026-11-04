// SPDX-License-Identifier: AGPL-3.0-or-later

package executorclient

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

func TestBatchRPCsForwardWithTimeoutAndMapErrors(t *testing.T) {
	t.Run("ProposeBatch", func(t *testing.T) { checkPVEAdminRPC(t, "ProposeBatch", (*Client).ProposeBatch) })
	t.Run("CommitBatch", func(t *testing.T) { checkPVEAdminRPC(t, "CommitBatch", (*Client).CommitBatch) })
	t.Run("ReviewBatch", func(t *testing.T) { checkPVEAdminRPC(t, "ReviewBatch", (*Client).ReviewBatch) })
	t.Run("ApproveBatchCLI", func(t *testing.T) { checkPVEAdminRPC(t, "ApproveBatchCLI", (*Client).ApproveBatchCLI) })
	t.Run("GetBatchStatus", func(t *testing.T) { checkPVEAdminRPC(t, "GetBatchStatus", (*Client).GetBatchStatus) })
	t.Run("GetBatchCredentialVersions", func(t *testing.T) {
		checkPVEAdminRPC(t, "GetBatchCredentialVersions", (*Client).GetBatchCredentialVersions)
	})
}

// credentialVersionClient answers GetBatchCredentialVersions with resp or err
// and records the request.
func credentialVersionClient(t *testing.T, resp *pb.GetBatchCredentialVersionsResponse, err error, got *[]string) *Client {
	t.Helper()
	return &Client{defaultTimeout: time.Second, rpc: pb.NewExecutorServiceClient(pveAdminConn{
		invoke: func(_ context.Context, method string, in, out any, _ ...grpc.CallOption) error {
			if method != pb.ExecutorService_GetBatchCredentialVersions_FullMethodName {
				t.Errorf("method = %q", method)
			}
			if got != nil {
				*got = in.(*pb.GetBatchCredentialVersionsRequest).GetCredentialRefs()
			}
			if err != nil {
				return err
			}
			proto.Merge(out.(*pb.GetBatchCredentialVersionsResponse), resp)
			return nil
		},
	})}
}

// CredentialVersion asks for exactly one reference and accepts only a
// matching nonzero version: a batch never binds a guessed version.
func TestCredentialVersionNeverGuesses(t *testing.T) {
	ok := &pb.GetBatchCredentialVersionsResponse{Versions: []*pb.BatchCredentialVersion{{CredentialRef: "default", Version: 42, PublicKeyFingerprint: "SHA256:x"}}}
	var refs []string
	v, err := CredentialVersion(context.Background(), credentialVersionClient(t, ok, nil, &refs), "default")
	if err != nil || v != 42 || len(refs) != 1 || refs[0] != "default" {
		t.Fatalf("version %d, refs %v, err %v", v, refs, err)
	}
	cases := map[string]struct {
		resp *pb.GetBatchCredentialVersionsResponse
		err  error
	}{
		"no entry":       {resp: &pb.GetBatchCredentialVersionsResponse{}},
		"other ref":      {resp: &pb.GetBatchCredentialVersionsResponse{Versions: []*pb.BatchCredentialVersion{{CredentialRef: "other", Version: 42}}}},
		"zero version":   {resp: &pb.GetBatchCredentialVersionsResponse{Versions: []*pb.BatchCredentialVersion{{CredentialRef: "default"}}}},
		"two entries":    {resp: &pb.GetBatchCredentialVersionsResponse{Versions: []*pb.BatchCredentialVersion{{CredentialRef: "default", Version: 1}, {CredentialRef: "default", Version: 2}}}},
		"locked":         {err: status.Error(codes.FailedPrecondition, "keyring is locked")},
		"unknown ref":    {err: status.Error(codes.NotFound, "not loaded")},
		"unimplemented":  {err: status.Error(codes.Unimplemented, "batch: authority not configured")},
		"executor down":  {err: status.Error(codes.Unavailable, "unavailable")},
		"internal error": {err: status.Error(codes.Internal, "keyring error")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := CredentialVersion(context.Background(), credentialVersionClient(t, c.resp, c.err, nil), "default")
			if err == nil || v != 0 {
				t.Errorf("version %d, err %v", v, err)
			}
		})
	}
}

// BatchesAvailable distinguishes a missing capability (Unimplemented) from
// a transient failure.
func TestBatchesAvailable(t *testing.T) {
	var refs []string
	ok, err := BatchesAvailable(context.Background(), credentialVersionClient(t, &pb.GetBatchCredentialVersionsResponse{}, nil, &refs))
	if !ok || err != nil || len(refs) != 0 {
		t.Errorf("available: %v %v refs %v", ok, err, refs)
	}
	ok, err = BatchesAvailable(context.Background(), credentialVersionClient(t, nil, status.Error(codes.Unimplemented, "unknown method"), nil))
	if ok || err != nil {
		t.Errorf("unimplemented: %v %v", ok, err)
	}
	ok, err = BatchesAvailable(context.Background(), credentialVersionClient(t, nil, status.Error(codes.Unavailable, "down"), nil))
	if ok || !errors.Is(err, ErrUnavailable) {
		t.Errorf("unavailable: %v %v", ok, err)
	}
}
