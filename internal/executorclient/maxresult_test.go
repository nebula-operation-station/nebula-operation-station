// SPDX-License-Identifier: AGPL-3.0-or-later

// Tests for the largest answers the executor may send and the client must
// receive: a run result of hostrun.MaxResult, a log of hostrun.MaxLog (with
// and without the truncation marker), a backup at the backup.go limit, and
// the message limits on both sides, all over a real Unix socket.

package executorclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// sizedService is the stand-in executor for the size tests. Each test sets
// the handler of the RPC it drives; every other RPC is Unimplemented. The
// handlers are set before the server starts and never change afterwards.
type sizedService struct {
	pb.UnimplementedExecutorServiceServer
	runAttached func(*pb.RunAttachedRequest) *pb.RunAttachedResponse
	getRun      func(*pb.GetRunRequest) *pb.GetRunResponse
	batchMember func(*pb.RunBatchMemberRequest) *pb.RunBatchMemberResponse
	backup      func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse
}

func (s *sizedService) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (s *sizedService) RunAttached(_ context.Context, in *pb.RunAttachedRequest) (*pb.RunAttachedResponse, error) {
	return s.runAttached(in), nil
}

func (s *sizedService) GetRun(_ context.Context, in *pb.GetRunRequest) (*pb.GetRunResponse, error) {
	return s.getRun(in), nil
}

func (s *sizedService) RunBatchMember(_ context.Context, in *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
	return s.batchMember(in), nil
}

func (s *sizedService) BackupExecutor(_ context.Context, in *pb.BackupExecutorRequest) (*pb.BackupExecutorResponse, error) {
	return s.backup(in), nil
}

// startSizedServer serves svc on a real peercred socket with the real role
// table. It mirrors the options of executor.NewGRPCServer, which takes the
// concrete *executor.Service and so cannot take this stand-in; the message
// limits are the executor's constants, not copies of them.
func startSizedServer(t *testing.T, svc pb.ExecutorServiceServer) string {
	t.Helper()
	uidRoles := map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer, peercred.RoleAdmin}}
	policy := peercred.NewPolicy(uidRoles, executor.MethodRoles())
	sockDir := t.TempDir()
	if err := os.Chmod(sockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(sockDir, "executor.sock")
	lis, err := peercred.Listen(peercred.ListenOptions{Path: socket, Mode: 0o666})
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(peercred.Credentials{Policy: policy}),
		grpc.MaxConcurrentStreams(executor.MaxConcurrentStreams),
		grpc.ChainUnaryInterceptor(policy.UnaryInterceptor(nil)),
		grpc.ChainStreamInterceptor(policy.StreamInterceptor(nil)),
		grpc.MaxRecvMsgSize(executor.MaxMessageSize),
		grpc.MaxSendMsgSize(executor.MaxResponseSize),
	)
	pb.RegisterExecutorServiceServer(srv, svc)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return socket
}

// newSizedClient returns a verified client with the production options.
func newSizedClient(t *testing.T, socket string) *Client {
	t.Helper()
	c, err := New(bigCtx(t), Options{SocketPath: socket, ExecutorUser: currentUser(t)})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// bigCtx is testCtx with room for a 64 MiB transfer under -race.
func bigCtx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

// sizePayload returns n bytes whose content depends on the position and the
// seed, so a truncated, shifted or swapped message fails the comparison.
func sizePayload(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) ^ byte(i>>8) ^ byte(i>>16) ^ seed
	}
	return b
}

// fitData returns buf[:n] for the n at which build(buf[:n]) has exactly
// target bytes on the wire (proto.Size). Only slice lengths change, so no
// copy is made. It reports false when no n fits.
func fitData(buf []byte, target int, build func(data []byte) proto.Message) ([]byte, bool) {
	n := 0
	for range 8 {
		s := proto.Size(build(buf[:n]))
		if s == target {
			return buf[:n], true
		}
		next := n + target - s
		if next < 0 || next > len(buf) {
			return nil, false
		}
		n = next
	}
	return nil, false
}

// checkBytes compares a received payload with the sent one. It reports the
// length and digest, not the content, so a failure stays readable.
func checkBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d bytes, want %d", what, len(got), len(want))
	}
	if sha256.Sum256(got) != sha256.Sum256(want) || !bytes.Equal(got, want) {
		t.Fatalf("%s: content differs (sha256 got %x, want %x)", what, sha256.Sum256(got), sha256.Sum256(want))
	}
}

// requireCode asserts that err is a client error with the given code, which
// mapCallError gives to a gRPC status.
func requireCode(t *testing.T, err error, code permit.Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want a typed client error %s, got %T: %v", code, err, err)
	}
	if e.Code != string(code) {
		t.Fatalf("error code = %q, want %q (detail %q)", e.Code, code, e.Detail)
	}
}

// literalValue reads a Go source file of this repository as text and
// returns n<<s for the first match of pattern, whose two groups are the
// number and the shift. The file is not changed.
func literalValue(t *testing.T, rel, pattern string) int {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(pattern).FindSubmatch(src)
	if m == nil {
		t.Fatalf("%s: no match for %q", rel, pattern)
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	s, err := strconv.Atoi(string(m[2]))
	if err != nil {
		t.Fatal(err)
	}
	return n << s
}

// --- RunAttached, GetRun and RunBatchMember at the largest allowed answer. ---
//
// Each answer carries one host (RunAttached, GetRun) or one member
// (RunBatchMember): the proto comments give the result and the log per
// answer, and no count of hosts or members per answer. A single host or
// member is therefore the largest answer these RPCs carry.

// largestOutput is the largest result and log one host run may return.
type largestOutput struct {
	name   string
	result []byte
	log    []byte
	// truncated is set when the log ends with the truncation marker
	// (hostrun appends it after MaxLog bytes).
	truncated bool
}

func largestOutputs() []largestOutput {
	logAtMax := sizePayload(hostrun.MaxLog, 2)
	logWithMarker := append(sizePayload(hostrun.MaxLog, 2), hostrun.TruncationMarker...)
	return []largestOutput{
		{name: "result and log at the limits", result: sizePayload(hostrun.MaxResult, 1), log: logAtMax},
		{name: "result and log with the truncation marker", result: sizePayload(hostrun.MaxResult, 1), log: logWithMarker, truncated: true},
	}
}

func TestLargestRunAttachedAnswerArrives(t *testing.T) {
	for _, o := range largestOutputs() {
		t.Run(o.name, func(t *testing.T) {
			svc := &sizedService{runAttached: func(*pb.RunAttachedRequest) *pb.RunAttachedResponse {
				return &pb.RunAttachedResponse{Class: "success", ExitCode: 0, Result: o.result, Log: o.log,
					LogTruncated: o.truncated, Endpoint: "192.0.2.10:22", DurationMs: 1}
			}}
			c := newSizedClient(t, startSizedServer(t, svc))
			resp, err := c.RunAttached(bigCtx(t), &pb.RunAttachedRequest{})
			if err != nil {
				t.Fatalf("RunAttached: %v", err)
			}
			checkBytes(t, "result", resp.GetResult(), o.result)
			checkBytes(t, "log", resp.GetLog(), o.log)
			if resp.GetLogTruncated() != o.truncated {
				t.Fatalf("log_truncated = %v, want %v", resp.GetLogTruncated(), o.truncated)
			}
		})
	}
}

func TestLargestGetRunAnswerArrives(t *testing.T) {
	for _, o := range largestOutputs() {
		t.Run(o.name, func(t *testing.T) {
			svc := &sizedService{getRun: func(*pb.GetRunRequest) *pb.GetRunResponse {
				return &pb.GetRunResponse{Run: &pb.RunStatus{ExecutionId: "exec-1", HostId: "host-1", State: "finished",
					Class: "success", Result: o.result, Log: o.log, LogTruncated: o.truncated, Endpoint: "192.0.2.10:22"}}
			}}
			c := newSizedClient(t, startSizedServer(t, svc))
			resp, err := c.GetRun(bigCtx(t), &pb.GetRunRequest{ExecutionId: "exec-1", HostId: "host-1"})
			if err != nil {
				t.Fatalf("GetRun: %v", err)
			}
			checkBytes(t, "result", resp.GetRun().GetResult(), o.result)
			checkBytes(t, "log", resp.GetRun().GetLog(), o.log)
		})
	}
}

func TestLargestRunBatchMemberAnswerArrives(t *testing.T) {
	for _, o := range largestOutputs() {
		t.Run(o.name, func(t *testing.T) {
			svc := &sizedService{batchMember: func(*pb.RunBatchMemberRequest) *pb.RunBatchMemberResponse {
				return &pb.RunBatchMemberResponse{ExecutionId: "exec-1", Class: "success", Result: o.result, Log: o.log,
					LogTruncated: o.truncated, Endpoint: "192.0.2.10:22"}
			}}
			c := newSizedClient(t, startSizedServer(t, svc))
			resp, err := c.RunBatchMember(bigCtx(t), &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1"})
			if err != nil {
				t.Fatalf("RunBatchMember: %v", err)
			}
			checkBytes(t, "result", resp.GetResult(), o.result)
			checkBytes(t, "log", resp.GetLog(), o.log)
		})
	}
}

// --- BackupExecutor at the backup.go limit and at the message limit. ---

// backupAnswer builds a backup answer with one file of data bytes.
func backupAnswer(data []byte) *pb.BackupExecutorResponse {
	return &pb.BackupExecutorResponse{SchemaVersion: 1, Version: "test",
		Files: []*pb.BackupFile{{Name: executordb.FileName, Mode: 0o600, Data: data}}}
}

// backupBuild is backupAnswer as the size function fitData needs.
func backupBuild(data []byte) proto.Message { return backupAnswer(data) }

func TestLargestBackupAnswerArrives(t *testing.T) {
	// maxBackupTotal is unexported in internal/executor (backup.go), so the
	// limit is read from its source text.
	limit := literalValue(t, "internal/executor/backup.go", `maxBackupTotal\s*=\s*(\d+)\s*<<\s*(\d+)`)
	data := sizePayload(limit, 4)
	svc := &sizedService{backup: func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse {
		return backupAnswer(data)
	}}
	c := newSizedClient(t, startSizedServer(t, svc))
	resp, err := c.BackupExecutor(bigCtx(t), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatalf("BackupExecutor: %v", err)
	}
	if n := len(resp.GetFiles()); n != 1 {
		t.Fatalf("got %d files, want 1", n)
	}
	checkBytes(t, "backup file", resp.GetFiles()[0].GetData(), data)
}

// TestAnswerAtMaxResponseSizeArrives and TestAnswerOverMaxResponseSizeIsRefused
// use the largest message the executor may send: exactly
// executor.MaxResponseSize bytes on the wire arrives, one byte more is refused
// by the server and reported by the client as ResourceExhausted (CodeLimit),
// not as a truncated message.
func TestAnswerAtMaxResponseSizeArrives(t *testing.T) {
	buf := sizePayload(executor.MaxResponseSize, 5)
	data, ok := fitData(buf, executor.MaxResponseSize, backupBuild)
	if !ok {
		t.Fatalf("no payload makes the answer exactly %d bytes", executor.MaxResponseSize)
	}
	svc := &sizedService{backup: func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse {
		return backupAnswer(data)
	}}
	c := newSizedClient(t, startSizedServer(t, svc))
	resp, err := c.BackupExecutor(bigCtx(t), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatalf("BackupExecutor at MaxResponseSize: %v", err)
	}
	checkBytes(t, "backup file", resp.GetFiles()[0].GetData(), data)
}

func TestAnswerOverMaxResponseSizeIsRefused(t *testing.T) {
	buf := sizePayload(executor.MaxResponseSize+1, 6)
	data, ok := fitData(buf, executor.MaxResponseSize+1, backupBuild)
	if !ok {
		t.Fatalf("no payload makes the answer %d bytes", executor.MaxResponseSize+1)
	}
	if size := proto.Size(backupAnswer(data)); size != executor.MaxResponseSize+1 {
		t.Fatalf("answer is %d bytes, want %d", size, executor.MaxResponseSize+1)
	}
	svc := &sizedService{backup: func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse {
		return backupAnswer(data)
	}}
	c := newSizedClient(t, startSizedServer(t, svc))
	resp, err := c.BackupExecutor(bigCtx(t), &pb.BackupExecutorRequest{})
	if err == nil {
		t.Fatalf("BackupExecutor over MaxResponseSize succeeded with %d files", len(resp.GetFiles()))
	}
	requireCode(t, err, permit.CodeLimit)
}

// --- Requests: the largest accepted message, and the refusal one byte over. ---

// artifactRequest builds a RunBatchMember request whose proto size is target.
func artifactRequest(t *testing.T, buf []byte, target int) *pb.RunBatchMemberRequest {
	t.Helper()
	build := func(data []byte) proto.Message {
		return &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1", Artifact: data}
	}
	data, ok := fitData(buf, target, build)
	if !ok {
		t.Fatalf("no artifact makes the request %d bytes", target)
	}
	return &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1", Artifact: data}
}

func TestRequestAtMaxMessageSizeArrives(t *testing.T) {
	buf := sizePayload(executor.MaxMessageSize, 7)
	req := artifactRequest(t, buf, executor.MaxMessageSize)
	var got []byte
	svc := &sizedService{batchMember: func(in *pb.RunBatchMemberRequest) *pb.RunBatchMemberResponse {
		got = in.GetArtifact()
		return &pb.RunBatchMemberResponse{Class: "success"}
	}}
	c := newSizedClient(t, startSizedServer(t, svc))
	if _, err := c.RunBatchMember(bigCtx(t), req); err != nil {
		t.Fatalf("RunBatchMember at MaxMessageSize: %v", err)
	}
	checkBytes(t, "artifact", got, req.GetArtifact())
}

func TestRequestOverMaxMessageSizeIsRefused(t *testing.T) {
	buf := sizePayload(executor.MaxMessageSize+1, 8)
	req := artifactRequest(t, buf, executor.MaxMessageSize+1)
	var calls atomic.Int32
	svc := &sizedService{batchMember: func(*pb.RunBatchMemberRequest) *pb.RunBatchMemberResponse {
		calls.Add(1)
		return &pb.RunBatchMemberResponse{Class: "success"}
	}}
	socket := startSizedServer(t, svc)

	// The production client refuses the request before it is sent.
	c := newSizedClient(t, socket)
	_, err := c.RunBatchMember(bigCtx(t), req)
	requireCode(t, err, permit.CodeLimit)

	// Past the client's own send limit, the server must refuse it: a raw
	// connection with a larger send limit sends the request anyway.
	conn, err := grpc.NewClient("passthrough:///executor",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, socket, uint32(os.Getuid()))
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(executor.MaxMessageSize+(1<<20))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	raw := pb.NewExecutorServiceClient(conn)
	_, err = raw.RunBatchMember(bigCtx(t), req)
	if st := status.Convert(err); st.Code() != codes.ResourceExhausted {
		t.Fatalf("server answered %v, want ResourceExhausted (%v)", st.Code(), err)
	}
	if n := calls.Load(); n != 0 {
		t.Fatalf("the handler ran %d times for an over-limit request", n)
	}
}

// --- Constants against each other. ---

// TestLimitsFitTogether checks the sums of the answers: the largest run
// answer, measured as the proto encodes it, is below executor.MaxResponseSize,
// and so is the backup answer at its limit. The strings of the answer
// (class, detail, endpoint) are not bounded by the proto; they must fit in
// the margin measured here.
func TestLimitsFitTogether(t *testing.T) {
	logWithMarker := append(sizePayload(hostrun.MaxLog, 2), hostrun.TruncationMarker...)
	largest := &pb.RunAttachedResponse{Class: "success", Result: sizePayload(hostrun.MaxResult, 1), Log: logWithMarker, LogTruncated: true}
	if size := proto.Size(largest); size >= executor.MaxResponseSize {
		t.Fatalf("largest run answer is %d bytes, not below MaxResponseSize %d", size, executor.MaxResponseSize)
	}
	if size := proto.Size(&pb.RunAttachedResponse{}); size+hostrun.MaxResult+hostrun.MaxLog+len(hostrun.TruncationMarker) >= executor.MaxResponseSize {
		t.Fatalf("run answer framing leaves no margin under MaxResponseSize")
	}

	backupLimit := literalValue(t, "internal/executor/backup.go", `maxBackupTotal\s*=\s*(\d+)\s*<<\s*(\d+)`)
	if backupLimit >= executor.MaxResponseSize {
		t.Fatalf("backup limit %d is not below MaxResponseSize %d", backupLimit, executor.MaxResponseSize)
	}
	if size := proto.Size(backupAnswer(make([]byte, backupLimit))); size >= executor.MaxResponseSize {
		t.Fatalf("backup answer at its limit is %d bytes, not below MaxResponseSize %d", size, executor.MaxResponseSize)
	}
}

// TestCLIReceiveLimitMatchesExecutor reads the receive limit of the CLI as
// text (cmd/nebula/main.go is protected and is not changed here) and
// compares it with executor.MaxResponseSize. A mismatch is a finding for the
// PR text.
func TestCLIReceiveLimitMatchesExecutor(t *testing.T) {
	cli := literalValue(t, "cmd/nebula/main.go", `MaxCallRecvMsgSize\((\d+)<<(\d+)\)`)
	if cli != executor.MaxResponseSize {
		t.Fatalf("CLI receive limit is %d, executor.MaxResponseSize is %d", cli, executor.MaxResponseSize)
	}
}
