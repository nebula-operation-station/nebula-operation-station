// SPDX-License-Identifier: AGPL-3.0-or-later

// Tests for the largest answers the executor may send and the client must
// receive: a run result of hostrun.MaxResult, a log of hostrun.MaxLog (with
// and without the truncation marker), a backup at the largest total the
// real BackupExecutor returns, and the message limits on both sides, all
// over a real Unix socket.
//
// Every server here is started by newHarness, so its options are the
// production ones. Requests and the backup are driven through
// executor.NewGRPCServer around the real Service. The run answers and the
// exact-size answers need a handler that returns a chosen answer; the real
// Service cannot be made to return those, so they use sizedService, a
// stand-in served under executor.ServerOptions (the options NewGRPCServer
// itself is built with) by startSized. Only the test of the client's own
// receive limit raises the server's send limit on top of them.

package executorclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// sizedService is the stand-in executor for the run answers and the
// exact-size answers. Each test sets the handler of the RPC it drives;
// every other RPC is Unimplemented. The handlers are set before the server
// starts and never change afterwards. calls counts the handler calls other
// than GetStatus, so a test can tell whether a message reached the handler.
type sizedService struct {
	pb.UnimplementedExecutorServiceServer
	runAttached func(*pb.RunAttachedRequest) *pb.RunAttachedResponse
	getRun      func(*pb.GetRunRequest) *pb.GetRunResponse
	batchMember func(*pb.RunBatchMemberRequest) *pb.RunBatchMemberResponse
	backup      func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse
	calls       atomic.Int32
}

func (s *sizedService) GetStatus(_ context.Context, _ *pb.GetStatusRequest) (*pb.GetStatusResponse, error) {
	return &pb.GetStatusResponse{}, nil
}

func (s *sizedService) RunAttached(_ context.Context, in *pb.RunAttachedRequest) (*pb.RunAttachedResponse, error) {
	s.calls.Add(1)
	return s.runAttached(in), nil
}

func (s *sizedService) GetRun(_ context.Context, in *pb.GetRunRequest) (*pb.GetRunResponse, error) {
	s.calls.Add(1)
	return s.getRun(in), nil
}

func (s *sizedService) RunBatchMember(_ context.Context, in *pb.RunBatchMemberRequest) (*pb.RunBatchMemberResponse, error) {
	s.calls.Add(1)
	return s.batchMember(in), nil
}

func (s *sizedService) BackupExecutor(_ context.Context, in *pb.BackupExecutorRequest) (*pb.BackupExecutorResponse, error) {
	s.calls.Add(1)
	return s.backup(in), nil
}

// startSized serves svc with newHarness under executor.ServerOptions, the
// options executor.NewGRPCServer is built with, and returns the socket. A
// change to the production server options is therefore seen here. extra is
// appended after them; only the test of the client's receive limit uses it.
func startSized(t *testing.T, svc *sizedService, extra ...grpc.ServerOption) string {
	t.Helper()
	return newHarness(t, harnessOptions{handler: svc, extraServerOptions: extra}).socket
}

// sendRefusal and receiveRefusal are the gRPC status messages of a message
// over a send or a receive limit: size is the message, limit the limit that
// refused it. The limits of the two sides differ (executor.MaxMessageSize
// for requests, executor.MaxResponseSize for answers), so the limit in the
// message names the side whose limit fired.
func sendRefusal(size, limit int) string {
	return fmt.Sprintf("trying to send message larger than max (%d vs. %d)", size, limit)
}

func receiveRefusal(size, limit int) string {
	return fmt.Sprintf("grpc: received message larger than max (%d vs. %d)", size, limit)
}

// requireLimitDetail asserts that err is the client's ErrLimitExceeded with
// exactly the given detail and a gRPC ResourceExhausted cause.
func requireLimitDetail(t *testing.T, err error, detail string) {
	t.Helper()
	requireCode(t, err, permit.CodeLimit)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error %v is not ErrLimitExceeded", err)
	}
	if got := clientErrorDetail(t, err); got != detail {
		t.Fatalf("limit detail = %q, want %q", got, detail)
	}
	if st, ok := status.FromError(errors.Unwrap(err)); !ok || st.Code() != codes.ResourceExhausted {
		t.Fatalf("cause of %v is not a gRPC ResourceExhausted status", err)
	}
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

// rawClient dials socket with the given per-call limits and none of the
// production client's checks. A test uses it to decide which side refuses a
// message: the limit the caller raises here cannot be the one that fires.
func rawClient(t *testing.T, socket string, recv, send int) pb.ExecutorServiceClient {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///executor",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return peercred.DialVerified(ctx, socket, uint32(os.Getuid()))
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(recv), grpc.MaxCallSendMsgSize(send)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewExecutorServiceClient(conn)
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
			c := newSizedClient(t, startSized(t, svc))
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
			c := newSizedClient(t, startSized(t, svc))
			resp, err := c.GetRun(bigCtx(t), &pb.GetRunRequest{ExecutionId: "exec-1", HostId: "host-1"})
			if err != nil {
				t.Fatalf("GetRun: %v", err)
			}
			checkBytes(t, "result", resp.GetRun().GetResult(), o.result)
			checkBytes(t, "log", resp.GetRun().GetLog(), o.log)
			if resp.GetRun().GetLogTruncated() != o.truncated {
				t.Fatalf("log_truncated = %v, want %v", resp.GetRun().GetLogTruncated(), o.truncated)
			}
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
			c := newSizedClient(t, startSized(t, svc))
			resp, err := c.RunBatchMember(bigCtx(t), &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1"})
			if err != nil {
				t.Fatalf("RunBatchMember: %v", err)
			}
			checkBytes(t, "result", resp.GetResult(), o.result)
			checkBytes(t, "log", resp.GetLog(), o.log)
			if resp.GetLogTruncated() != o.truncated {
				t.Fatalf("log_truncated = %v, want %v", resp.GetLogTruncated(), o.truncated)
			}
		})
	}
}

// --- BackupExecutor: the real path, at the largest total it returns. ---

// backupChunk is the size of one key file in the probe. It is below the
// executor's per-file limit (executor backup.go); a file over that limit is
// skipped silently by the executor, and the answer check below catches it.
const backupChunk = 1 << 20

// backupProbe drives the real BackupExecutor over gRPC. It adds key files of
// known sizes to the real keys directory and asks the real executor whether
// the answer is accepted.
type backupProbe struct {
	t        *testing.T
	c        *Client
	keysDir  string
	template string // one backupChunk file, outside keysDir
}

// probeName is the key file the probe writes; it matches the executor's key
// file pattern (backupKeyRe), so the executor reads it.
func probeName(i int) string { return fmt.Sprintf("probe-%02d.key", i) }

// probePart is the name of the file holding the bytes past the last full
// chunk.
const probePart = "probe-part.key"

// setExtra makes the probe files total k bytes: full chunks as hard links to
// the template (no copy of the data), then one part file of the rest. Files
// from an earlier, larger probe are removed.
func (p *backupProbe) setExtra(k int) {
	p.t.Helper()
	full, rest := k/backupChunk, k%backupChunk
	if k < 0 || k > executor.MaxBackupTotal+backupChunk {
		p.t.Fatalf("probe size %d is outside 0..%d", k, executor.MaxBackupTotal+backupChunk)
	}
	for i := 0; i <= (executor.MaxBackupTotal+backupChunk)/backupChunk; i++ {
		name := filepath.Join(p.keysDir, probeName(i))
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			p.t.Fatal(err)
		}
		if i < full {
			if err := os.Link(p.template, name); err != nil {
				p.t.Fatalf("link probe chunk: %v", err)
			}
		}
	}
	part := filepath.Join(p.keysDir, probePart)
	if err := os.Remove(part); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.t.Fatal(err)
	}
	if rest > 0 {
		data, err := os.ReadFile(p.template)
		if err != nil {
			p.t.Fatal(err)
		}
		if err := os.WriteFile(part, data[:rest], 0o600); err != nil {
			p.t.Fatal(err)
		}
	}
}

// backupTooLargeMsg is the message the executor sets on its own refusal of a
// backup over its total limit (executor backup.go). The client maps every
// gRPC ResourceExhausted to CodeLimit, transport send and receive limits
// included, so the message is what tells the executor's refusal apart. A
// transport refusal fails the test instead of passing as the executor's.
const backupTooLargeMsg = "the backup is too large"

// accepted asks the executor for a backup with the current probe files. A
// refusal must be the executor's own size refusal, with its message; any other
// error fails the test.
func (p *backupProbe) accepted(resp *pb.BackupExecutorResponse, err error) bool {
	p.t.Helper()
	if err == nil {
		return resp != nil
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != string(permit.CodeLimit) || e.Detail != backupTooLargeMsg {
		p.t.Fatalf("backup refused by something other than the executor's size refusal %q: %v", backupTooLargeMsg, err)
	}
	return false
}

// run makes the probe files total k bytes and asks the executor. It returns
// the answer when it is accepted.
func (p *backupProbe) run(k int) (*pb.BackupExecutorResponse, bool) {
	p.t.Helper()
	p.setExtra(k)
	resp, err := p.c.BackupExecutor(bigCtx(p.t), &pb.BackupExecutorRequest{})
	return resp, p.accepted(resp, err)
}

func TestLargestBackupAnswerArrivesOverRealService(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	dir := t.TempDir()
	template := filepath.Join(dir, "chunk.bin")
	if err := os.WriteFile(template, sizePayload(backupChunk, 9), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &backupProbe{t: t, c: c, keysDir: h.keysDir, template: template}

	// Zero probe bytes: the executor.db snapshot and the keys already in the
	// directory (the harness key). This is the base every probe adds to.
	base, ok := p.run(0)
	if !ok {
		t.Fatal("the backup with no probe key files is refused")
	}
	baseBytes := backupTotal(base)
	if baseBytes <= 0 || baseBytes >= executor.MaxBackupTotal {
		t.Fatalf("base backup is %d bytes, want 1..%d", baseBytes, executor.MaxBackupTotal-1)
	}

	// One byte over executor.MaxBackupTotal is the executor's own refusal
	// (accepted fails the test on any other error).
	over := executor.MaxBackupTotal - baseBytes + 1
	if _, ok := p.run(over); ok {
		t.Fatalf("a backup of %d bytes, one over MaxBackupTotal, is accepted", baseBytes+over)
	}

	// Exactly executor.MaxBackupTotal is accepted and arrives whole: every
	// file the probe wrote is in it with its exact content, and the total is
	// MaxBackupTotal.
	lo := executor.MaxBackupTotal - baseBytes
	resp, ok := p.run(lo)
	if !ok {
		t.Fatalf("the backup at MaxBackupTotal (%d bytes, base %d + probe %d) is refused", executor.MaxBackupTotal, baseBytes, lo)
	}
	if got := backupTotal(resp); got != executor.MaxBackupTotal {
		t.Fatalf("backup total = %d bytes, want MaxBackupTotal %d (base %d + probe %d)", got, executor.MaxBackupTotal, baseBytes, lo)
	}
	chunk := sizePayload(backupChunk, 9)
	full, rest := lo/backupChunk, lo%backupChunk
	probeFiles := 0
	for _, f := range resp.GetFiles() {
		var want []byte
		switch name := strings.TrimPrefix(f.GetName(), "keys/"); {
		case strings.HasPrefix(name, "probe-") && name != probePart:
			want = chunk
		case name == probePart:
			want = chunk[:rest]
		default:
			continue
		}
		probeFiles++
		checkBytes(t, f.GetName(), f.GetData(), want)
	}
	if want := full; rest > 0 {
		if probeFiles != want+1 {
			t.Fatalf("answer has %d probe files, want %d", probeFiles, want+1)
		}
	} else if probeFiles != want {
		t.Fatalf("answer has %d probe files, want %d", probeFiles, want)
	}
	if size := proto.Size(resp); size >= executor.MaxResponseSize {
		t.Fatalf("largest backup answer is %d bytes, not below MaxResponseSize %d", size, executor.MaxResponseSize)
	}
}

// backupTotal is the sum of the data of every file of a backup answer.
func backupTotal(resp *pb.BackupExecutorResponse) int {
	n := 0
	for _, f := range resp.GetFiles() {
		n += len(f.GetData())
	}
	return n
}

// backupAnswer builds a backup answer with one file of data bytes. It is
// used only as the size function of the exact-size test below.
func backupAnswer(data []byte) *pb.BackupExecutorResponse {
	return &pb.BackupExecutorResponse{SchemaVersion: 1, Version: "test",
		Files: []*pb.BackupFile{{Name: executordb.FileName, Mode: 0o600, Data: data}}}
}

// backupBuild is backupAnswer as the size function fitData needs.
func backupBuild(data []byte) proto.Message { return backupAnswer(data) }

// --- The message limits on both sides. ---

// TestAnswerAtMaxResponseSizeArrives: exactly executor.MaxResponseSize bytes
// on the wire arrive. The answer comes from the stand-in, because the real
// Service cannot be made to produce an answer of this size.
func TestAnswerAtMaxResponseSizeArrives(t *testing.T) {
	buf := sizePayload(executor.MaxResponseSize, 5)
	data, ok := fitData(buf, executor.MaxResponseSize, backupBuild)
	if !ok {
		t.Fatalf("no payload makes the answer exactly %d bytes", executor.MaxResponseSize)
	}
	svc := &sizedService{backup: func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse {
		return backupAnswer(data)
	}}
	c := newSizedClient(t, startSized(t, svc))
	resp, err := c.BackupExecutor(bigCtx(t), &pb.BackupExecutorRequest{})
	if err != nil {
		t.Fatalf("BackupExecutor at MaxResponseSize: %v", err)
	}
	checkBytes(t, "backup file", resp.GetFiles()[0].GetData(), data)
}

// overMaxResponseAnswer returns a backup answer of exactly one byte over
// executor.MaxResponseSize on the wire.
func overMaxResponseAnswer(t *testing.T) *pb.BackupExecutorResponse {
	t.Helper()
	buf := sizePayload(executor.MaxResponseSize+1, 6)
	data, ok := fitData(buf, executor.MaxResponseSize+1, backupBuild)
	if !ok {
		t.Fatalf("no payload makes the answer %d bytes", executor.MaxResponseSize+1)
	}
	answer := backupAnswer(data)
	if size := proto.Size(answer); size != executor.MaxResponseSize+1 {
		t.Fatalf("answer is %d bytes, want %d", size, executor.MaxResponseSize+1)
	}
	return answer
}

// TestAnswerOverMaxResponseSizeIsRefused shows the server's send limit
// refuses an answer one byte over MaxResponseSize. The caller is a raw
// client whose receive limit is raised, so only the server can refuse: the
// message is the send refusal against MaxResponseSize, after the handler
// built the answer.
func TestAnswerOverMaxResponseSizeIsRefused(t *testing.T) {
	answer := overMaxResponseAnswer(t)
	svc := &sizedService{backup: func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse { return answer }}
	socket := startSized(t, svc)
	raw := rawClient(t, socket, executor.MaxResponseSize+(1<<20), executor.MaxMessageSize)
	_, err := raw.BackupExecutor(bigCtx(t), &pb.BackupExecutorRequest{})
	st := status.Convert(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("server answered %v, want ResourceExhausted (%v)", st.Code(), err)
	}
	if want := sendRefusal(executor.MaxResponseSize+1, executor.MaxResponseSize); st.Message() != want {
		t.Fatalf("refusal = %q, want the server's send refusal %q", st.Message(), want)
	}
	if n := svc.calls.Load(); n != 1 {
		t.Fatalf("handler ran %d times, want 1: the refusal must come after the answer was built", n)
	}
}

// TestProductionClientRefusesAnswerOverMaxResponseSize: the production
// client's receive limit refuses an answer one byte over MaxResponseSize.
// The server's send limit is raised on top of the production options for
// this test only, so the server sends the answer and only the client can
// refuse it: the detail is the receive refusal against MaxResponseSize, not
// the server's send refusal or its receive limit (MaxMessageSize).
func TestProductionClientRefusesAnswerOverMaxResponseSize(t *testing.T) {
	answer := overMaxResponseAnswer(t)
	svc := &sizedService{backup: func(*pb.BackupExecutorRequest) *pb.BackupExecutorResponse { return answer }}
	c := newSizedClient(t, startSized(t, svc, grpc.MaxSendMsgSize(executor.MaxResponseSize+(1<<20))))
	_, err := c.BackupExecutor(bigCtx(t), &pb.BackupExecutorRequest{})
	requireLimitDetail(t, err, receiveRefusal(executor.MaxResponseSize+1, executor.MaxResponseSize))
	if n := svc.calls.Load(); n != 1 {
		t.Fatalf("handler ran %d times, want 1", n)
	}
}

// TestRequestAtMaxMessageSizeArrives: a request of exactly
// executor.MaxMessageSize bytes is read by the real server and reaches the
// handler, which rejects it by its own rule (the artifact is over
// permit.MaxArtifactSize). A gRPC ResourceExhausted would mean the server
// did not read it.
func TestRequestAtMaxMessageSizeArrives(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	c := h.client()
	buf := sizePayload(executor.MaxMessageSize, 7)
	build := func(data []byte) proto.Message {
		return &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1", Artifact: data}
	}
	data, ok := fitData(buf, executor.MaxMessageSize, build)
	if !ok {
		t.Fatalf("no artifact makes the request %d bytes", executor.MaxMessageSize)
	}
	req := &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1", Artifact: data}

	// The production client sends the request: it is at its send limit, not
	// over it. The handler then refuses it by its own rule. A local refusal
	// by the client would be CodeLimit and fails here.
	_, err := c.RunBatchMember(bigCtx(t), req)
	requireCode(t, err, permit.CodeInvalidRequest)
	if detail := clientErrorDetail(t, err); !strings.Contains(detail, "artifact missing or oversize") {
		t.Fatalf("request did not reach the handler's artifact rule: detail %q", detail)
	}

	raw := rawClient(t, h.socket, executor.MaxMessageSize, executor.MaxMessageSize)
	_, err = raw.RunBatchMember(bigCtx(t), req)
	st := status.Convert(err)
	if st.Code() == codes.ResourceExhausted {
		t.Fatalf("server refused a request at MaxMessageSize: %v", err)
	}
	if st.Code() != codes.InvalidArgument || !strings.Contains(st.Message(), "artifact missing or oversize") {
		t.Fatalf("request did not reach the handler's artifact rule: %v", err)
	}
}

// clientErrorDetail returns the Detail of a typed client error, or fails the
// test when err is not one.
func clientErrorDetail(t *testing.T, err error) string {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("want a typed client error, got %T: %v", err, err)
	}
	return e.Detail
}

// TestRequestOverMaxMessageSizeIsRefused: one byte over is refused by the
// production client before it is sent, and by the server (production
// options) when the client's own send limit is raised. The handler is the
// stand-in, so the test sees that the request never reaches it.
func TestRequestOverMaxMessageSizeIsRefused(t *testing.T) {
	svc := &sizedService{batchMember: func(*pb.RunBatchMemberRequest) *pb.RunBatchMemberResponse {
		return &pb.RunBatchMemberResponse{}
	}}
	socket := startSized(t, svc)
	c := newSizedClient(t, socket)
	buf := sizePayload(executor.MaxMessageSize+1, 8)
	build := func(data []byte) proto.Message {
		return &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1", Artifact: data}
	}
	data, ok := fitData(buf, executor.MaxMessageSize+1, build)
	if !ok {
		t.Fatalf("no artifact makes the request %d bytes", executor.MaxMessageSize+1)
	}
	req := &pb.RunBatchMemberRequest{BatchDigest: unknownDigest, MemberId: "m1", Artifact: data}

	// The production client refuses the request before it is sent. The
	// detail is the send refusal against MaxMessageSize: the server never
	// sends a request, and its own send limit is MaxResponseSize, its receive
	// refusal reads "received". mapCallError maps every ResourceExhausted to
	// CodeLimit, so the code alone would not tell the sides apart.
	_, err := c.RunBatchMember(bigCtx(t), req)
	requireLimitDetail(t, err, sendRefusal(executor.MaxMessageSize+1, executor.MaxMessageSize))
	if n := svc.calls.Load(); n != 0 {
		t.Fatalf("the refused request reached the handler (%d calls)", n)
	}

	// Past the client's send limit, the server refuses it on its receive
	// limit, against MaxMessageSize, before the handler.
	raw := rawClient(t, socket, executor.MaxMessageSize, executor.MaxMessageSize+(1<<20))
	_, err = raw.RunBatchMember(bigCtx(t), req)
	st := status.Convert(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("server answered %v, want ResourceExhausted (%v)", st.Code(), err)
	}
	if want := receiveRefusal(executor.MaxMessageSize+1, executor.MaxMessageSize); st.Message() != want {
		t.Fatalf("refusal = %q, want the server's receive refusal %q", st.Message(), want)
	}
	if n := svc.calls.Load(); n != 0 {
		t.Fatalf("the refused request reached the handler (%d calls)", n)
	}
}

// runAnswerStringRoom is the length given to each of the class, detail and
// endpoint strings of a run answer in TestLimitsFitTogether. The proto does
// not bound these strings, so the test checks that a run answer with three
// strings of this length, plus the largest result and log, still fits
// executor.MaxResponseSize.
const runAnswerStringRoom = 1 << 20

// TestLimitsFitTogether checks that the largest run answer fits the response
// limit, both with empty strings and with three strings of runAnswerStringRoom
// bytes each. The second check fails if the response limit is lowered below
// the answer's content plus the strings.
func TestLimitsFitTogether(t *testing.T) {
	logWithMarker := append(sizePayload(hostrun.MaxLog, 2), hostrun.TruncationMarker...)
	largest := &pb.RunAttachedResponse{Class: "success", Result: sizePayload(hostrun.MaxResult, 1), Log: logWithMarker, LogTruncated: true}
	if size := proto.Size(largest); size >= executor.MaxResponseSize {
		t.Fatalf("largest run answer is %d bytes, not below MaxResponseSize %d", size, executor.MaxResponseSize)
	}

	withStrings := &pb.RunAttachedResponse{
		Class:        strings.Repeat("c", runAnswerStringRoom),
		Detail:       strings.Repeat("d", runAnswerStringRoom),
		Endpoint:     strings.Repeat("e", runAnswerStringRoom),
		Result:       largest.GetResult(),
		Log:          logWithMarker,
		LogTruncated: true,
	}
	if size := proto.Size(withStrings); size >= executor.MaxResponseSize {
		t.Fatalf("run answer with %d-byte class, detail and endpoint is %d bytes, not below MaxResponseSize %d",
			runAnswerStringRoom, size, executor.MaxResponseSize)
	}
}
