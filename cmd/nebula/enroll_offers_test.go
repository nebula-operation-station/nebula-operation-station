// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fakeOfferServer is an executor stand-in for the two offer RPCs. It sits
// behind the real peer-credential policy and the real method-role table,
// so a test sees exactly the role decisions the executor makes.
type fakeOfferServer struct {
	pb.UnimplementedExecutorServiceServer
	mu      sync.Mutex
	offers  []*pb.EnrollOfferInfo
	revoked []string
	lists   int
	// unlisted hides every offer from the list, as after a state change
	// between the CLI's list and its revoke.
	unlisted bool
}

func (f *fakeOfferServer) revokedSnap() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

func (f *fakeOfferServer) listCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
}

func (f *fakeOfferServer) ListEnrollOffers(context.Context, *pb.ListEnrollOffersRequest) (*pb.ListEnrollOffersResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	out := &pb.ListEnrollOffersResponse{}
	if f.unlisted {
		return out, nil
	}
	for _, o := range f.offers {
		out.Offers = append(out.Offers, proto.Clone(o).(*pb.EnrollOfferInfo))
	}
	return out, nil
}

// RevokeEnrollOffer mirrors the executor: unknown → NotFound, final →
// FailedPrecondition, any other state → revoked.
func (f *fakeOfferServer) RevokeEnrollOffer(_ context.Context, req *pb.RevokeEnrollOfferRequest) (*pb.RevokeEnrollOfferResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.offers {
		if o.GetOfferIdHash() != req.GetOfferIdHash() {
			continue
		}
		switch o.GetState() {
		case "enrolled", "expired", "revoked", "failed":
			return nil, grpcstatus.Errorf(codes.FailedPrecondition, "revoke enroll offer: offer is already %s", o.GetState())
		}
		o.State = "revoked"
		f.revoked = append(f.revoked, req.GetOfferIdHash())
		return &pb.RevokeEnrollOfferResponse{State: "revoked"}, nil
	}
	return nil, grpcstatus.Error(codes.NotFound, "revoke enroll offer: no such offer")
}

// startOfferServer serves f on a Unix socket in a temporary directory and
// gives the current UID the roles listed. The returned client goes through
// dialExecutor, the CLI's own connection path.
func startOfferServer(t *testing.T, f *fakeOfferServer, roles ...peercred.Role) pb.ExecutorServiceClient {
	t.Helper()
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{uint32(os.Getuid()): roles}, executor.MethodRoles())
	srv := grpc.NewServer(
		grpc.Creds(peercred.Credentials{Policy: policy}),
		grpc.UnaryInterceptor(policy.UnaryInterceptor(nil)),
	)
	pb.RegisterExecutorServiceServer(srv, f)
	socket := filepath.Join(t.TempDir(), "executor.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { srv.Stop(); _ = l.Close() })
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NEBULA_EXECUTOR_USER", u.Username)
	t.Setenv("NEBULA_EXECUTOR_SOCKET", socket)
	conn, err := dialExecutor()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return pb.NewExecutorServiceClient(conn)
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

const (
	hashA = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
	hashB = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
	hashC = "aaaa1111cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333"
	shaS  = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
)

func sampleOffers() []*pb.EnrollOfferInfo {
	exp := time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC).Unix()
	return []*pb.EnrollOfferInfo{
		{OfferIdHash: hashA, HostId: "web-01", SshUser: "nebula", CredentialRef: "nebula-default", State: "downloaded",
			CreatedUnix: exp - 3600, ExpiresUnix: exp, ScriptSha256: shaS, DownloadedUnix: exp - 60,
			ClientAddr: "192.0.2.10", PeerAddr: "127.0.0.1", SetupKeyRecord: "none"},
		{OfferIdHash: hashB, HostId: "db-02", SshUser: "nebula", CredentialRef: "nebula-default", Netbird: true,
			State: "awaiting_approval", CreatedUnix: exp - 600, ExpiresUnix: exp, SetupKeyRecord: "none"},
		// A NetBird offer whose script was downloaded and that then
		// failed: the host may have joined NetBird, a possible orphan peer.
		{OfferIdHash: hashC, HostId: "nas-03", SshUser: "nebula", CredentialRef: "nebula-default", Netbird: true,
			State: "failed", CreatedUnix: exp - 7200, ExpiresUnix: exp - 3600, ScriptSha256: shaS,
			DownloadedUnix: exp - 5000, ClientAddr: "198.51.100.7", PeerAddr: "198.51.100.7", SetupKeyRecord: "created"},
	}
}

func TestHostOffersTableShowsStateHostExpiryHashAddressAndOrphans(t *testing.T) {
	c := startOfferServer(t, &fakeOfferServer{offers: sampleOffers()}, peercred.RoleAdmin)
	var out bytes.Buffer
	if err := hostOffers(testCtx(t), c, nil, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{
		"STATE", "HOST", "EXPIRES", "SCRIPT SHA-256", "DOWNLOADED FROM",
		hashA, "downloaded", "web-01", "2026-11-12T10:30:00Z", shaS, "192.0.2.10 (via 127.0.0.1)",
		hashB, "awaiting_approval", "db-02",
		hashC, "failed", "nas-03", "198.51.100.7",
		"possible orphan NetBird peers",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	// Only the failed, downloaded NetBird offer is a possible orphan.
	orphan := s[strings.Index(s, "possible orphan NetBird peers"):]
	if !strings.Contains(orphan, "nas-03") || strings.Contains(orphan, "db-02") || strings.Contains(orphan, "web-01") {
		t.Errorf("orphan section wrong:\n%s", orphan)
	}
}

func TestHostOffersEmpty(t *testing.T) {
	c := startOfferServer(t, &fakeOfferServer{}, peercred.RoleAdmin)
	var out bytes.Buffer
	if err := hostOffers(testCtx(t), c, nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "no enrollment offers") {
		t.Fatalf("got %q", out.String())
	}
}

func TestHostOffersJSON(t *testing.T) {
	c := startOfferServer(t, &fakeOfferServer{offers: sampleOffers()}, peercred.RoleAdmin)
	var out bytes.Buffer
	if err := hostOffers(testCtx(t), c, []string{"--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Offers []map[string]any `json:"offers"`
		Orphan []map[string]any `json:"possible_orphan_netbird_peers"`
	}
	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(doc.Offers) != 3 || len(doc.Orphan) != 1 {
		t.Fatalf("got %d offers, %d orphans", len(doc.Offers), len(doc.Orphan))
	}
	first := doc.Offers[0]
	for k, want := range map[string]any{
		"offer_id_hash": hashA, "state": "downloaded", "host_id": "web-01",
		"expires": "2026-11-12T10:30:00Z", "script_sha256": shaS,
		"client_addr": "192.0.2.10", "peer_addr": "127.0.0.1", "netbird": false,
	} {
		if first[k] != want {
			t.Errorf("%s = %v, want %v", k, first[k], want)
		}
	}
	if _, ok := first["offer_id"]; ok {
		t.Error("JSON carries an offer_id field")
	}
	if doc.Orphan[0]["offer_id_hash"] != hashC || doc.Orphan[0]["host_id"] != "nas-03" {
		t.Errorf("orphan = %v", doc.Orphan[0])
	}
}

// Host IDs and addresses are stored data; terminal control sequences in
// them must not reach the terminal raw.
func TestHostOffersEscapesControlCharacters(t *testing.T) {
	offers := sampleOffers()
	offers[0].HostId = "evil\x1b[2Jhost"
	offers[0].ClientAddr = "192.0.2.10\r\nfake"
	c := startOfferServer(t, &fakeOfferServer{offers: offers}, peercred.RoleAdmin)
	var out bytes.Buffer
	if err := hostOffers(testCtx(t), c, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\r") || strings.Contains(out.String(), "10\nfake") {
		t.Fatalf("control characters passed through: %q", out.String())
	}
}

func TestHostOffersUsage(t *testing.T) {
	c := startOfferServer(t, &fakeOfferServer{}, peercred.RoleAdmin)
	for _, args := range [][]string{{"extra"}, {"--bogus"}} {
		if err := hostOffers(testCtx(t), c, args, io.Discard); err == nil {
			t.Errorf("args %v: expected an error", args)
		}
	}
}

func TestHostOfferRevokeEveryNonFinalState(t *testing.T) {
	for _, st := range []string{"awaiting_approval", "open", "downloaded", "pairing_proposed"} {
		t.Run(st, func(t *testing.T) {
			f := &fakeOfferServer{offers: []*pb.EnrollOfferInfo{{OfferIdHash: hashB, HostId: "db-02", State: st}}}
			c := startOfferServer(t, f, peercred.RoleAdmin)
			var out bytes.Buffer
			if err := hostOfferRevoke(testCtx(t), c, []string{hashB}, &out); err != nil {
				t.Fatal(err)
			}
			if len(f.revokedSnap()) != 1 || f.revokedSnap()[0] != hashB {
				t.Fatalf("revoked = %v", f.revokedSnap())
			}
			if !strings.Contains(out.String(), "revoked") || !strings.Contains(out.String(), "was "+st) {
				t.Fatalf("output %q", out.String())
			}
		})
	}
}

func TestHostOfferRevokeFinalStateIsClearAndRevokesNothing(t *testing.T) {
	for _, st := range []string{"enrolled", "expired", "revoked", "failed"} {
		t.Run(st, func(t *testing.T) {
			f := &fakeOfferServer{offers: []*pb.EnrollOfferInfo{{OfferIdHash: hashB, HostId: "db-02", State: st}}}
			c := startOfferServer(t, f, peercred.RoleAdmin)
			err := hostOfferRevoke(testCtx(t), c, []string{hashB}, io.Discard)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "already "+st) || !strings.Contains(err.Error(), "nothing to revoke") {
				t.Fatalf("error %q", err)
			}
			if len(f.revokedSnap()) != 0 {
				t.Fatalf("revoked = %v", f.revokedSnap())
			}
		})
	}
}

// The state may change between the CLI's list and its revoke, and an
// offer may be missing from the executor's list: for a full hash the CLI
// asks the executor, and a final state it reports gets the same clear
// message.
func TestHostOfferRevokeUnlistedOffer(t *testing.T) {
	for _, tc := range []struct {
		state, want string
		revoked     int
	}{
		{"enrolled", "already enrolled", 0},
		{"awaiting_approval", "", 1},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := &fakeOfferServer{unlisted: true, offers: []*pb.EnrollOfferInfo{{OfferIdHash: hashA, State: tc.state}}}
			c := startOfferServer(t, f, peercred.RoleAdmin)
			err := hostOfferRevoke(testCtx(t), c, []string{hashA}, io.Discard)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing to revoke")) {
				t.Fatalf("error %v", err)
			}
			if len(f.revokedSnap()) != tc.revoked {
				t.Fatalf("revoked = %v", f.revokedSnap())
			}
		})
	}
	c := startOfferServer(t, &fakeOfferServer{}, peercred.RoleAdmin)
	err := hostOfferRevoke(testCtx(t), c, []string{hashA}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no such offer") {
		t.Fatalf("error %v", err)
	}
}

func TestHostOfferRevokePrefix(t *testing.T) {
	f := &fakeOfferServer{offers: sampleOffers()}
	c := startOfferServer(t, f, peercred.RoleAdmin)
	if err := hostOfferRevoke(testCtx(t), c, []string{"bbbb2222"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(f.revokedSnap()) != 1 || f.revokedSnap()[0] != hashB {
		t.Fatalf("revoked = %v", f.revokedSnap())
	}
	// hashA and hashC share this prefix.
	err := hostOfferRevoke(testCtx(t), c, []string{"aaaa1111"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error %v", err)
	}
	err = hostOfferRevoke(testCtx(t), c, []string{"dddd4444"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "no offer") {
		t.Fatalf("error %v", err)
	}
	if len(f.revokedSnap()) != 1 {
		t.Fatalf("revoked = %v", f.revokedSnap())
	}
}

func TestHostOfferRevokeRejectsMalformedID(t *testing.T) {
	f := &fakeOfferServer{offers: sampleOffers()}
	c := startOfferServer(t, f, peercred.RoleAdmin)
	for _, args := range [][]string{
		{}, {"a", "b"}, {"aaaa"}, {"AAAA1111"}, {"zzzz1111"}, {hashA + "00"}, {"aaaa1111\x1b"},
	} {
		if err := hostOfferRevoke(testCtx(t), c, args, io.Discard); err == nil {
			t.Errorf("args %q: expected an error", args)
		}
	}
	if f.listCount() != 0 || len(f.revokedSnap()) != 0 {
		t.Fatalf("malformed IDs reached the executor: lists %d, revoked %v", f.listCount(), f.revokedSnap())
	}
}

// Only the admin UID may use these commands. The server role may call
// RevokeEnrollOffer on the executor, but the CLI first lists (admin only),
// so a server-role caller revokes nothing through the CLI either.
func TestHostOffersRequireAdminUID(t *testing.T) {
	for _, role := range []peercred.Role{peercred.RoleServer, peercred.RolePVECollector} {
		t.Run(string(role), func(t *testing.T) {
			f := &fakeOfferServer{offers: sampleOffers()}
			c := startOfferServer(t, f, role)
			err := hostOffers(testCtx(t), c, nil, io.Discard)
			if grpcstatus.Code(err) != codes.PermissionDenied {
				t.Fatalf("offers: %v", err)
			}
			if !strings.Contains(err.Error(), "admin") {
				t.Errorf("offers error does not name the admin UID: %v", err)
			}
			err = hostOfferRevoke(testCtx(t), c, []string{hashB}, io.Discard)
			if grpcstatus.Code(err) != codes.PermissionDenied {
				t.Fatalf("offer-revoke: %v", err)
			}
			if len(f.revokedSnap()) != 0 || f.listCount() != 0 {
				t.Fatalf("non-admin reached the handlers: lists %d, revoked %v", f.listCount(), f.revokedSnap())
			}
		})
	}
}

func TestHostCmdDispatchesOfferCommands(t *testing.T) {
	if !strings.Contains(hostUsage, "nebula host offers") || !strings.Contains(hostUsage, "nebula host offer-revoke") {
		t.Fatal("host usage lacks the offer commands")
	}
	if !strings.Contains(usage, "host offers") || !strings.Contains(usage, "host offer-revoke") {
		t.Fatal("usage lacks the offer commands")
	}
}
