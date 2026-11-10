// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// netDevCollectorAllowed is the complete method set of the
// netdev-collector role (ND-12): device metadata and typed reads.
var netDevCollectorAllowed = map[string]bool{
	pb.ExecutorService_ListNetDevices_FullMethodName: true,
	pb.ExecutorService_ReadNetDevice_FullMethodName:  true,
}

// allServiceMethods returns the full name of every ExecutorService method
// in the descriptor, so a method missing from the role table is covered
// too.
func allServiceMethods(t *testing.T) []string {
	t.Helper()
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	if svc == nil {
		t.Fatal("ExecutorService not found")
	}
	var out []string
	for i := 0; i < svc.Methods().Len(); i++ {
		out = append(out, fmt.Sprintf("/%s/%s", svc.FullName(), svc.Methods().Get(i).Name()))
	}
	return out
}

// TestMethodRolesNetDevReadSurface pins the ND-12 role entries: ReadNetDevice
// is {netdev-collector, admin} exactly like ReadPVE is {pve-collector,
// admin}; ListNetDevices is admin plus the netdev-collector; the server
// and the pve-collector call neither.
func TestMethodRolesNetDevReadSurface(t *testing.T) {
	roles := MethodRoles()
	read := roles[pb.ExecutorService_ReadNetDevice_FullMethodName]
	if want := []peercred.Role{peercred.RoleNetDevCollector, peercred.RoleAdmin}; !slices.Equal(read, want) {
		t.Errorf("ReadNetDevice roles %v, want %v", read, want)
	}
	// Mirror of ReadPVE with the collector role swapped.
	pve := slices.Clone(roles[pb.ExecutorService_ReadPVE_FullMethodName])
	for i, r := range pve {
		if r == peercred.RolePVECollector {
			pve[i] = peercred.RoleNetDevCollector
		}
	}
	if !slices.Equal(read, pve) {
		t.Errorf("ReadNetDevice roles %v do not mirror ReadPVE %v", read, roles[pb.ExecutorService_ReadPVE_FullMethodName])
	}
	list := roles[pb.ExecutorService_ListNetDevices_FullMethodName]
	if want := []peercred.Role{peercred.RoleAdmin, peercred.RoleNetDevCollector}; !slices.Equal(list, want) {
		t.Errorf("ListNetDevices roles %v, want %v", list, want)
	}
	for _, m := range []string{pb.ExecutorService_ReadNetDevice_FullMethodName, pb.ExecutorService_ListNetDevices_FullMethodName} {
		for _, r := range []peercred.Role{peercred.RoleServer, peercred.RolePVECollector} {
			if slices.Contains(roles[m], r) {
				t.Errorf("%s allows %s", m, r)
			}
		}
	}
}

// TestNetDevCollectorMayCallOnlyTypedReads: through the real interceptor,
// the netdev-collector reaches ListNetDevices and ReadNetDevice and is
// refused for every other method of the service (reveal, admin, change,
// PVE, read grants, execution), before the handler runs. The server is
// refused ReadNetDevice; the pve-collector is refused both netdev methods.
func TestNetDevCollectorMayCallOnlyTypedReads(t *testing.T) {
	const (
		serverUID uint32 = 32001
		adminUID  uint32 = 32002
		pveUID    uint32 = 32003
		ndUID     uint32 = 32004
	)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
		pveUID:    {peercred.RolePVECollector},
		ndUID:     {peercred.RoleNetDevCollector},
	}, MethodRoles())
	call := func(uid uint32, method string) (bool, error) {
		ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
		reached := false
		_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
			func(ctx context.Context, _ any) (any, error) {
				reached = true
				if c, ok := peercred.CallerFrom(ctx); !ok || (uid == ndUID && c.Role != peercred.RoleNetDevCollector) {
					t.Errorf("%s: caller role %v", method, c.Role)
				}
				return nil, nil
			})
		return reached, err
	}
	methods := allServiceMethods(t)
	for m := range MethodRoles() {
		if !slices.Contains(methods, m) {
			methods = append(methods, m)
		}
	}
	seen := 0
	for _, m := range methods {
		reached, err := call(ndUID, m)
		if netDevCollectorAllowed[m] {
			seen++
			if err != nil || !reached {
				t.Errorf("netdev-collector %s: err %v reached %v, want allowed", m, err, reached)
			}
			continue
		}
		if status.Code(err) != codes.PermissionDenied || reached {
			t.Errorf("netdev-collector %s: err %v reached %v, want PermissionDenied", m, err, reached)
		}
	}
	if seen != len(netDevCollectorAllowed) {
		t.Fatalf("found %d of %d allowed methods in the service", seen, len(netDevCollectorAllowed))
	}
	for _, c := range []struct {
		uid    uint32
		method string
		want   bool
	}{
		{serverUID, pb.ExecutorService_ReadNetDevice_FullMethodName, false},
		{serverUID, pb.ExecutorService_ListNetDevices_FullMethodName, false},
		{pveUID, pb.ExecutorService_ReadNetDevice_FullMethodName, false},
		{pveUID, pb.ExecutorService_ListNetDevices_FullMethodName, false},
		{adminUID, pb.ExecutorService_ReadNetDevice_FullMethodName, true},
		{adminUID, pb.ExecutorService_ListNetDevices_FullMethodName, true},
	} {
		reached, err := call(c.uid, c.method)
		if c.want != (reached && err == nil) {
			t.Errorf("uid %d %s: err %v reached %v, want allowed=%v", c.uid, c.method, err, reached, c.want)
		}
		if !c.want && status.Code(err) != codes.PermissionDenied {
			t.Errorf("uid %d %s: err %v, want PermissionDenied", c.uid, c.method, err)
		}
	}
}

// TestReadNetDeviceProtoIsClosedAndTyped pins the wire contract: the
// request is exactly {device_id, read}; the read enum is the closed set of
// ten typed reads; no message reachable from request or reply has a bytes
// field or a free-form command, XPath, URL or raw-text field.
func TestReadNetDeviceProtoIsClosedAndTyped(t *testing.T) {
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	m := svc.Methods().ByName("ReadNetDevice")
	if m == nil {
		t.Fatal("ReadNetDevice missing")
	}
	if m.IsStreamingClient() || m.IsStreamingServer() {
		t.Fatal("ReadNetDevice must be unary")
	}
	in := m.Input()
	if in.Fields().Len() != 2 {
		t.Fatalf("ReadNetDeviceRequest has %d fields, want 2", in.Fields().Len())
	}
	id, rd := in.Fields().ByName("device_id"), in.Fields().ByName("read")
	if id == nil || id.Number() != 1 || id.Kind() != protoreflect.StringKind ||
		rd == nil || rd.Number() != 2 || rd.Kind() != protoreflect.EnumKind || rd.Enum().Name() != "NetDeviceRead" {
		t.Fatalf("ReadNetDeviceRequest fields %v", in.Fields())
	}
	wantReads := []string{
		"NET_DEVICE_READ_UNSPECIFIED",
		"NET_DEVICE_READ_CBS_VERSION", "NET_DEVICE_READ_CBS_VLANS", "NET_DEVICE_READ_CBS_INTERFACES",
		"NET_DEVICE_READ_CBS_MAC_TABLE", "NET_DEVICE_READ_CBS_LLDP",
		"NET_DEVICE_READ_PANOS_ZONES", "NET_DEVICE_READ_PANOS_OBJECTS", "NET_DEVICE_READ_PANOS_SECURITY_RULES",
		"NET_DEVICE_READ_PANOS_NAT_RULES", "NET_DEVICE_READ_PANOS_RULE_HIT_COUNTS",
	}
	vals := rd.Enum().Values()
	if vals.Len() != len(wantReads) {
		t.Fatalf("NetDeviceRead has %d values, want %d", vals.Len(), len(wantReads))
	}
	for i, name := range wantReads {
		if v := vals.Get(i); string(v.Name()) != name || int(v.Number()) != i {
			t.Errorf("NetDeviceRead value %d = %s(%d), want %s(%d)", i, v.Name(), v.Number(), name, i)
		}
	}
	// Each typed read has exactly one payload in the reply oneof.
	out := m.Output()
	payload := out.Oneofs().ByName("payload")
	if payload == nil || payload.Fields().Len() != len(wantReads)-1 {
		t.Fatalf("ReadNetDeviceResponse payload oneof: %v", payload)
	}
	for _, f := range []string{"device_id", "trust_generation", "observed_at_unix", "incomplete"} {
		if out.Fields().ByName(protoreflect.Name(f)) == nil {
			t.Errorf("ReadNetDeviceResponse lacks %s", f)
		}
	}
	forbidden := []string{"command", "cmd", "xpath", "url", "path", "raw", "query", "cli", "secret", "password", "credential", "key", "config", "body"}
	for _, md := range []protoreflect.MessageDescriptor{in, out} {
		walkFields(md, map[protoreflect.FullName]bool{}, func(f protoreflect.FieldDescriptor) {
			if f.Kind() == protoreflect.BytesKind {
				t.Errorf("%s is a bytes field", f.FullName())
			}
			for _, part := range strings.Split(string(f.Name()), "_") {
				if slices.Contains(forbidden, part) {
					t.Errorf("%s is a free-form or secret field", f.FullName())
				}
			}
		})
	}
}

// TestNetDevRepinRolesMatchPVERepin: the network device re-pin pair has
// exactly the roles of the PVE re-pin pair (admin only), method by
// method, and no single-step re-pin method exists in the role table.
func TestNetDevRepinRolesMatchPVERepin(t *testing.T) {
	roles := MethodRoles()
	for _, c := range []struct{ netdev, pve string }{
		{pb.ExecutorService_ProposeNetDeviceRepin_FullMethodName, pb.ExecutorService_ProposePVERepin_FullMethodName},
		{pb.ExecutorService_CommitNetDeviceRepin_FullMethodName, pb.ExecutorService_CommitPVERepin_FullMethodName},
	} {
		got, ok := roles[c.netdev]
		if !ok {
			t.Errorf("%s missing from the role table", c.netdev)
			continue
		}
		if len(got) == 0 || !slices.Equal(got, roles[c.pve]) {
			t.Errorf("%s roles %v, want the roles of %s %v", c.netdev, got, c.pve, roles[c.pve])
		}
	}
	for method := range roles {
		if strings.HasSuffix(method, "/RepinNetDevice") {
			t.Errorf("single-step re-pin method %s is in the role table", method)
		}
	}
}

// TestNetDevRepinMirrorsPVERepinContract pins the wire contract of the
// re-pin pair (ADR 0010 D1): there is no single-step RepinNetDevice; the
// proposal returns the shared HIGH permit reply; the commit carries the
// execution_digest of that permit and the same device, old and new pin
// fields as the proposal, field for field like CommitPVERepin.
func TestNetDevRepinMirrorsPVERepinContract(t *testing.T) {
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	if svc == nil {
		t.Fatal("ExecutorService not found")
	}
	if svc.Methods().ByName("RepinNetDevice") != nil {
		t.Fatal("single-step RepinNetDevice must not exist")
	}
	propose := svc.Methods().ByName("ProposeNetDeviceRepin")
	commit := svc.Methods().ByName("CommitNetDeviceRepin")
	pvePropose := svc.Methods().ByName("ProposePVERepin")
	pveCommit := svc.Methods().ByName("CommitPVERepin")
	if propose == nil || commit == nil || pvePropose == nil || pveCommit == nil {
		t.Fatal("re-pin methods missing from the descriptor")
	}

	// The proposal reply is exactly the PVE proposal reply shape: one
	// field "permit" of type ProposeExecutionResponse.
	wantPermit := pvePropose.Output().Fields().ByName("permit")
	gotPermit := propose.Output().Fields().ByName("permit")
	if gotPermit == nil || propose.Output().Fields().Len() != 1 ||
		gotPermit.Message() == nil || gotPermit.Message().FullName() != wantPermit.Message().FullName() ||
		gotPermit.Number() != wantPermit.Number() {
		t.Fatalf("ProposeNetDeviceRepin reply must be {permit ProposeExecutionResponse = 1}, got %v", propose.Output().Fields())
	}

	// The commit binds the same subject as the proposal plus the digest.
	type field struct {
		name   protoreflect.Name
		kind   protoreflect.Kind
		number protoreflect.FieldNumber
	}
	fieldsOf := func(md protoreflect.MessageDescriptor) []field {
		var out []field
		for i := 0; i < md.Fields().Len(); i++ {
			f := md.Fields().Get(i)
			out = append(out, field{f.Name(), f.Kind(), f.Number()})
		}
		return out
	}
	subject := []field{
		{"device_id", protoreflect.StringKind, 1},
		{"old_pin", protoreflect.StringKind, 2},
		{"confirmed_new_pin", protoreflect.StringKind, 3},
	}
	if got := fieldsOf(propose.Input()); !slices.Equal(got, subject) {
		t.Errorf("ProposeNetDeviceRepinRequest fields %v, want %v", got, subject)
	}
	wantCommit := append(slices.Clone(subject), field{"execution_digest", protoreflect.StringKind, 4})
	if got := fieldsOf(commit.Input()); !slices.Equal(got, wantCommit) {
		t.Errorf("CommitNetDeviceRepinRequest fields %v, want %v", got, wantCommit)
	}
	// The digest field is the one the PVE commit uses.
	pveDigest := pveCommit.Input().Fields().ByName("execution_digest")
	if pveDigest == nil || pveDigest.Number() != 4 || pveDigest.Kind() != protoreflect.StringKind {
		t.Fatalf("CommitPVERepinRequest.execution_digest changed: %v", pveDigest)
	}
	// Neither request carries a free-form confirmation in place of the
	// permit.
	for _, md := range []protoreflect.MessageDescriptor{propose.Input(), commit.Input()} {
		if md.Fields().ByName("confirm") != nil {
			t.Errorf("%s has a confirm field; re-pin is gated by the HIGH permit", md.FullName())
		}
	}
	// The commit reply is the device metadata, like the other admin
	// replies.
	dev := commit.Output().Fields().ByName("device")
	if dev == nil || dev.Message() == nil || dev.Message().Name() != "NetDeviceInfo" {
		t.Errorf("CommitNetDeviceRepinResponse must carry {device NetDeviceInfo}")
	}
}
