// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// netDevAdminMethods is every network device admin method (ND-11).
var netDevAdminMethods = []string{
	pb.ExecutorService_ProbeNetDevice_FullMethodName,
	pb.ExecutorService_RegisterNetDevice_FullMethodName,
	pb.ExecutorService_SetNetDeviceCredential_FullMethodName,
	pb.ExecutorService_RotateNetDeviceCredential_FullMethodName,
	pb.ExecutorService_RepinNetDevice_FullMethodName,
	pb.ExecutorService_BlockNetDevice_FullMethodName,
	pb.ExecutorService_UnblockNetDevice_FullMethodName,
	pb.ExecutorService_RemoveNetDevice_FullMethodName,
	pb.ExecutorService_ListNetDevices_FullMethodName,
}

// TestNetDevAdminMethodsRefuseNonAdmin: through the real interceptor and
// role table, only the admin reaches a network device admin handler;
// server, pve-collector, any other role and an unknown UID are refused
// before the handler runs. The roles equal the PVE admin methods'.
func TestNetDevAdminMethodsRefuseNonAdmin(t *testing.T) {
	const (
		serverUID uint32 = 31001
		adminUID  uint32 = 31002
		collUID   uint32 = 31003
		discUID   uint32 = 31004
		otherUID  uint32 = 31999
	)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
		collUID:   {peercred.RolePVECollector},
		discUID:   {peercred.Role("discovery")},
	}, MethodRoles())
	roles := MethodRoles()
	pveAdmin := roles[pb.ExecutorService_ListPVEAdminRemotes_FullMethodName]
	for _, method := range netDevAdminMethods {
		if !slices.Equal(roles[method], pveAdmin) {
			t.Errorf("%s roles %v, want the PVE admin roles %v", method, roles[method], pveAdmin)
		}
		for _, uid := range []uint32{serverUID, adminUID, collUID, discUID, otherUID} {
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
			reached := false
			_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
				func(context.Context, any) (any, error) {
					reached = true
					return nil, nil
				})
			if uid == adminUID {
				if err != nil || !reached {
					t.Errorf("%s admin: err %v reached %v, want allowed", method, err, reached)
				}
			} else if status.Code(err) != codes.PermissionDenied || reached {
				t.Errorf("%s uid %d: err %v reached %v, want PermissionDenied", method, uid, err, reached)
			}
		}
	}
}

// TestNetDevAdminUnimplementedExceptList: every admin method except
// ListNetDevices answers Unimplemented with no reply, and the credential
// methods wipe the secret buffer even so.
func TestNetDevAdminUnimplementedExceptList(t *testing.T) {
	svc := &Service{}
	ctx := context.Background()
	setSecret := []byte("s3cr3t-read-credential")
	rotSecret := []byte("n3w-read-credential")
	calls := map[string]func() (proto.Message, error){
		"ProbeNetDevice": func() (proto.Message, error) {
			return svc.ProbeNetDevice(ctx, &pb.ProbeNetDeviceRequest{Family: "cbs", Endpoint: "10.0.0.2", Port: 22})
		},
		"RegisterNetDevice": func() (proto.Message, error) {
			return svc.RegisterNetDevice(ctx, &pb.RegisterNetDeviceRequest{DeviceId: "sw1", Confirm: "yes"})
		},
		"SetNetDeviceCredential": func() (proto.Message, error) {
			return svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: "sw1", Username: "nos-read", Secret: setSecret})
		},
		"RotateNetDeviceCredential": func() (proto.Message, error) {
			return svc.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: "sw1", ExpectedCredentialVersion: 1, Secret: rotSecret})
		},
		"RepinNetDevice": func() (proto.Message, error) {
			return svc.RepinNetDevice(ctx, &pb.RepinNetDeviceRequest{DeviceId: "sw1", Confirm: "yes"})
		},
		"BlockNetDevice": func() (proto.Message, error) {
			return svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: "sw1", Reason: "test"})
		},
		"UnblockNetDevice": func() (proto.Message, error) {
			return svc.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: "sw1", Confirm: "yes"})
		},
		"RemoveNetDevice": func() (proto.Message, error) {
			return svc.RemoveNetDevice(ctx, &pb.RemoveNetDeviceRequest{DeviceId: "sw1", Confirm: "yes"})
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			got, err := call()
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("want Unimplemented, got %v", err)
			}
			if got != nil && !isNilMessage(got) {
				t.Fatalf("want no reply, got %v", got)
			}
			if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "n3w-read") {
				t.Fatal("error echoes the secret")
			}
		})
	}
	for name, buf := range map[string][]byte{"set": setSecret, "rotate": rotSecret} {
		if !bytes.Equal(buf, make([]byte, len(buf))) {
			t.Errorf("%s: secret buffer not wiped", name)
		}
	}
}

// isNilMessage reports whether m is a typed nil message pointer.
func isNilMessage(m proto.Message) bool {
	return !m.ProtoReflect().IsValid()
}

// TestListNetDevicesReturnsRegistryRowsWithoutKeyRefs: ListNetDevices
// returns every live registry row, blocked ones flagged, tombstoned ones
// omitted, with the credential version and never a vault reference.
func TestListNetDevicesReturnsRegistryRowsWithoutKeyRefs(t *testing.T) {
	e := newNetDevTestEnv(t)
	ctx := context.Background()
	sw, err := e.reg.RegisterNetDevice(ctx, cbsReq("core-sw", "10.20.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	fwReq := cbsReq("edge-fw", "10.20.0.1")
	fwReq.Family, fwReq.PinKind, fwReq.Pin, fwReq.Port, fwReq.Label = netdevcontract.FamilyPANOS, netdevcontract.PinTLSLeaf, testNetDevPin2, 443, "edge firewall"
	fw, err := e.reg.RegisterNetDevice(ctx, fwReq)
	if err != nil {
		t.Fatal(err)
	}
	if fw, err = e.db.BlockNetDevice(fw.ID, "pin mismatch"); err != nil {
		t.Fatal(err)
	}
	// A device with an enrolled read credential at vault version 2.
	const credRef = "netdev-acc-sw-cred"
	for _, v := range []string{"first-read-secret", "second-read-secret"} {
		if _, err := e.vault.Put(credRef, []byte(v), "admin"); err != nil {
			t.Fatal(err)
		}
	}
	acc, err := e.db.InsertNetDevice(executordb.NetDevice{
		ID: "acc-sw", Family: netdevcontract.FamilyCBS, Label: "access", EndpointIP: "10.20.0.3", Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, PinValue: strings.Repeat("ab", 32), TrustGeneration: 1,
		CredentialRef: credRef, DigestKeyRef: "netdev-acc-sw-dk", FingerprintKeyRef: "netdev-acc-sw-fk",
	})
	if err != nil {
		t.Fatal(err)
	}
	goneReq := cbsReq("old-sw", "10.20.0.9")
	goneReq.Pin = strings.Repeat("cd", 32)
	gone, err := e.reg.RegisterNetDevice(ctx, goneReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.TombstoneNetDevice(gone.ID); err != nil {
		t.Fatal(err)
	}

	svc := &Service{db: e.db}
	got, err := svc.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	info := func(d executordb.NetDevice, credVersion int64) *pb.NetDeviceInfo {
		return &pb.NetDeviceInfo{
			DeviceId: d.ID, Family: string(d.Family), Label: d.Label, EndpointIp: d.EndpointIP, Port: uint32(d.Port),
			PinKind: string(d.PinKind), TrustPin: d.PinValue, TrustGeneration: d.TrustGeneration,
			Blocked: d.Blocked, BlockReason: d.BlockReason, CredentialVersion: credVersion,
			CreatedAtUnix: d.CreatedAt.Unix(), UpdatedAtUnix: d.UpdatedAt.Unix(),
		}
	}
	want := &pb.ListNetDevicesResponse{Devices: []*pb.NetDeviceInfo{info(acc, 2), info(sw, 0), info(fw, 0)}}
	if !proto.Equal(got, want) {
		t.Fatalf("list mismatch:\ngot  %v\nwant %v", got, want)
	}
	if !fw.Blocked || got.Devices[2].GetBlockReason() != "pin mismatch" {
		t.Fatalf("blocked device not flagged: %v", got.Devices[2])
	}
	text := prototext.Format(got)
	for _, d := range []executordb.NetDevice{acc, sw, fw} {
		for _, ref := range []string{d.CredentialRef, d.DigestKeyRef, d.FingerprintKeyRef} {
			if ref != "" && strings.Contains(text, ref) {
				t.Errorf("reply carries vault reference %q", ref)
			}
		}
	}
	for _, s := range []string{"netdev-", "read-secret"} {
		if strings.Contains(text, s) {
			t.Errorf("reply carries %q", s)
		}
	}
}

// TestListNetDevicesFailsClosed: a store error or a credential reference
// without its vault entry returns no devices and a fixed message.
func TestListNetDevicesFailsClosed(t *testing.T) {
	ctx := context.Background()
	got, err := (&Service{}).ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if got != nil || status.Code(err) != codes.Internal || status.Convert(err).Message() != "network device operation failed" {
		t.Fatalf("no store: reply %v error %v", got, err)
	}

	e := newNetDevTestEnv(t)
	if _, err := e.db.InsertNetDevice(executordb.NetDevice{
		ID: "orphan-sw", Family: netdevcontract.FamilyCBS, Label: "orphan", EndpointIP: "10.20.0.4", Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, PinValue: testNetDevPin, TrustGeneration: 1,
		CredentialRef: "netdev-orphan-cred", DigestKeyRef: "netdev-orphan-dk", FingerprintKeyRef: "netdev-orphan-fk",
	}); err != nil {
		t.Fatal(err)
	}
	got, err = (&Service{db: e.db}).ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if got != nil || status.Code(err) != codes.Internal || status.Convert(err).Message() != "network device operation failed" {
		t.Fatalf("missing credential entry: reply %v error %v", got, err)
	}
}

// TestNetDevAdminProtoCarriesNoSecrets pins the wire contract: requests
// carry secret material only in bytes fields named "secret" marked
// debug_redact, and no reply (transitively) has a secret, user name,
// password, vault reference or key field, or any redacted field.
func TestNetDevAdminProtoCarriesNoSecrets(t *testing.T) {
	svc := pb.File_nebula_executor_v1_executor_proto.Services().ByName("ExecutorService")
	if svc == nil {
		t.Fatal("ExecutorService not found")
	}
	secretFields := 0
	for _, full := range netDevAdminMethods {
		name := protoreflect.Name(full[strings.LastIndex(full, "/")+1:])
		m := svc.Methods().ByName(name)
		if m == nil {
			t.Fatalf("method %s not in descriptor", name)
		}
		walkFields(m.Input(), map[protoreflect.FullName]bool{}, func(f protoreflect.FieldDescriptor) {
			redact := f.Options().(*descriptorpb.FieldOptions).GetDebugRedact()
			if f.Kind() == protoreflect.BytesKind || f.Name() == "secret" || redact {
				if f.Kind() != protoreflect.BytesKind || f.Name() != "secret" || !redact {
					t.Errorf("%s: field %s must be bytes named secret with debug_redact", name, f.FullName())
				}
				secretFields++
			}
		})
		walkFields(m.Output(), map[protoreflect.FullName]bool{}, func(f protoreflect.FieldDescriptor) {
			n := string(f.Name())
			if f.Kind() == protoreflect.BytesKind || f.Options().(*descriptorpb.FieldOptions).GetDebugRedact() ||
				strings.Contains(n, "secret") || strings.Contains(n, "user") || strings.Contains(n, "password") ||
				strings.HasSuffix(n, "_ref") || strings.Contains(n, "key_ref") || strings.Contains(n, "token") {
				t.Errorf("%s: reply field %s may carry secret material", name, f.FullName())
			}
		})
	}
	if secretFields != 2 {
		t.Errorf("secret request fields = %d, want 2 (set and rotate)", secretFields)
	}
}

// walkFields calls fn for every field of md and of its nested messages.
func walkFields(md protoreflect.MessageDescriptor, seen map[protoreflect.FullName]bool, fn func(protoreflect.FieldDescriptor)) {
	if seen[md.FullName()] {
		return
	}
	seen[md.FullName()] = true
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		fn(f)
		if f.Message() != nil {
			walkFields(f.Message(), seen, fn)
		}
	}
}
