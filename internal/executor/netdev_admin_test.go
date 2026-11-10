// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
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
	pb.ExecutorService_ProposeNetDeviceRepin_FullMethodName,
	pb.ExecutorService_CommitNetDeviceRepin_FullMethodName,
	pb.ExecutorService_BlockNetDevice_FullMethodName,
	pb.ExecutorService_UnblockNetDevice_FullMethodName,
	pb.ExecutorService_RemoveNetDevice_FullMethodName,
	pb.ExecutorService_ListNetDevices_FullMethodName,
}

// TestNetDevAdminMethodsRefuseNonAdmin: through the real interceptor and
// role table, only the admin reaches a network device admin handler;
// server, pve-collector, netdev-collector, any other role and an unknown
// UID are refused before the handler runs. The roles equal the PVE admin
// methods'. The one exception is ListNetDevices, which the
// netdev-collector may also call for device metadata (ND-12).
func TestNetDevAdminMethodsRefuseNonAdmin(t *testing.T) {
	const (
		serverUID uint32 = 31001
		adminUID  uint32 = 31002
		collUID   uint32 = 31003
		discUID   uint32 = 31004
		ndUID     uint32 = 31005
		otherUID  uint32 = 31999
	)
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		serverUID: {peercred.RoleServer},
		adminUID:  {peercred.RoleAdmin},
		collUID:   {peercred.RolePVECollector},
		discUID:   {peercred.Role("discovery")},
		ndUID:     {peercred.RoleNetDevCollector},
	}, MethodRoles())
	roles := MethodRoles()
	pveAdmin := roles[pb.ExecutorService_ListPVEAdminRemotes_FullMethodName]
	for _, method := range netDevAdminMethods {
		wantRoles := pveAdmin
		listForCollector := method == pb.ExecutorService_ListNetDevices_FullMethodName
		if listForCollector {
			wantRoles = append(slices.Clone(pveAdmin), peercred.RoleNetDevCollector)
		}
		if !slices.Equal(roles[method], wantRoles) {
			t.Errorf("%s roles %v, want %v", method, roles[method], wantRoles)
		}
		for _, uid := range []uint32{serverUID, adminUID, collUID, discUID, ndUID, otherUID} {
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
			reached := false
			_, err := policy.UnaryInterceptor(nil)(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
				func(context.Context, any) (any, error) {
					reached = true
					return nil, nil
				})
			if uid == adminUID || (uid == ndUID && listForCollector) {
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
		"ProposeNetDeviceRepin": func() (proto.Message, error) {
			return svc.ProposeNetDeviceRepin(ctx, &pb.ProposeNetDeviceRepinRequest{DeviceId: "sw1", OldPin: testNetDevPin, ConfirmedNewPin: testNetDevPin2})
		},
		"CommitNetDeviceRepin": func() (proto.Message, error) {
			return svc.CommitNetDeviceRepin(ctx, &pb.CommitNetDeviceRepinRequest{DeviceId: "sw1", OldPin: testNetDevPin, ConfirmedNewPin: testNetDevPin2, ExecutionDigest: strings.Repeat("0", 64)})
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

// TestListNetDevicesFailsClosed: a missing store, a registry read error
// or a vault version read error returns no devices and a fixed message
// that does not repeat the store error.
func TestListNetDevicesFailsClosed(t *testing.T) {
	ctx := context.Background()
	got, err := (&Service{}).ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if got != nil || status.Code(err) != codes.Internal || status.Convert(err).Message() != "network device operation failed" {
		t.Fatalf("no store: reply %v error %v", got, err)
	}

	e := newNetDevTestEnv(t)
	if _, err := e.reg.RegisterNetDevice(ctx, cbsReq("core-sw", "10.20.0.2")); err != nil {
		t.Fatal(err)
	}
	for name, store := range map[string]*netDevListHookStore{
		"registry": {DB: e.db, failDevices: errors.New("registry read failed: netdev-core-sw-cred")},
		"vault":    {DB: e.db, failSecrets: errors.New("vault read failed: netdev-core-sw-cred")},
	} {
		svc := &Service{}
		got, err := listNetDevices(ctx, store)
		if got != nil || err == nil {
			t.Fatalf("%s: reply %v error %v, want an error", name, got, err)
		}
		if st := svc.netDevListFailed(err); status.Code(st) != codes.Internal || status.Convert(st).Message() != "network device operation failed" {
			t.Fatalf("%s: reply error %v", name, st)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := listNetDevices(cancelled, e.db); got != nil || err == nil {
		t.Fatalf("cancelled: reply %v error %v, want an error", got, err)
	}
}

// netDevListHookStore wraps the real store for the list path. It can fail
// either read and runs between after the registry read and before the
// vault read, which is where a concurrent remove or rotate lands.
type netDevListHookStore struct {
	*executordb.DB
	failDevices, failSecrets error
	between                  func() error
}

func (s *netDevListHookStore) ListNetDevices() ([]executordb.NetDevice, error) {
	if s.failDevices != nil {
		return nil, s.failDevices
	}
	rows, err := s.DB.ListNetDevices()
	if err == nil && s.between != nil {
		err = s.between()
	}
	return rows, err
}

func (s *netDevListHookStore) ListSecrets() ([]executordb.VaultSecret, error) {
	if s.failSecrets != nil {
		return nil, s.failSecrets
	}
	return s.DB.ListSecrets()
}

// insertNetDevWithCredential stores a device whose read credential is at
// vault version len(values).
func insertNetDevWithCredential(t *testing.T, e *netDevTestEnv, id, ip string, pin string, values ...string) executordb.NetDevice {
	t.Helper()
	ref := "netdev-" + id + "-cred"
	for _, v := range values {
		if _, err := e.vault.Put(ref, []byte(v), "admin"); err != nil {
			t.Fatal(err)
		}
	}
	d, err := e.db.InsertNetDevice(executordb.NetDevice{
		ID: id, Family: netdevcontract.FamilyCBS, Label: id, EndpointIP: ip, Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, PinValue: pin, TrustGeneration: 1,
		CredentialRef: ref, DigestKeyRef: "netdev-" + id + "-dk", FingerprintKeyRef: "netdev-" + id + "-fk",
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestListNetDevicesFlagsMissingCredential: a device whose credential
// vault entry is missing is listed with credential_missing and version 0;
// the other devices are listed normally and no vault reference leaks.
func TestListNetDevicesFlagsMissingCredential(t *testing.T) {
	ctx := context.Background()
	e := newNetDevTestEnv(t)
	orphan, err := e.db.InsertNetDevice(executordb.NetDevice{
		ID: "orphan-sw", Family: netdevcontract.FamilyCBS, Label: "orphan", EndpointIP: "10.20.0.4", Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, PinValue: testNetDevPin, TrustGeneration: 1,
		CredentialRef: "netdev-orphan-cred", DigestKeyRef: "netdev-orphan-dk", FingerprintKeyRef: "netdev-orphan-fk",
	})
	if err != nil {
		t.Fatal(err)
	}
	ok := insertNetDevWithCredential(t, e, "acc-sw", "10.20.0.3", testNetDevPin2, "first-read-secret")
	got, err := (&Service{db: e.db}).ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		t.Fatalf("list with a missing credential entry: %v", err)
	}
	if len(got.GetDevices()) != 2 {
		t.Fatalf("devices %v, want acc-sw and orphan-sw", got.GetDevices())
	}
	acc, orph := got.Devices[0], got.Devices[1]
	if acc.GetDeviceId() != ok.ID || acc.GetCredentialMissing() || acc.GetCredentialVersion() != 1 {
		t.Errorf("healthy device: %v", acc)
	}
	if orph.GetDeviceId() != orphan.ID || !orph.GetCredentialMissing() || orph.GetCredentialVersion() != 0 {
		t.Errorf("orphan device: %v, want credential_missing and version 0", orph)
	}
	text := prototext.Format(got)
	for _, s := range []string{"netdev-", "read-secret"} {
		if strings.Contains(text, s) {
			t.Errorf("reply carries %q", s)
		}
	}
	// A device without any credential reference is not "missing".
	swReq := cbsReq("core-sw", "10.20.0.2")
	swReq.Pin = strings.Repeat("cd", 32)
	sw, err := e.reg.RegisterNetDevice(ctx, swReq)
	if err != nil {
		t.Fatal(err)
	}
	got, err = (&Service{db: e.db}).ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range got.GetDevices() {
		if d.GetDeviceId() == sw.ID && (d.GetCredentialMissing() || d.GetCredentialVersion() != 0) {
			t.Errorf("device without credential: %v", d)
		}
	}
}

// TestListNetDevicesToleratesConcurrentCredentialChange: a credential
// removed or rotated after the registry read and before the version read
// shows as missing or at its new version; the list never fails.
func TestListNetDevicesToleratesConcurrentCredentialChange(t *testing.T) {
	ctx := context.Background()
	e := newNetDevTestEnv(t)
	rm := insertNetDevWithCredential(t, e, "rm-sw", "10.20.0.5", testNetDevPin, "v1")
	rot := insertNetDevWithCredential(t, e, "rot-sw", "10.20.0.6", testNetDevPin2, "v1")
	store := &netDevListHookStore{DB: e.db, between: func() error {
		if _, err := e.db.DeleteSecret(rm.CredentialRef); err != nil {
			return err
		}
		_, err := e.vault.Put(rot.CredentialRef, []byte("v2"), "admin")
		return err
	}}
	got, err := listNetDevices(ctx, store)
	if err != nil {
		t.Fatalf("list across a concurrent remove and rotate: %v", err)
	}
	if len(got.GetDevices()) != 2 {
		t.Fatalf("devices %v", got.GetDevices())
	}
	if d := got.Devices[0]; d.GetDeviceId() != rm.ID || !d.GetCredentialMissing() || d.GetCredentialVersion() != 0 {
		t.Errorf("removed credential: %v, want credential_missing", d)
	}
	if d := got.Devices[1]; d.GetDeviceId() != rot.ID || d.GetCredentialMissing() || d.GetCredentialVersion() != 2 {
		t.Errorf("rotated credential: %v, want version 2", d)
	}
}

// TestListNetDevicesConcurrentRemoveNeverInternal runs lists against a
// writer that keeps removing and re-adding a device credential; no list
// may fail and every row is either at a real version or flagged missing.
func TestListNetDevicesConcurrentRemoveNeverInternal(t *testing.T) {
	ctx := context.Background()
	e := newNetDevTestEnv(t)
	d := insertNetDevWithCredential(t, e, "flap-sw", "10.20.0.7", testNetDevPin, "v1")
	svc := &Service{db: e.db}
	done := make(chan struct{})
	writerErr := make(chan error, 1)
	go func() {
		defer close(writerErr)
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := e.db.DeleteSecret(d.CredentialRef); err != nil {
				writerErr <- err
				return
			}
			if _, err := e.vault.Put(d.CredentialRef, []byte("again"), "admin"); err != nil {
				writerErr <- err
				return
			}
		}
	}()
	for i := 0; i < 50; i++ {
		got, err := svc.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
		if err != nil {
			close(done)
			t.Fatalf("list %d during concurrent remove: %v", i, err)
		}
		if len(got.GetDevices()) != 1 {
			close(done)
			t.Fatalf("list %d: devices %v", i, got.GetDevices())
		}
		row := got.Devices[0]
		if row.GetCredentialMissing() == (row.GetCredentialVersion() != 0) {
			close(done)
			t.Fatalf("list %d: inconsistent row %v", i, row)
		}
	}
	close(done)
	if err := <-writerErr; err != nil {
		t.Fatal(err)
	}
}

// TestListNetDevicesLoadsNoSecretBlobs: the list path reads credential
// versions only through the blob-free ListSecrets. The store it is given
// is the narrow netDevListStore (no GetSecret), and the source of the
// list path never names GetSecret.
func TestListNetDevicesLoadsNoSecretBlobs(t *testing.T) {
	var _ netDevListStore = (*executordb.DB)(nil)
	if _, ok := reflect.TypeFor[netDevListStore]().MethodByName("GetSecret"); ok {
		t.Fatal("netDevListStore exposes GetSecret")
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "netdev_admin.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The list path's functions (the credential handlers' protobuf
	// in.GetSecret() getters are a different thing and are excluded).
	listPath := map[string]bool{"ListNetDevices": true, "listNetDevices": true, "netDevListFailed": true, "netDeviceInfo": true}
	seen := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !listPath[fn.Name.Name] {
			continue
		}
		seen++
		ast.Inspect(fn, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "GetSecret" || sel.Sel.Name == "WrappedDEK" || sel.Sel.Name == "Sealed") {
				t.Errorf("%s: list path names %s", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
	if seen != len(listPath) {
		t.Fatalf("found %d of %d list path functions in netdev_admin.go", seen, len(listPath))
	}

	e := newNetDevTestEnv(t)
	insertNetDevWithCredential(t, e, "acc-sw", "10.20.0.3", testNetDevPin, "read-secret")
	secrets, err := e.db.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if s.WrappedDEK != nil || s.Sealed != nil {
			t.Fatalf("ListSecrets returned blobs for %s", s.ID)
		}
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
		// The re-pin proposal returns the shared permit reply; its bytes
		// fields (canonical request, WebAuthn challenge and options) are
		// approval material, not secrets. It is skipped by marking it seen;
		// TestNetDevRepinMirrorsPVERepinContract pins that reply type.
		walkFields(m.Output(), map[protoreflect.FullName]bool{"nebula.executor.v1.ProposeExecutionResponse": true}, func(f protoreflect.FieldDescriptor) {
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
