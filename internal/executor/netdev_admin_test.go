// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
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

// TestNetDevAdminWithoutStoreFailsClosed: a service without database and
// vault answers every lifecycle method with an error and no reply, never
// echoes a secret, and the credential methods wipe the secret buffer even
// so. (Part 1 pinned Unimplemented here; part 2 implements the methods.)
func TestNetDevAdminWithoutStoreFailsClosed(t *testing.T) {
	svc := &Service{}
	ctx := context.Background()
	setSecret := []byte("s3cr3t-read-credential")
	rotSecret := []byte("n3w-read-credential")
	calls := map[string]func() (proto.Message, error){
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
			if err == nil {
				t.Fatal("want an error without a store")
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

// --- ND-11 part 2: probe, registration and credential lifecycle ---

const netDevTestVaultPass = "correct-horse-battery-staple-correct-horse-battery-staple-correct-horse-battery-staple-correct-horse-battery-staple-"

// netDevSSHServer is a loopback SSH server that records every user
// authentication attempt (including "none") and refuses all of them.
type netDevSSHServer struct {
	addr  string
	key   ssh.PublicKey
	mu    sync.Mutex
	auths []string
	done  chan struct{}
}

func startNetDevSSHServer(t *testing.T) *netDevSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s := &netDevSSHServer{key: signer.PublicKey(), done: make(chan struct{}, 64)}
	refuse := errors.New("refused")
	cfg := &ssh.ServerConfig{
		AuthLogCallback: func(c ssh.ConnMetadata, method string, _ error) {
			s.mu.Lock()
			s.auths = append(s.auths, method+" "+c.User())
			s.mu.Unlock()
		},
		PasswordCallback:  func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, refuse },
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, refuse },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { s.done <- struct{}{} }()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				if sc, chans, reqs, err := ssh.NewServerConn(c, cfg); err == nil {
					go ssh.DiscardRequests(reqs)
					go func() {
						for ch := range chans {
							_ = ch.Reject(ssh.Prohibited, "no")
						}
					}()
					_ = sc.Close()
				}
			}()
		}
	}()
	return s
}

// waitConns waits until n connections have ended on the server side, so
// every byte the client sent has been processed.
func (s *netDevSSHServer) waitConns(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			t.Fatal("ssh server connection did not end")
		}
	}
}

func (s *netDevSSHServer) authAttempts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.auths)
}

// netDevTLSServer is a loopback TLS server with a self-signed leaf. It
// counts completed handshakes and application bytes received.
type netDevTLSServer struct {
	addr      string
	cert      *x509.Certificate
	mu        sync.Mutex
	completed int
	appBytes  int64
	done      chan struct{}
}

func startNetDevTLSServer(t *testing.T) *netDevTLSServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fw.lab.test"}, DNSNames: []string{"fw.lab.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s := &netDevTLSServer{cert: cert, done: make(chan struct{}, 64)}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { s.done <- struct{}{} }()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				n, _ := io.Copy(io.Discard, tc)
				s.mu.Lock()
				s.completed++
				s.appBytes += n
				s.mu.Unlock()
			}()
		}
	}()
	return s
}

func (s *netDevTLSServer) waitConns(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			t.Fatal("tls server connection did not end")
		}
	}
}

// netDevDialer maps every dial to a loopback target and records the
// address the executor asked for (the checked private literal).
type netDevDialer struct {
	mu     sync.Mutex
	target string
	dialed []string
}

func (d *netDevDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	target := d.target
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, target)
}

func (d *netDevDialer) setTarget(addr string) {
	d.mu.Lock()
	d.target = addr
	d.mu.Unlock()
}

func (d *netDevDialer) calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dialed)
}

// newNetDevService returns a service over the test env with the probe
// dial mapped through d and the log (the event sink) captured.
func newNetDevService(e *netDevTestEnv, d *netDevDialer) (*Service, *syncBuffer) {
	logs := &syncBuffer{}
	return &Service{db: e.db, vault: e.vault, log: slog.New(slog.NewJSONHandler(logs, nil)),
		transport: sshtransport.Config{DialContext: d.dial}}, logs
}

// netDevRevokes records revocations.
type netDevRevokes struct {
	mu   sync.Mutex
	ids  []string
	fail error
}

func (r *netDevRevokes) revoke(id, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	return r.fail
}

func (r *netDevRevokes) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ids)
}

func sshPinOf(k ssh.PublicKey) string {
	sum := sha256.Sum256(k.Marshal())
	return hex.EncodeToString(sum[:])
}

func certPinOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// TestProbeNetDeviceSSHSendsNoCredential: a CBS probe dials the checked
// private literal, returns the SHA-256 of the host key in wire format and
// never starts user authentication (not even "none").
func TestProbeNetDeviceSSHSendsNoCredential(t *testing.T) {
	e := newNetDevTestEnv(t)
	srv := startNetDevSSHServer(t)
	d := &netDevDialer{target: srv.addr}
	svc, _ := newNetDevService(e, d)
	got, err := svc.ProbeNetDevice(context.Background(), &pb.ProbeNetDeviceRequest{Family: "cbs", Endpoint: "10.20.0.2", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	srv.waitConns(t, 1)
	if got.GetObservedPin() != sshPinOf(srv.key) || got.GetPinKind() != "ssh-host-key" || got.GetEndpointIp() != "10.20.0.2" ||
		got.GetPort() != 22 || got.GetResolvedFrom() != "" || got.GetFacts().GetSshHostKeyType() != ssh.KeyAlgoED25519 {
		t.Fatalf("probe reply %v", got)
	}
	if a := srv.authAttempts(); len(a) != 0 {
		t.Fatalf("probe started user authentication: %v", a)
	}
	if c := d.calls(); !slices.Equal(c, []string{"10.20.0.2:22"}) {
		t.Fatalf("dialed %v, want the private literal only", c)
	}
	if ids := e.secretIDs(t); len(ids) != 0 {
		t.Fatalf("probe wrote vault entries %v", ids)
	}
}

// TestProbeNetDeviceTLSSendsNoCredential: a PAN-OS probe records the leaf
// and aborts the handshake; the server never completes a handshake and
// receives no application byte (no request, header or API key).
func TestProbeNetDeviceTLSSendsNoCredential(t *testing.T) {
	e := newNetDevTestEnv(t)
	srv := startNetDevTLSServer(t)
	d := &netDevDialer{target: srv.addr}
	svc, _ := newNetDevService(e, d)
	got, err := svc.ProbeNetDevice(context.Background(), &pb.ProbeNetDeviceRequest{Family: "panos", Endpoint: "10.20.0.1", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	srv.waitConns(t, 1)
	pin := certPinOf(srv.cert)
	f := got.GetFacts()
	if got.GetObservedPin() != pin || got.GetPinKind() != "tls-leaf" || got.GetEndpointIp() != "10.20.0.1" || got.GetPort() != 443 {
		t.Fatalf("probe reply %v", got)
	}
	if !strings.Contains(f.GetTlsSubject(), "fw.lab.test") || !slices.Equal(f.GetTlsDnsNames(), []string{"fw.lab.test"}) ||
		f.GetTlsNotAfterUnix() != srv.cert.NotAfter.Unix() || f.GetTlsCaFingerprint() != pin {
		t.Fatalf("probe facts %v", f)
	}
	srv.mu.Lock()
	completed, appBytes := srv.completed, srv.appBytes
	srv.mu.Unlock()
	if completed != 0 || appBytes != 0 {
		t.Fatalf("probe completed %d handshakes and sent %d application bytes, want none", completed, appBytes)
	}
	if c := d.calls(); !slices.Equal(c, []string{"10.20.0.1:443"}) {
		t.Fatalf("dialed %v", c)
	}
}

// TestProbeNetDeviceRefusesBeforeDial: a refused address class, a
// numeric shorthand, a bad family or port is refused with InvalidArgument
// before anything is dialled.
func TestProbeNetDeviceRefusesBeforeDial(t *testing.T) {
	e := newNetDevTestEnv(t)
	d := &netDevDialer{target: "127.0.0.1:1"}
	svc, _ := newNetDevService(e, d)
	cases := []*pb.ProbeNetDeviceRequest{
		{Family: "cbs", Endpoint: "127.0.0.1", Port: 22},
		{Family: "cbs", Endpoint: "8.8.8.8", Port: 22},
		{Family: "cbs", Endpoint: "169.254.1.1", Port: 22},
		{Family: "cbs", Endpoint: "fe80::1", Port: 22},
		{Family: "cbs", Endpoint: "::ffff:10.0.0.1", Port: 22},
		{Family: "cbs", Endpoint: "0.0.0.0", Port: 22},
		{Family: "cbs", Endpoint: "224.0.0.1", Port: 22},
		{Family: "cbs", Endpoint: "010.0.0.1", Port: 22},
		{Family: "cbs", Endpoint: "10.1", Port: 22},
		{Family: "cbs", Endpoint: "", Port: 22},
		{Family: "pfsense", Endpoint: "10.20.0.2", Port: 22},
		{Family: "cbs", Endpoint: "10.20.0.2", Port: 0},
		{Family: "cbs", Endpoint: "10.20.0.2", Port: 70000},
	}
	for _, in := range cases {
		got, err := svc.ProbeNetDevice(context.Background(), in)
		if status.Code(err) != codes.InvalidArgument || got != nil {
			t.Errorf("%v: reply %v error %v, want InvalidArgument", in, got, err)
		}
	}
	if c := d.calls(); len(c) != 0 {
		t.Fatalf("refused probes dialled %v", c)
	}
}

// TestNetDevProbeResolvesNameOnce: a host name is resolved exactly once;
// a public answer is refused before any dial; a private answer is probed
// at the literal and reported as resolved from the name.
func TestNetDevProbeResolvesNameOnce(t *testing.T) {
	e := newNetDevTestEnv(t)
	srv := startNetDevSSHServer(t)
	d := &netDevDialer{target: srv.addr}
	answer := "203.0.113.5"
	lookups := 0
	a := &NetDevAdmin{Store: e.store, Vault: e.vault, Dial: d.dial, Resolve: func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr(answer)}, nil
	}}
	ctx := context.Background()
	if _, err := a.Probe(ctx, netdevcontract.FamilyCBS, "SW.lab.test.", 22); !errors.Is(err, ErrNetDeviceAddress) {
		t.Fatalf("public answer: %v, want ErrNetDeviceAddress", err)
	}
	if lookups != 1 || len(d.calls()) != 0 {
		t.Fatalf("lookups %d dials %v", lookups, d.calls())
	}
	answer = "10.20.0.7"
	p, err := a.Probe(ctx, netdevcontract.FamilyCBS, "SW.lab.test.", 22)
	if err != nil {
		t.Fatal(err)
	}
	srv.waitConns(t, 1)
	if lookups != 2 || p.ResolvedFrom != "sw.lab.test" || p.Addr.String() != "10.20.0.7:22" || !slices.Equal(d.calls(), []string{"10.20.0.7:22"}) {
		t.Fatalf("lookups %d probe %+v dials %v", lookups, p, d.calls())
	}
	a.Resolve = nil
	if _, err := a.Probe(ctx, netdevcontract.FamilyCBS, "sw.lab.test", 22); !errors.Is(err, ErrNetDeviceResolve) {
		t.Fatalf("no resolver: %v", err)
	}
}

// TestRegisterNetDeviceRequiresTypedYes: anything but exactly "yes" is
// refused before any probe, vault write or registry row.
func TestRegisterNetDeviceRequiresTypedYes(t *testing.T) {
	e := newNetDevTestEnv(t)
	srv := startNetDevSSHServer(t)
	d := &netDevDialer{target: srv.addr}
	svc, _ := newNetDevService(e, d)
	for _, confirm := range []string{"", "y", "YES", "Yes", "yes ", " yes", "yes\n", "ja"} {
		got, err := svc.RegisterNetDevice(context.Background(), &pb.RegisterNetDeviceRequest{DeviceId: "core-sw", Family: "cbs", Label: "core",
			Endpoint: "10.20.0.2", Port: 22, PinKind: "ssh-host-key", ConfirmedPin: sshPinOf(srv.key), Confirm: confirm})
		if status.Code(err) != codes.InvalidArgument || got != nil {
			t.Errorf("confirm %q: reply %v error %v, want InvalidArgument", confirm, got, err)
		}
	}
	if c := d.calls(); len(c) != 0 {
		t.Fatalf("unconfirmed registration probed %v", c)
	}
	if _, ok, _ := e.db.GetNetDevice("core-sw"); ok {
		t.Fatal("unconfirmed registration stored a device")
	}
	if ids := e.secretIDs(t); len(ids) != 0 {
		t.Fatalf("unconfirmed registration wrote vault entries %v", ids)
	}
}

// TestRegisterNetDeviceRequiresPresentedPin: registration probes again
// and stores the device only if the endpoint presents exactly the
// confirmed pin; a mismatch (wrong pin, or the endpoint now presenting
// another key) stores nothing.
func TestRegisterNetDeviceRequiresPresentedPin(t *testing.T) {
	e := newNetDevTestEnv(t)
	srvA, srvB := startNetDevSSHServer(t), startNetDevSSHServer(t)
	d := &netDevDialer{target: srvA.addr}
	svc, _ := newNetDevService(e, d)
	ctx := context.Background()
	req := func(pin string) *pb.RegisterNetDeviceRequest {
		return &pb.RegisterNetDeviceRequest{DeviceId: "core-sw", Family: "cbs", Label: "core switch",
			Endpoint: "10.20.0.2", Port: 22, PinKind: "ssh-host-key", ConfirmedPin: pin, Confirm: "yes"}
	}
	if _, err := svc.RegisterNetDevice(ctx, req(testNetDevPin)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("wrong pin: %v, want FailedPrecondition", err)
	}
	srvA.waitConns(t, 1)
	probed, err := svc.ProbeNetDevice(ctx, &pb.ProbeNetDeviceRequest{Family: "cbs", Endpoint: "10.20.0.2", Port: 22})
	if err != nil {
		t.Fatal(err)
	}
	srvA.waitConns(t, 1)
	d.setTarget(srvB.addr) // the endpoint now presents another key
	if _, err := svc.RegisterNetDevice(ctx, req(probed.GetObservedPin())); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("key changed after the probe: %v, want FailedPrecondition", err)
	}
	srvB.waitConns(t, 1)
	if _, ok, _ := e.db.GetNetDevice("core-sw"); ok {
		t.Fatal("mismatched registration stored a device")
	}
	if ids := e.secretIDs(t); len(ids) != 0 {
		t.Fatalf("mismatched registration left vault entries %v", ids)
	}
	if _, err := svc.RegisterNetDevice(ctx, req("not-a-pin")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("malformed pin: %v", err)
	}

	d.setTarget(srvA.addr)
	got, err := svc.RegisterNetDevice(ctx, req(probed.GetObservedPin()))
	if err != nil {
		t.Fatal(err)
	}
	srvA.waitConns(t, 1)
	dev := got.GetDevice()
	if dev.GetDeviceId() != "core-sw" || dev.GetTrustPin() != sshPinOf(srvA.key) || dev.GetTrustGeneration() != 1 ||
		dev.GetEndpointIp() != "10.20.0.2" || dev.GetLabel() != "core switch" || dev.GetCredentialVersion() != 0 || dev.GetBlocked() {
		t.Fatalf("registered %v", dev)
	}
	for _, s := range []*netDevSSHServer{srvA, srvB} {
		if a := s.authAttempts(); len(a) != 0 {
			t.Fatalf("registration started user authentication: %v", a)
		}
	}
	if _, err := svc.RegisterNetDevice(ctx, req(probed.GetObservedPin())); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second registration: %v, want AlreadyExists", err)
	}

	// PAN-OS with the leaf pin from a TLS probe.
	tsrv := startNetDevTLSServer(t)
	d.setTarget(tsrv.addr)
	fw, err := svc.RegisterNetDevice(ctx, &pb.RegisterNetDeviceRequest{DeviceId: "edge-fw", Family: "panos", Label: "edge",
		Endpoint: "10.20.0.1", Port: 443, PinKind: "tls-leaf", ConfirmedPin: certPinOf(tsrv.cert), Confirm: "yes"})
	if err != nil {
		t.Fatal(err)
	}
	tsrv.waitConns(t, 1)
	if fw.GetDevice().GetTrustPin() != certPinOf(tsrv.cert) || fw.GetDevice().GetPinKind() != "tls-leaf" {
		t.Fatalf("registered firewall %v", fw.GetDevice())
	}
}

// registerTestNetDev registers id through the ND-10 registry directly.
func registerTestNetDev(t *testing.T, e *netDevTestEnv, id, ip, pin string) executordb.NetDevice {
	t.Helper()
	r := cbsReq(id, ip)
	r.Pin = pin
	d, err := e.reg.RegisterNetDevice(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func openNetDevCredential(t *testing.T, e *netDevTestEnv, d executordb.NetDevice) (string, string, int64) {
	t.Helper()
	v, version, err := e.vault.OpenVersion(netDevReadCredRef(d))
	if err != nil {
		t.Fatal(err)
	}
	user, secret, err := decodeNetDevCredential(netDevPurposeRead, v)
	if err != nil {
		t.Fatal(err)
	}
	return user, string(secret), version
}

// TestSetNetDeviceCredentialStoresReadCredential: the first read
// credential is stored as vault version 1 under the device-scoped read
// id, tagged as a read credential; it is never overwritten by a second
// set; malformed requests and unknown devices are refused.
func TestSetNetDeviceCredentialStoresReadCredential(t *testing.T) {
	e := newNetDevTestEnv(t)
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
	svc, _ := newNetDevService(e, &netDevDialer{})
	ctx := context.Background()
	secret := []byte("first-read-secret")
	got, err := svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: dev.ID, Username: "nos-read", Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("secret buffer not wiped")
	}
	if got.GetDevice().GetCredentialVersion() != 1 || got.GetDevice().GetTrustGeneration() != 1 {
		t.Fatalf("set reply %v", got.GetDevice())
	}
	if ref := netDevReadCredRef(dev); ref != "netdev-core-sw-rc" || ref == dev.DigestKeyRef || ref == dev.FingerprintKeyRef {
		t.Fatalf("read credential ref %q", ref)
	}
	user, val, version := openNetDevCredential(t, e, dev)
	if user != "nos-read" || val != "first-read-secret" || version != 1 {
		t.Fatalf("stored %q %q v%d", user, val, version)
	}
	// Read/change separation: the stored value is a read credential only.
	raw, err := e.vault.Open(netDevReadCredRef(dev))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeNetDevCredential('c', raw); !errors.Is(err, ErrNetDevCredentialFormat) {
		t.Fatalf("read credential opened as another purpose: %v", err)
	}
	list, err := svc.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if l := list.GetDevices()[0]; l.GetCredentialVersion() != 1 || l.GetCredentialMissing() {
		t.Fatalf("list after set %v", l)
	}

	again := []byte("second-read-secret")
	if _, err := svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: dev.ID, Secret: again}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second set: %v, want AlreadyExists", err)
	}
	if !bytes.Equal(again, make([]byte, len(again))) {
		t.Fatal("refused secret buffer not wiped")
	}
	if _, val, version := openNetDevCredential(t, e, dev); val != "first-read-secret" || version != 1 {
		t.Fatalf("second set changed the credential: %q v%d", val, version)
	}

	for name, in := range map[string]*pb.SetNetDeviceCredentialRequest{
		"empty secret":    {DeviceId: dev.ID},
		"huge secret":     {DeviceId: dev.ID, Secret: make([]byte, maxNetDevSecretBytes+1)},
		"control in user": {DeviceId: dev.ID, Username: "nos\nread", Secret: []byte("x")},
		"long user":       {DeviceId: dev.ID, Username: strings.Repeat("u", maxNetDevUsernameBytes+1), Secret: []byte("x")},
	} {
		if _, err := svc.SetNetDeviceCredential(ctx, in); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: "no-such-sw", Secret: []byte("x")}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown device: %v, want NotFound", err)
	}
}

// TestRotateNetDeviceCredentialRevokesAuthority: rotation replaces exactly
// the expected version, bumps the credential version and revokes the
// device's grants; a stale or missing version changes nothing and revokes
// nothing; a failed revocation blocks the device.
func TestRotateNetDeviceCredentialRevokesAuthority(t *testing.T) {
	e := newNetDevTestEnv(t)
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
	rev := &netDevRevokes{}
	a := &NetDevAdmin{Store: e.store, Vault: e.vault, Revoke: rev.revoke}
	ctx := context.Background()
	if _, _, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("x"), ExpectedVersion: 1}); !errors.Is(err, ErrNetDevCredentialVersion) {
		t.Fatalf("rotate without credential: %v", err)
	}
	if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Username: "nos-read", Secret: []byte("v1-secret")}); err != nil {
		t.Fatal(err)
	}
	if rev.count() != 0 {
		t.Fatal("first set revoked authority")
	}
	if _, _, err := a.RotateCredential(ctx, NetDevCredential{DeviceID: dev.ID, Secret: []byte("v2-secret"), ExpectedVersion: 1}); !errors.Is(err, ErrNetDevCredentialRequest) {
		t.Fatalf("rotation without actor: %v", err)
	}
	for _, expected := range []int64{0, 2, -1} {
		if _, _, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v2-secret"), ExpectedVersion: expected}); err == nil {
			t.Fatalf("expected version %d accepted", expected)
		}
	}
	if _, val, v := openNetDevCredential(t, e, dev); val != "v1-secret" || v != 1 || rev.count() != 0 {
		t.Fatalf("refused rotation changed state: %q v%d revokes %d", val, v, rev.count())
	}
	_, v, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Username: "nos-read2", Secret: []byte("v2-secret"), ExpectedVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if user, val, sv := openNetDevCredential(t, e, dev); v != 2 || sv != 2 || val != "v2-secret" || user != "nos-read2" {
		t.Fatalf("rotated to %q %q v%d (reply v%d)", user, val, sv, v)
	}
	if !slices.Equal(rev.ids, []string{dev.ID}) {
		t.Fatalf("revocations %v, want one for %s", rev.ids, dev.ID)
	}

	rev.fail = errors.New("grant store down")
	if _, _, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v3-secret"), ExpectedVersion: 2}); !errors.Is(err, ErrNetDevRevoke) {
		t.Fatalf("failed revocation: %v, want ErrNetDevRevoke", err)
	}
	if cur, _, _ := e.db.GetNetDevice(dev.ID); !cur.Blocked {
		t.Fatal("device not blocked after a failed revocation")
	}
}

// TestNetDevCredentialVaultFailureRollsBack: a vault write failure leaves
// the previous credential and version untouched and revokes nothing; a
// locked vault refuses every credential, register and remove operation
// before any side effect.
func TestNetDevCredentialVaultFailureRollsBack(t *testing.T) {
	e := newNetDevTestEnv(t)
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
	rev := &netDevRevokes{}
	a := &NetDevAdmin{Store: e.store, Vault: e.vault, Revoke: rev.revoke}
	ctx := context.Background()

	e.store.failPutAfter = e.store.puts
	if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v1-secret")}); err == nil {
		t.Fatal("set succeeded with a failing vault")
	}
	if v, err := a.credentialVersion(netDevReadCredRef(dev)); err != nil || v != 0 {
		t.Fatalf("failed set left version %d (%v)", v, err)
	}
	e.store.failPutAfter = -1
	if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v1-secret")}); err != nil {
		t.Fatal(err)
	}
	e.store.failPutAfter = e.store.puts
	if _, _, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v2-secret"), ExpectedVersion: 1}); err == nil {
		t.Fatal("rotate succeeded with a failing vault")
	}
	e.store.failPutAfter = -1
	if _, val, v := openNetDevCredential(t, e, dev); val != "v1-secret" || v != 1 || rev.count() != 0 {
		t.Fatalf("failed rotation changed state: %q v%d revokes %d", val, v, rev.count())
	}

	e.vault.Lock()
	t.Cleanup(func() { _ = e.vault.Unlock([]byte(netDevTestVaultPass)) })
	if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("x")}); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("locked set: %v", err)
	}
	if _, _, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("x"), ExpectedVersion: 1}); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("locked rotate: %v", err)
	}
	if _, err := a.Remove(ctx, dev.ID, "yes"); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("locked remove: %v", err)
	}
	if _, err := a.Register(ctx, NetDevRegister{DeviceID: "sw2", Family: netdevcontract.FamilyCBS, Label: "x", Endpoint: "10.20.0.3", Port: 22,
		PinKind: netdevcontract.PinSSHHostKey, ConfirmedPin: testNetDevPin2, Confirm: "yes"}); !errors.Is(err, vault.ErrLocked) {
		t.Fatalf("locked register: %v", err)
	}
	if cur, _, _ := e.db.GetNetDevice(dev.ID); cur.Blocked || cur.TombstonedAt != nil || rev.count() != 0 {
		t.Fatalf("locked remove had side effects: %+v revokes %d", cur, rev.count())
	}
	svc, _ := newNetDevService(e, &netDevDialer{})
	if _, err := svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: dev.ID, Secret: []byte("x")}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("locked set RPC: %v, want FailedPrecondition", err)
	}
}

// TestBlockUnblockNetDevice: block needs a printable reason and revokes
// grants; unblock needs the typed "yes"; neither event carries the
// reason.
func TestBlockUnblockNetDevice(t *testing.T) {
	e := newNetDevTestEnv(t)
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
	svc, logs := newNetDevService(e, &netDevDialer{})
	ctx := context.Background()
	for _, reason := range []string{"", "bad\nreason", strings.Repeat("r", maxNetDevBlockReason+1)} {
		if _, err := svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: dev.ID, Reason: reason}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("reason %q: %v, want InvalidArgument", reason, err)
		}
	}
	const reason = "maintenance window seven"
	got, err := svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: dev.ID, Reason: reason})
	if err != nil {
		t.Fatal(err)
	}
	if !got.GetDevice().GetBlocked() || got.GetDevice().GetBlockReason() != reason {
		t.Fatalf("block reply %v", got.GetDevice())
	}
	if cur, _, _ := e.db.GetNetDevice(dev.ID); func() error { _, err := DialAddr(cur); return err }() == nil {
		t.Fatal("blocked device still dialable")
	}
	// A second block is the revocation retry: it keeps the block and its
	// first reason (TestNetDevFailedRevocationKeepsDeviceBlocked covers
	// the retried revocation).
	again, err := svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: dev.ID, Reason: "another reason"})
	if err != nil || !again.GetDevice().GetBlocked() || again.GetDevice().GetBlockReason() != reason {
		t.Fatalf("second block: %v %v, want still blocked with the first reason", again.GetDevice(), err)
	}
	for _, confirm := range []string{"", "no", "YES"} {
		if _, err := svc.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: dev.ID, Confirm: confirm}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("unblock confirm %q: %v", confirm, err)
		}
	}
	if cur, _, _ := e.db.GetNetDevice(dev.ID); !cur.Blocked {
		t.Fatal("unconfirmed unblock lifted the block")
	}
	un, err := svc.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: dev.ID, Confirm: "yes"})
	if err != nil || un.GetDevice().GetBlocked() {
		t.Fatalf("unblock: %v %v", un, err)
	}
	if _, err := svc.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: dev.ID, Confirm: "yes"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unblock of an unblocked device: %v, want FailedPrecondition", err)
	}
	if strings.Contains(logs.String(), reason) {
		t.Fatal("event or log carries the block reason")
	}
	for _, action := range []string{`"action":"blocked"`, `"action":"unblocked"`} {
		if !strings.Contains(logs.String(), action) {
			t.Errorf("no %s event", action)
		}
	}
	if _, err := svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: "no-such", Reason: reason}); status.Code(err) != codes.NotFound {
		t.Fatalf("block unknown: %v", err)
	}
}

// TestRemoveNetDevice: remove needs "yes"; it blocks, revokes, deletes the
// device's vault entries and tombstones the id. A failed vault deletion
// stops with the device blocked and live, and a retry completes.
func TestRemoveNetDevice(t *testing.T) {
	e := newNetDevTestEnv(t)
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
	other := registerTestNetDev(t, e, "acc-sw", "10.20.0.3", testNetDevPin2)
	rev := &netDevRevokes{}
	a := &NetDevAdmin{Store: e.store, Vault: e.vault, Revoke: rev.revoke}
	ctx := context.Background()
	if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("read-secret")}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Remove(ctx, dev.ID, "no"); !errors.Is(err, ErrNetDevConfirm) {
		t.Fatalf("unconfirmed remove: %v", err)
	}
	e.store.failDelete = true
	if _, err := a.Remove(ctx, dev.ID, "yes"); err == nil {
		t.Fatal("remove succeeded with a failing vault delete")
	}
	cur, _, _ := e.db.GetNetDevice(dev.ID)
	if !cur.Blocked || cur.TombstonedAt != nil {
		t.Fatalf("after failed delete: %+v, want blocked and live", cur)
	}
	e.store.failDelete = false
	got, err := a.Remove(ctx, dev.ID, "yes")
	if err != nil {
		t.Fatal(err)
	}
	if got.TombstonedAt == nil {
		t.Fatal("removed device not tombstoned")
	}
	for _, id := range e.secretIDs(t) {
		if strings.HasPrefix(id, "netdev-core-sw-") {
			t.Errorf("vault entry %s survived removal", id)
		}
	}
	if !slices.Contains(e.secretIDs(t), other.DigestKeyRef) {
		t.Fatal("removal deleted another device's key")
	}
	if rev.count() < 1 || rev.ids[len(rev.ids)-1] != dev.ID {
		t.Fatalf("revocations %v", rev.ids)
	}
	if _, err := a.Remove(ctx, dev.ID, "yes"); !errors.Is(err, executordb.ErrNetDeviceTombstoned) {
		t.Fatalf("second remove: %v", err)
	}
	if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("x")}); !errors.Is(err, executordb.ErrNetDeviceTombstoned) {
		t.Fatalf("set on removed device: %v", err)
	}
	svc, _ := newNetDevService(e, &netDevDialer{})
	if _, err := svc.RemoveNetDevice(ctx, &pb.RemoveNetDeviceRequest{DeviceId: other.ID}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("remove RPC without confirm: %v", err)
	}
	list, err := svc.ListNetDevices(ctx, &pb.ListNetDevicesRequest{})
	if err != nil || len(list.GetDevices()) != 1 || list.GetDevices()[0].GetDeviceId() != other.ID {
		t.Fatalf("list after remove %v %v", list, err)
	}
}

// TestNetDevRepinBumpsGenerationAndRevokes: a re-pin needs an authorized
// permit for exactly the current binding; it bumps the trust generation,
// keeps a block and revokes the device's grants.
func TestNetDevRepinBumpsGenerationAndRevokes(t *testing.T) {
	e := newNetDevTestEnv(t)
	srvA, srvB := startNetDevSSHServer(t), startNetDevSSHServer(t)
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", sshPinOf(srvA.key))
	d := &netDevDialer{target: srvB.addr}
	rev := &netDevRevokes{}
	var authorized []NetDevRepinBinding
	deny := errors.New("no permit")
	allow := false
	a := &NetDevAdmin{Store: e.store, Vault: e.vault, Dial: d.dial, Revoke: rev.revoke,
		AuthorizeRepin: func(_ context.Context, b NetDevRepinBinding, _ string) error {
			authorized = append(authorized, b)
			if !allow {
				return deny
			}
			return nil
		}}
	ctx := context.Background()
	if _, err := e.db.BlockNetDevice(dev.ID, "pin mismatch"); err != nil {
		t.Fatal(err)
	}
	oldPin, newPin := sshPinOf(srvA.key), sshPinOf(srvB.key)
	if _, err := a.Repin(ctx, dev.ID, oldPin, newPin, "digest"); !errors.Is(err, ErrNetDevRepinApproval) {
		t.Fatalf("unapproved re-pin: %v", err)
	}
	srvB.waitConns(t, 1)
	if cur, _, _ := e.db.GetNetDevice(dev.ID); cur.TrustGeneration != 1 || rev.count() != 0 {
		t.Fatalf("unapproved re-pin changed state: %+v revokes %d", cur, rev.count())
	}
	if _, err := a.Repin(ctx, dev.ID, testNetDevPin, newPin, "digest"); !errors.Is(err, ErrNetDevPinMismatch) {
		t.Fatalf("wrong old pin: %v", err)
	}
	if _, err := a.Repin(ctx, dev.ID, oldPin, testNetDevPin2, "digest"); !errors.Is(err, ErrNetDevPinMismatch) {
		t.Fatalf("new pin not presented: %v", err)
	}
	srvB.waitConns(t, 1)
	allow = true
	got, err := a.Repin(ctx, dev.ID, oldPin, newPin, "digest")
	if err != nil {
		t.Fatal(err)
	}
	srvB.waitConns(t, 1)
	if got.TrustGeneration != 2 || got.PinValue != newPin || !got.Blocked {
		t.Fatalf("re-pinned %+v, want generation 2, new pin, still blocked", got)
	}
	b := authorized[len(authorized)-1]
	if b.DeviceID != dev.ID || b.OldPin != oldPin || b.NewPin != newPin || b.TrustGeneration != 1 || b.EndpointIP != "10.20.0.2" {
		t.Fatalf("authorized binding %+v", b)
	}
	if !slices.Equal(rev.ids, []string{dev.ID}) {
		t.Fatalf("revocations %v", rev.ids)
	}
	if a := srvB.authAttempts(); len(a) != 0 {
		t.Fatalf("re-pin probe started user authentication: %v", a)
	}
}

// TestNetDevRepinRequiresExactSingleUseHighApproval runs the RPC pair
// against the real permit authority: no commit without an approved HIGH
// permit; a changed binding (device, pins, generation, credential
// version, endpoint) is refused; the approval is single use.
func TestNetDevRepinRequiresExactSingleUseHighApproval(t *testing.T) {
	e := newNetDevTestEnv(t)
	approval := newReconcileEnv(t)
	svc := approval.svc
	svc.db, svc.vault = e.db, e.vault
	srvA, srvB := startNetDevSSHServer(t), startNetDevSSHServer(t)
	d := &netDevDialer{target: srvB.addr}
	svc.transport = sshtransport.Config{DialContext: d.dial}
	dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", sshPinOf(srvA.key))
	ctx := context.Background()
	if _, err := svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: dev.ID, Secret: []byte("read-secret")}); err != nil {
		t.Fatal(err)
	}
	oldPin, newPin := sshPinOf(srvA.key), sshPinOf(srvB.key)
	request := &pb.CommitNetDeviceRepinRequest{DeviceId: dev.ID, OldPin: oldPin, ConfirmedNewPin: newPin}
	if _, err := svc.CommitNetDeviceRepin(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("approval bypass: %v", err)
	}
	if _, err := svc.ProposeNetDeviceRepin(ctx, &pb.ProposeNetDeviceRepinRequest{DeviceId: dev.ID, OldPin: testNetDevPin, ConfirmedNewPin: newPin}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("wrong old pin proposal: %v", err)
	}
	proposed, err := svc.ProposeNetDeviceRepin(ctx, &pb.ProposeNetDeviceRepinRequest{DeviceId: dev.ID, OldPin: oldPin, ConfirmedNewPin: newPin})
	if err != nil {
		t.Fatal(err)
	}
	proposal := proposed.GetPermit()
	if proposal.RiskClass != pb.RiskClass_RISK_CLASS_HIGH || proposal.ApprovalRequirement != pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED {
		t.Fatalf("re-pin approval is not HIGH with UV: %v", proposal)
	}
	request.ExecutionDigest = proposal.ExecutionDigest
	if _, err := svc.CommitNetDeviceRepin(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pending permit accepted: %v", err)
	}
	dg, err := canonical.ParseDigest(proposal.ExecutionDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.auth.ApproveCLI(dg, 0, "personal-admin"); err != nil {
		t.Fatal(err)
	}
	b, err := svc.netDevAdmin().RepinBinding(ctx, dev.ID, oldPin, newPin)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*NetDevRepinBinding){
		"device":     func(b *NetDevRepinBinding) { b.DeviceID = "other-sw" },
		"old pin":    func(b *NetDevRepinBinding) { b.OldPin = testNetDevPin },
		"new pin":    func(b *NetDevRepinBinding) { b.NewPin = testNetDevPin2 },
		"generation": func(b *NetDevRepinBinding) { b.TrustGeneration++ },
		"credential": func(b *NetDevRepinBinding) { b.CredentialVersion++ },
		"endpoint":   func(b *NetDevRepinBinding) { b.EndpointIP = "10.20.0.99" },
	} {
		c := b
		change(&c)
		if err := svc.authorizeNetDevRepin(ctx, c, proposal.ExecutionDigest); err == nil {
			t.Errorf("%s: approval accepted a changed binding", name)
		}
	}
	result, err := svc.CommitNetDeviceRepin(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.GetDevice().GetTrustPin() != newPin || result.GetDevice().GetTrustGeneration() != 2 || result.GetDevice().GetCredentialVersion() != 1 {
		t.Fatalf("re-pin result %v", result.GetDevice())
	}
	if _, err := svc.CommitNetDeviceRepin(ctx, request); err == nil {
		t.Fatal("approval replay accepted")
	}
	for _, s := range []*netDevSSHServer{srvA, srvB} {
		if a := s.authAttempts(); len(a) != 0 {
			t.Fatalf("re-pin started user authentication: %v", a)
		}
	}
}

// TestNetDevSecretNeverInReplyLogOrEvent runs the whole lifecycle through
// the RPC handlers with the logger (the executor's event sink) captured:
// no reply, error, log line or event carries a secret, a user name or a
// vault reference, and every lifecycle event carries action and device
// only.
func TestNetDevSecretNeverInReplyLogOrEvent(t *testing.T) {
	e := newNetDevTestEnv(t)
	srv := startNetDevSSHServer(t)
	d := &netDevDialer{target: srv.addr}
	svc, logs := newNetDevService(e, d)
	ctx := context.Background()
	const (
		secret1 = "S3cret-One-pa55word"
		secret2 = "S3cret-Two-api-key-0123"
		user    = "nos-read-account"
	)
	var outputs []string
	record := func(m proto.Message, err error) {
		if m != nil && !isNilMessage(m) {
			outputs = append(outputs, prototext.Format(m))
		}
		if err != nil {
			outputs = append(outputs, err.Error())
		}
	}
	record(svc.ProbeNetDevice(ctx, &pb.ProbeNetDeviceRequest{Family: "cbs", Endpoint: "10.20.0.2", Port: 22}))
	record(svc.RegisterNetDevice(ctx, &pb.RegisterNetDeviceRequest{DeviceId: "core-sw", Family: "cbs", Label: "core", Endpoint: "10.20.0.2",
		Port: 22, PinKind: "ssh-host-key", ConfirmedPin: sshPinOf(srv.key), Confirm: "yes"}))
	record(svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: "core-sw", Username: user, Secret: []byte(secret1)}))
	record(svc.SetNetDeviceCredential(ctx, &pb.SetNetDeviceCredentialRequest{DeviceId: "core-sw", Username: user, Secret: []byte(secret2)}))
	record(svc.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: "core-sw", ExpectedCredentialVersion: 5, Username: user, Secret: []byte(secret2)}))
	record(svc.RotateNetDeviceCredential(ctx, &pb.RotateNetDeviceCredentialRequest{DeviceId: "core-sw", ExpectedCredentialVersion: 1, Username: user, Secret: []byte(secret2)}))
	record(svc.ListNetDevices(ctx, &pb.ListNetDevicesRequest{}))
	record(svc.BlockNetDevice(ctx, &pb.BlockNetDeviceRequest{DeviceId: "core-sw", Reason: "test"}))
	record(svc.UnblockNetDevice(ctx, &pb.UnblockNetDeviceRequest{DeviceId: "core-sw", Confirm: "yes"}))
	e.store.failDelete = true
	record(svc.RemoveNetDevice(ctx, &pb.RemoveNetDeviceRequest{DeviceId: "core-sw", Confirm: "yes"}))
	e.store.failDelete = false
	record(svc.RemoveNetDevice(ctx, &pb.RemoveNetDeviceRequest{DeviceId: "core-sw", Confirm: "yes"}))
	// An internal error whose text names a vault reference is logged masked.
	record(nil, svc.netDevRPCError("test", fmt.Errorf("store network device key netdev-core-sw-dk: %w", errors.New("boom"))))
	srv.waitConns(t, 2)

	all := strings.Join(outputs, "\n") + "\n" + logs.String()
	for _, s := range []string{secret1, secret2, user, "netdev-"} {
		if strings.Contains(all, s) {
			t.Errorf("reply, error or log carries %q", s)
		}
	}
	if !strings.Contains(logs.String(), "<vault-ref>") {
		t.Error("internal error was not logged")
	}
	actions := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["kind"] != "netdev_admin" {
			continue
		}
		keys := slices.Sorted(maps.Keys(rec))
		if !slices.Equal(keys, []string{"action", "device", "kind", "level", "msg", "time"}) {
			t.Errorf("event %v carries more than action and device", rec)
		}
		actions[rec["action"].(string)] = true
	}
	for _, want := range []string{"registered", "credential_set", "credential_rotated", "blocked", "unblocked", "removed"} {
		if !actions[want] {
			t.Errorf("no %q event (have %v)", want, actions)
		}
	}
	if a := srv.authAttempts(); len(a) != 0 {
		t.Fatalf("lifecycle started user authentication: %v", a)
	}
}

// TestNetDevCredentialEnvelope: the vault value round-trips and malformed
// or foreign-purpose values are refused.
func TestNetDevCredentialEnvelope(t *testing.T) {
	v := encodeNetDevCredential(netDevPurposeRead, "nos-read", []byte("pw"))
	u, s, err := decodeNetDevCredential(netDevPurposeRead, v)
	if err != nil || u != "nos-read" || string(s) != "pw" {
		t.Fatalf("round trip %q %q %v", u, s, err)
	}
	for name, bad := range map[string][]byte{
		"empty":       nil,
		"magic":       append([]byte("xxx1r"), v[5:]...),
		"purpose":     encodeNetDevCredential('c', "nos-read", []byte("pw")),
		"no secret":   encodeNetDevCredential(netDevPurposeRead, "nos-read", nil),
		"short user":  v[:len(netDevCredMagic)+4],
		"user length": append(append([]byte(netDevCredMagic), netDevPurposeRead, 0xff, 0xff), []byte("x")...),
	} {
		if _, _, err := decodeNetDevCredential(netDevPurposeRead, bad); !errors.Is(err, ErrNetDevCredentialFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// requireUnblockRefused checks that Unblock retries the revocation, is
// refused with ErrNetDevRevoke while it fails, and leaves the device
// blocked with reason.
func requireUnblockRefused(t *testing.T, e *netDevTestEnv, a *NetDevAdmin, rev *netDevRevokes, id, reason string) {
	t.Helper()
	before := rev.count()
	if _, err := a.Unblock(context.Background(), id, "yes"); !errors.Is(err, ErrNetDevRevoke) {
		t.Fatalf("unblock with a pending revocation: %v, want ErrNetDevRevoke", err)
	}
	if rev.count() != before+1 {
		t.Fatal("unblock did not retry the revocation")
	}
	if cur, _, _ := e.db.GetNetDevice(id); !cur.Blocked || cur.BlockReason != reason {
		t.Fatalf("after refused unblock: blocked %v reason %q, want blocked with %q", cur.Blocked, cur.BlockReason, reason)
	}
}

// setFail switches the injected revocation failure.
func (r *netDevRevokes) setFail(err error) {
	r.mu.Lock()
	r.fail = err
	r.mu.Unlock()
}

// TestNetDevFailedRevocationKeepsDeviceBlocked: a failed revocation on
// Block, Repin or a rotation of an already-blocked device leaves the
// device blocked; Unblock retries the revocation and is refused (the
// block stays) while it fails; Block on the blocked device retries the
// revocation, and once a revocation succeeded Unblock lifts the block.
func TestNetDevFailedRevocationKeepsDeviceBlocked(t *testing.T) {
	ctx := context.Background()
	down := errors.New("grant store down")

	t.Run("block", func(t *testing.T) {
		e := newNetDevTestEnv(t)
		dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
		rev := &netDevRevokes{fail: down}
		a := &NetDevAdmin{Store: e.store, Vault: e.vault, Revoke: rev.revoke}
		if _, err := a.Block(ctx, dev.ID, "maintenance"); !errors.Is(err, ErrNetDevRevoke) {
			t.Fatalf("block with failing revocation: %v, want ErrNetDevRevoke", err)
		}
		requireUnblockRefused(t, e, a, rev, dev.ID, "maintenance")
		if _, err := a.Block(ctx, dev.ID, "retry"); !errors.Is(err, ErrNetDevRevoke) {
			t.Fatalf("block retry with failing revocation: %v, want ErrNetDevRevoke", err)
		}
		requireUnblockRefused(t, e, a, rev, dev.ID, "maintenance")

		rev.setFail(nil)
		n := rev.count()
		got, err := a.Block(ctx, dev.ID, "retry")
		if err != nil || !got.Blocked || got.BlockReason != "maintenance" || rev.count() != n+1 {
			t.Fatalf("block retry: %+v %v revokes %d, want blocked, first reason, one more revocation", got, err, rev.count()-n)
		}
		un, err := a.Unblock(ctx, dev.ID, "yes")
		if err != nil || un.Blocked {
			t.Fatalf("unblock after successful retry: %+v %v", un, err)
		}
	})

	t.Run("repin", func(t *testing.T) {
		e := newNetDevTestEnv(t)
		srvA, srvB := startNetDevSSHServer(t), startNetDevSSHServer(t)
		dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", sshPinOf(srvA.key))
		d := &netDevDialer{target: srvB.addr}
		rev := &netDevRevokes{fail: down}
		a := &NetDevAdmin{Store: e.store, Vault: e.vault, Dial: d.dial, Revoke: rev.revoke,
			AuthorizeRepin: func(context.Context, NetDevRepinBinding, string) error { return nil }}
		newPin := sshPinOf(srvB.key)
		if _, err := a.Repin(ctx, dev.ID, sshPinOf(srvA.key), newPin, "digest"); !errors.Is(err, ErrNetDevRevoke) {
			t.Fatalf("re-pin with failing revocation: %v, want ErrNetDevRevoke", err)
		}
		srvB.waitConns(t, 1)
		cur, _, _ := e.db.GetNetDevice(dev.ID)
		if !cur.Blocked || cur.BlockReason != netDevRevokePendingReason || cur.PinValue != newPin || cur.TrustGeneration != 2 {
			t.Fatalf("after re-pin with failed revocation: %+v, want re-pinned and blocked as revocation pending", cur)
		}
		requireUnblockRefused(t, e, a, rev, dev.ID, netDevRevokePendingReason)

		rev.setFail(nil)
		n := rev.count()
		if got, err := a.Block(ctx, dev.ID, "retry"); err != nil || !got.Blocked || rev.count() != n+1 {
			t.Fatalf("block retry: %+v %v", got, err)
		}
		if un, err := a.Unblock(ctx, dev.ID, "yes"); err != nil || un.Blocked {
			t.Fatalf("unblock after successful retry: %+v %v", un, err)
		}
	})

	t.Run("rotation of a blocked device", func(t *testing.T) {
		e := newNetDevTestEnv(t)
		dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", testNetDevPin)
		rev := &netDevRevokes{}
		a := &NetDevAdmin{Store: e.store, Vault: e.vault, Revoke: rev.revoke}
		if _, _, err := a.SetCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v1-secret")}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.db.BlockNetDevice(dev.ID, "pin mismatch"); err != nil {
			t.Fatal(err)
		}
		rev.setFail(down)
		if _, _, err := a.RotateCredential(ctx, NetDevCredential{By: "admin", DeviceID: dev.ID, Secret: []byte("v2-secret"), ExpectedVersion: 1}); !errors.Is(err, ErrNetDevRevoke) {
			t.Fatalf("rotation with failing revocation: %v, want ErrNetDevRevoke", err)
		}
		// The earlier reason stays; the block itself is the pending state.
		requireUnblockRefused(t, e, a, rev, dev.ID, "pin mismatch")
		rev.setFail(nil)
		n := rev.count()
		if un, err := a.Unblock(ctx, dev.ID, "yes"); err != nil || un.Blocked || rev.count() != n+1 {
			t.Fatalf("unblock once revocation works: %+v %v revokes %d", un, err, rev.count()-n)
		}
	})

	t.Run("rpc", func(t *testing.T) {
		svc, logs := newNetDevService(newNetDevTestEnv(t), &netDevDialer{})
		err := svc.netDevRPCError("unblock", fmt.Errorf("%w: %w", ErrNetDevRevoke, errors.Join(down, executordb.ErrNetDeviceState)))
		if status.Code(err) != codes.Internal || !strings.Contains(status.Convert(err).Message(), "the device is blocked") {
			t.Fatalf("revocation failure maps to %v", err)
		}
		if !strings.Contains(logs.String(), "unblock failed") {
			t.Fatal("revocation failure not logged")
		}
	})
}

// netDevBumpRaceStore runs race right before the store's trust bump.
type netDevBumpRaceStore struct {
	*netDevFaultStore
	race func(id string)
}

func (s *netDevBumpRaceStore) BumpTrustGeneration(id, newPin string) (executordb.NetDevice, error) {
	if s.race != nil {
		s.race(id)
	}
	return s.netDevFaultStore.BumpTrustGeneration(id, newPin)
}

// TestNetDevRepinConcurrentTrustChangeFailsClosed: the commit compares the
// stored trust state with the permit-bound generation and old pin right
// before the bump (a change is refused without a bump), and a bump that
// does not land exactly one generation after the bound one (another
// writer bumped in between) blocks the device and revokes its authority.
func TestNetDevRepinConcurrentTrustChangeFailsClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("change before the bump", func(t *testing.T) {
		e := newNetDevTestEnv(t)
		srvA, srvB := startNetDevSSHServer(t), startNetDevSSHServer(t)
		dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", sshPinOf(srvA.key))
		d := &netDevDialer{target: srvB.addr}
		rev := &netDevRevokes{}
		a := &NetDevAdmin{Store: e.store, Vault: e.vault, Dial: d.dial, Revoke: rev.revoke,
			AuthorizeRepin: func(context.Context, NetDevRepinBinding, string) error {
				_, err := e.db.BumpTrustGeneration(dev.ID, testNetDevPin2)
				return err
			}}
		if _, err := a.Repin(ctx, dev.ID, sshPinOf(srvA.key), sshPinOf(srvB.key), "digest"); !errors.Is(err, ErrNetDevConcurrentChange) {
			t.Fatalf("re-pin over a concurrent change: %v, want ErrNetDevConcurrentChange", err)
		}
		srvB.waitConns(t, 1)
		if cur, _, _ := e.db.GetNetDevice(dev.ID); cur.PinValue != testNetDevPin2 || cur.TrustGeneration != 2 || rev.count() != 0 {
			t.Fatalf("refused re-pin changed state: %+v revokes %d", cur, rev.count())
		}
	})

	t.Run("change during the bump", func(t *testing.T) {
		e := newNetDevTestEnv(t)
		srvA, srvB := startNetDevSSHServer(t), startNetDevSSHServer(t)
		dev := registerTestNetDev(t, e, "core-sw", "10.20.0.2", sshPinOf(srvA.key))
		d := &netDevDialer{target: srvB.addr}
		rev := &netDevRevokes{}
		store := &netDevBumpRaceStore{netDevFaultStore: e.store, race: func(id string) {
			if _, err := e.db.BumpTrustGeneration(id, testNetDevPin2); err != nil {
				t.Errorf("concurrent bump: %v", err)
			}
		}}
		a := &NetDevAdmin{Store: store, Vault: e.vault, Dial: d.dial, Revoke: rev.revoke,
			AuthorizeRepin: func(context.Context, NetDevRepinBinding, string) error { return nil }}
		_, err := a.Repin(ctx, dev.ID, sshPinOf(srvA.key), sshPinOf(srvB.key), "digest")
		if !errors.Is(err, ErrNetDevConcurrentChange) {
			t.Fatalf("re-pin racing a bump: %v, want ErrNetDevConcurrentChange", err)
		}
		srvB.waitConns(t, 1)
		cur, _, _ := e.db.GetNetDevice(dev.ID)
		if !cur.Blocked || cur.TrustGeneration != 3 || !slices.Equal(rev.ids, []string{dev.ID}) {
			t.Fatalf("raced re-pin: %+v revocations %v, want blocked and revoked", cur, rev.ids)
		}
		svc, _ := newNetDevService(e, d)
		if c := status.Code(svc.netDevRPCError("commit re-pin", err)); c != codes.Aborted {
			t.Fatalf("raced re-pin maps to %v, want Aborted", c)
		}
	})
}

// TestNetDevListFailedMasksVaultRefs: a list failure is logged with the
// same vault reference masking as every other lifecycle failure.
func TestNetDevListFailedMasksVaultRefs(t *testing.T) {
	svc, logs := newNetDevService(newNetDevTestEnv(t), &netDevDialer{})
	err := svc.netDevListFailed(fmt.Errorf("credential versions: read netdev-core-sw-rc: %w", errors.New("disk I/O error")))
	if status.Code(err) != codes.Internal || status.Convert(err).Message() != netDevRPCFailed {
		t.Fatalf("list failure maps to %v", err)
	}
	out := logs.String()
	if strings.Contains(out, "netdev-core-sw") || !strings.Contains(out, "<vault-ref>") || !strings.Contains(out, "disk I/O error") {
		t.Fatalf("list failure log not masked: %s", out)
	}
}

// netDevTestCert creates a certificate for cn, signed by parent (self-signed
// if parent is nil) with signer (its own key if signer is nil).
func netDevTestCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, signer *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = nil
	}
	if parent == nil {
		parent = tmpl
	}
	if signer == nil {
		signer = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

// serveNetDevTLSChain serves chain with the leaf key on loopback and
// returns the address.
func serveNetDevTLSChain(t *testing.T, key *ecdsa.PrivateKey, chain ...*x509.Certificate) string {
	t.Helper()
	var raw [][]byte
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: raw, PrivateKey: key}}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_ = tls.Server(c, cfg).Handshake()
			}()
		}
	}()
	return ln.Addr().String()
}

// TestNetDevProbeCAPinAnchorsLeaf: the CA pin offered by a probe is the
// self-signed certificate that actually signs the chain down to the leaf;
// an unrelated self-signed certificate the endpoint appends, or one whose
// self-signature does not verify, is never offered, and a tls-ca
// registration of its fingerprint is refused.
func TestNetDevProbeCAPinAnchorsLeaf(t *testing.T) {
	root, rootKey := netDevTestCert(t, "Lab Root CA", true, nil, nil)
	inter, interKey := netDevTestCert(t, "Lab Intermediate CA", true, root, rootKey)
	leaf, leafKey := netDevTestCert(t, "fw.lab.test", false, root, rootKey)
	deepLeaf, _ := netDevTestCert(t, "fw2.lab.test", false, inter, interKey)
	unrelated, _ := netDevTestCert(t, "Unrelated Root CA", true, nil, nil)
	selfLeaf, _ := netDevTestCert(t, "self.lab.test", false, nil, nil)
	_, otherKey := netDevTestCert(t, "other", false, nil, nil)
	forged, _ := netDevTestCert(t, "Forged Root CA", true, nil, otherKey)
	notCA, notCAKey := netDevTestCert(t, "Not A CA", false, nil, nil)
	underNotCA, _ := netDevTestCert(t, "fw3.lab.test", false, notCA, notCAKey)

	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		want  *x509.Certificate
	}{
		"leaf and root":                   {[]*x509.Certificate{leaf, root}, root},
		"leaf, intermediate, root":        {[]*x509.Certificate{deepLeaf, inter, root}, root},
		"root then unrelated appended":    {[]*x509.Certificate{leaf, root, unrelated}, root},
		"only an unrelated self-signed":   {[]*x509.Certificate{leaf, unrelated}, nil},
		"intermediate without its root":   {[]*x509.Certificate{deepLeaf, inter, unrelated}, nil},
		"self-signed leaf":                {[]*x509.Certificate{selfLeaf}, selfLeaf},
		"self-signed leaf plus unrelated": {[]*x509.Certificate{selfLeaf, unrelated}, selfLeaf},
		"forged self-signature":           {[]*x509.Certificate{forged}, nil},
		"issuer is not a CA":              {[]*x509.Certificate{underNotCA, notCA}, nil},
	} {
		if got := netDevChainCA(tc.chain); got != tc.want {
			gotCN, wantCN := "<nil>", "<nil>"
			if got != nil {
				gotCN = got.Subject.CommonName
			}
			if tc.want != nil {
				wantCN = tc.want.Subject.CommonName
			}
			t.Errorf("%s: CA %s, want %s", name, gotCN, wantCN)
		}
	}

	// End to end: the endpoint presents its leaf plus an unrelated
	// self-signed certificate.
	e := newNetDevTestEnv(t)
	d := &netDevDialer{target: serveNetDevTLSChain(t, leafKey, leaf, unrelated)}
	a := &NetDevAdmin{Store: e.store, Vault: e.vault, Dial: d.dial}
	ctx := context.Background()
	p, err := a.Probe(ctx, netdevcontract.FamilyPANOS, "10.20.0.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	if p.CAPin != "" || p.Facts.GetTlsCaFingerprint() != "" {
		t.Fatalf("probe offered CA pin %q for an unrelated self-signed certificate", p.CAPin)
	}
	if _, err := a.Register(ctx, NetDevRegister{DeviceID: "fw1", Family: netdevcontract.FamilyPANOS, Label: "fw1", Endpoint: "10.20.0.1", Port: 443,
		PinKind: netdevcontract.PinTLSCA, ConfirmedPin: certPinOf(unrelated), Confirm: "yes", By: "admin"}); !errors.Is(err, ErrNetDevPinMismatch) {
		t.Fatalf("tls-ca registration of an unrelated certificate: %v, want ErrNetDevPinMismatch", err)
	}

	d.setTarget(serveNetDevTLSChain(t, leafKey, leaf, root, unrelated))
	p, err = a.Probe(ctx, netdevcontract.FamilyPANOS, "10.20.0.1", 443)
	if err != nil {
		t.Fatal(err)
	}
	if p.CAPin != certPinOf(root) {
		t.Fatalf("probe CA pin %q, want the root that signs the leaf", p.CAPin)
	}
}

// TestRegisterNetDeviceProbesWithoutLifecycleLock: name resolution and the
// probe run without the lifecycle lock, which the RPC wiring sets as
// CommitLock; the store step takes it and re-checks the id, so an id taken
// while the probe ran is refused and the earlier device is untouched.
func TestRegisterNetDeviceProbesWithoutLifecycleLock(t *testing.T) {
	e := newNetDevTestEnv(t)
	srv := startNetDevTLSServer(t)
	svc, _ := newNetDevService(e, &netDevDialer{})
	if svc.netDevAdmin().CommitLock != &netDevAdminMu {
		t.Fatal("RPC lifecycle does not register under the lifecycle lock")
	}

	var lockFree []bool
	took := false
	d := &netDevDialer{target: srv.addr}
	svc.transport = sshtransport.Config{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		free := netDevAdminMu.TryLock()
		if free {
			netDevAdminMu.Unlock()
		}
		lockFree = append(lockFree, free)
		if !took {
			// Another admin takes the id while the probe runs.
			took = true
			registerTestNetDev(t, e, "fw1", "10.20.0.8", testNetDevPin)
		}
		return d.dial(ctx, network, addr)
	}}
	_, err := svc.RegisterNetDevice(context.Background(), &pb.RegisterNetDeviceRequest{DeviceId: "fw1", Family: string(netdevcontract.FamilyPANOS),
		Endpoint: "10.20.0.9", Port: 443, PinKind: string(netdevcontract.PinTLSLeaf), ConfirmedPin: certPinOf(srv.cert), Confirm: "yes"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("register of an id taken during the probe: %v, want AlreadyExists", err)
	}
	if !slices.Equal(lockFree, []bool{true}) {
		t.Fatalf("lifecycle lock free during probe dials: %v, want [true]", lockFree)
	}
	if cur, _, _ := e.db.GetNetDevice("fw1"); cur.Family != netdevcontract.FamilyCBS || cur.EndpointIP != "10.20.0.8" {
		t.Fatalf("earlier device changed: %+v", cur)
	}
	if !netDevAdminMu.TryLock() {
		t.Fatal("register left the lifecycle lock held")
	}
	netDevAdminMu.Unlock()
}
