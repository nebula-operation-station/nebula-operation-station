// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

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
