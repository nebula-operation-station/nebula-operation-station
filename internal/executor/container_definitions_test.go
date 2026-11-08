// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	defPlanted      = "planted-env-value-7f3a"
	defPlantedLabel = "planted-label-91c2"
)

func newDefinitionEnv(t *testing.T) *reconcileEnv {
	t.Helper()
	e := newReconcileEnv(t)
	e.svc.SetVaultParams(testVaultParams)
	pass := []byte(strings.Repeat("correct-horse-battery-staple-", 4))
	if err := e.svc.vault.Init(pass, testVaultParams, "test"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.vault.Unlock(pass); err != nil {
		t.Fatal(err)
	}
	return e
}

func putDefinitionRequest(name string) *pb.PutContainerDefinitionRequest {
	return &pb.PutContainerDefinitionRequest{
		HostId: "web-1", ContainerName: name,
		Options: []string{"--name=" + name, "--restart=unless-stopped", "--publish=8080:80", "--label=note=" + defPlantedLabel},
		Command: []string{"serve"},
		Env:     []*pb.ContainerDefinitionEnv{{Name: "DB_PASSWORD", Value: defPlanted}, {Name: "PORT", Value: "8080"}},
	}
}

// standaloneIntent writes a standalone recreation row in intent whose
// recreation definition names definitionID at version.
func standaloneIntent(t *testing.T, db *executordb.DB, exec, definitionID string, version uint64) {
	t.Helper()
	err := db.CreateContainerRecreation(executordb.ContainerRecreation{
		ExecutionID: exec, BatchDigest: strings.Repeat("d", 64), MemberID: "m-01", Kind: "update",
		HostID: "web-1", HostKey: "SHA256:k", Form: "standalone", Unit: "web",
		Binding:    []byte(`{"kind":"update"}`),
		Definition: fmt.Appendf(nil, `{"form":"standalone","definition_id":%q,"definition_version":%d,"services":[]}`, definitionID, version),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, c codes.Code) {
	t.Helper()
	if status.Code(err) != c {
		t.Fatalf("got %v, want %s", err, c)
	}
}

// noLeak fails when any log record holds one of the needles.
func noLeak(t *testing.T, e *reconcileEnv, needles ...string) {
	t.Helper()
	e.logs.mu.Lock()
	defer e.logs.mu.Unlock()
	for _, r := range e.logs.records {
		line := fmt.Sprint(r.msg, r.attrs)
		for _, n := range needles {
			if strings.Contains(line, n) {
				t.Fatalf("log line holds %q: %s", n, line)
			}
		}
	}
}

func TestNoDefinitionDigestLeavesExecutor(t *testing.T) {
	e := newDefinitionEnv(t)
	ctx := context.Background()
	put, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web"))
	if err != nil {
		t.Fatal(err)
	}
	info := put.GetDefinition()
	if info.GetVersion() != 1 || !info.GetLatest() || info.GetContainerName() != "web" || info.GetDefinitionId() == "" {
		t.Fatalf("put answer %+v", info)
	}
	// The stored content and its digest, as they exist inside the executor.
	secretID := executordb.ContainerDefinitionSecretID(info.GetDefinitionId(), 1)
	raw, err := e.svc.vault.Open(secretID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), defPlanted) {
		t.Fatal("stored definition lacks its env value")
	}
	sum := sha256.Sum256(raw)
	needles := []string{defPlanted, defPlantedLabel, hex.EncodeToString(sum[:]), secretID, "unless-stopped", "DB_PASSWORD"}

	if _, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web")); err != nil {
		t.Fatal(err)
	}
	list, err := e.svc.ListContainerDefinitions(ctx, &pb.ListContainerDefinitionsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetDefinitions()) != 2 || list.GetDefinitions()[0].GetLatest() || !list.GetDefinitions()[1].GetLatest() {
		t.Fatalf("list %+v", list)
	}
	rm, err := e.svc.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web", Version: 1})
	if err != nil || !slices.Equal(rm.GetVersions(), []uint64{1}) {
		t.Fatalf("remove %+v %v", rm, err)
	}
	for _, m := range []proto.Message{put, list, rm} {
		b, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b) + protojson.Format(m)
		for _, n := range needles {
			if strings.Contains(text, n) {
				t.Fatalf("%T holds %q", m, n)
			}
		}
	}
	noLeak(t, e, needles...)
	// The metadata message has no field that could carry content or a
	// digest.
	fields := (&pb.ContainerDefinitionInfo{}).ProtoReflect().Descriptor().Fields()
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		for _, bad := range []string{"digest", "hash", "content", "env", "option", "command", "secret"} {
			if strings.Contains(name, bad) {
				t.Fatalf("ContainerDefinitionInfo field %s", name)
			}
		}
	}
}

func TestDefinitionNewlineEnvRefusedAtPut(t *testing.T) {
	for name, v := range map[string]string{
		"newline":     defPlanted + "\nsecond",
		"trailing CR": defPlanted + "\r",
		"inner CR":    "planted-env\rvalue-7f3a",
		"NUL":         "planted-env\x00value-7f3a",
	} {
		t.Run(name, func(t *testing.T) {
			e := newDefinitionEnv(t)
			req := putDefinitionRequest("web")
			req.Env[0].Value = v
			_, err := e.svc.PutContainerDefinition(context.Background(), req)
			wantCode(t, err, codes.InvalidArgument)
			for _, n := range []string{"planted-env", "value-7f3a"} {
				if strings.Contains(err.Error(), n) {
					t.Fatalf("error echoes the value: %v", err)
				}
			}
			noLeak(t, e, "planted-env", "value-7f3a")
			if rows, err := e.db.ListContainerDefinitions(""); err != nil || len(rows) != 0 {
				t.Fatalf("refused definition stored: %+v %v", rows, err)
			}
			secrets, err := e.svc.vault.List()
			if err != nil || len(secrets) != 0 {
				t.Fatalf("refused definition wrote a secret: %+v %v", secrets, err)
			}
		})
	}
}

func TestDefinitionRejectedShapesAtPut(t *testing.T) {
	cases := map[string]func(*pb.PutContainerDefinitionRequest){
		"name of another container": func(r *pb.PutContainerDefinitionRequest) { r.Options[0] = "--name=db" },
		"no name":                   func(r *pb.PutContainerDefinitionRequest) { r.Options = r.Options[1:] },
		"image in options":          func(r *pb.PutContainerDefinitionRequest) { r.Options = append(r.Options, "nginx:1.27") },
		"env on the command line":   func(r *pb.PutContainerDefinitionRequest) { r.Options = append(r.Options, "--env=A="+defPlanted) },
		"docker-chosen host port":   func(r *pb.PutContainerDefinitionRequest) { r.Options = append(r.Options, "--publish=80") },
		"publish all":               func(r *pb.PutContainerDefinitionRequest) { r.Options = append(r.Options, "--publish-all=true") },
		"bad host":                  func(r *pb.PutContainerDefinitionRequest) { r.HostId = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDefinitionEnv(t)
			req := putDefinitionRequest("web")
			mutate(req)
			_, err := e.svc.PutContainerDefinition(context.Background(), req)
			wantCode(t, err, codes.InvalidArgument)
			if strings.Contains(err.Error(), defPlanted) {
				t.Fatalf("error echoes the value: %v", err)
			}
			if rows, _ := e.db.ListContainerDefinitions(""); len(rows) != 0 {
				t.Fatalf("refused definition stored: %+v", rows)
			}
		})
	}
}

func TestDefinitionRemoveRefusedInsideWindowAtRPC(t *testing.T) {
	e := newDefinitionEnv(t)
	ctx := context.Background()
	v1, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web"))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web"))
	if err != nil {
		t.Fatal(err)
	}
	id := v1.GetDefinition().GetDefinitionId()
	if v2.GetDefinition().GetDefinitionId() != id || v2.GetDefinition().GetVersion() != 2 {
		t.Fatalf("second put %+v", v2.GetDefinition())
	}
	standaloneIntent(t, e.db, "00000000-0000-4000-9000-0000000000c1", id, 1)
	_, err = e.svc.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web"})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = e.svc.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web", Version: 1})
	wantCode(t, err, codes.FailedPrecondition)
	_, err = e.svc.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web", Version: 2})
	wantCode(t, err, codes.FailedPrecondition)
	// Both versions and their secrets are still there.
	for v := uint64(1); v <= 2; v++ {
		if _, err := e.svc.vault.Open(executordb.ContainerDefinitionSecretID(id, v)); err != nil {
			t.Fatalf("version %d secret: %v", v, err)
		}
	}
	_, err = e.svc.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "nope"})
	wantCode(t, err, codes.NotFound)
}

func TestDefinitionSecretsOnlyThroughDefinitionRPCs(t *testing.T) {
	e := newDefinitionEnv(t)
	ctx := context.Background()
	put, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web"))
	if err != nil {
		t.Fatal(err)
	}
	id := executordb.ContainerDefinitionSecretID(put.GetDefinition().GetDefinitionId(), 1)
	// The generic vault RPCs can neither replace nor delete a version, nor
	// pre-create the next one.
	_, err = e.svc.SetSecret(ctx, &pb.SetSecretRequest{Id: id, Value: []byte("replaced")})
	wantCode(t, err, codes.PermissionDenied)
	_, err = e.svc.SetSecret(ctx, &pb.SetSecretRequest{Id: executordb.ContainerDefinitionSecretID(put.GetDefinition().GetDefinitionId(), 2), Value: []byte("x")})
	wantCode(t, err, codes.PermissionDenied)
	_, err = e.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: id})
	wantCode(t, err, codes.PermissionDenied)
	raw, err := e.svc.vault.Open(id)
	if err != nil || !strings.Contains(string(raw), defPlanted) {
		t.Fatalf("version 1 changed: %v", err)
	}
}

func TestDefinitionPutRefusedWhileVaultLocked(t *testing.T) {
	e := newDefinitionEnv(t)
	ctx := context.Background()
	if _, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web")); err != nil {
		t.Fatal(err)
	}
	e.svc.vault.Lock()
	_, err := e.svc.PutContainerDefinition(ctx, putDefinitionRequest("web"))
	wantCode(t, err, codes.FailedPrecondition)
	_, err = e.svc.RemoveContainerDefinition(ctx, &pb.RemoveContainerDefinitionRequest{HostId: "web-1", ContainerName: "web"})
	wantCode(t, err, codes.FailedPrecondition)
	// Listing metadata needs no secret.
	list, err := e.svc.ListContainerDefinitions(ctx, &pb.ListContainerDefinitionsRequest{HostId: "web-1"})
	if err != nil || len(list.GetDefinitions()) != 1 {
		t.Fatalf("list while locked %+v %v", list, err)
	}
}

func TestDefinitionRPCsAdminOnly(t *testing.T) {
	roles := MethodRoles()
	for _, m := range []string{
		pb.ExecutorService_PutContainerDefinition_FullMethodName,
		pb.ExecutorService_RemoveContainerDefinition_FullMethodName,
		pb.ExecutorService_ListContainerDefinitions_FullMethodName,
	} {
		if !slices.Equal(roles[m], []peercred.Role{peercred.RoleAdmin}) {
			t.Fatalf("%s roles %v", m, roles[m])
		}
	}
}
