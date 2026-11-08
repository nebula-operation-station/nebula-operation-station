// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/containerdef"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const plantedEnvValue = "s3cr3t-planted-env-value-8b1f"

type fakeDefinitions struct {
	pb.ExecutorServiceClient
	put     *pb.PutContainerDefinitionRequest
	removed *pb.RemoveContainerDefinitionRequest
	listed  *pb.ListContainerDefinitionsRequest
	putErr  error
	list    []*pb.ContainerDefinitionInfo
}

func (f *fakeDefinitions) PutContainerDefinition(_ context.Context, in *pb.PutContainerDefinitionRequest, _ ...grpc.CallOption) (*pb.PutContainerDefinitionResponse, error) {
	f.put = in
	if f.putErr != nil {
		return nil, f.putErr
	}
	return &pb.PutContainerDefinitionResponse{Definition: &pb.ContainerDefinitionInfo{HostId: in.GetHostId(), ContainerName: in.GetContainerName(),
		DefinitionId: "0b8f2c1e-6a0d-4e57-9f43-1f7f0f5d9a11", Version: 2, CreatedBy: "alice", Latest: true}}, nil
}

func (f *fakeDefinitions) RemoveContainerDefinition(_ context.Context, in *pb.RemoveContainerDefinitionRequest, _ ...grpc.CallOption) (*pb.RemoveContainerDefinitionResponse, error) {
	f.removed = in
	if in.GetVersion() != 0 {
		return &pb.RemoveContainerDefinitionResponse{Versions: []uint64{in.GetVersion()}}, nil
	}
	return &pb.RemoveContainerDefinitionResponse{Versions: []uint64{1, 2}}, nil
}

func (f *fakeDefinitions) ListContainerDefinitions(_ context.Context, in *pb.ListContainerDefinitionsRequest, _ ...grpc.CallOption) (*pb.ListContainerDefinitionsResponse, error) {
	f.listed = in
	return &pb.ListContainerDefinitionsResponse{Definitions: f.list}, nil
}

func definitionJSON(name string) string {
	return `{"format":"` + containerdef.Format + `","container_name":"` + name + `","options":["--name=` + name +
		`","--publish=8080:80"],"command":["serve"],"env":[{"name":"TOKEN","value":"` + plantedEnvValue + `"}]}` + "\n"
}

func noFile(string) (io.ReadCloser, error) { return nil, errors.New("no file in this test") }

func TestContainerDefinitionPutReadsStdinAndNeverEchoesContent(t *testing.T) {
	f := &fakeDefinitions{}
	var out bytes.Buffer
	err := containerCmd(context.Background(), f, []string{"definition", "put", "web-1", "web"}, strings.NewReader(definitionJSON("web")), noFile, &out)
	if err != nil {
		t.Fatal(err)
	}
	if f.put == nil || f.put.GetHostId() != "web-1" || f.put.GetContainerName() != "web" {
		t.Fatalf("put request %v", f.put)
	}
	if len(f.put.GetEnv()) != 1 || f.put.GetEnv()[0].GetValue() != plantedEnvValue || f.put.GetEnv()[0].GetName() != "TOKEN" {
		t.Fatalf("env not passed through: %v", f.put.GetEnv())
	}
	if strings.Join(f.put.GetOptions(), " ") != "--name=web --publish=8080:80" || strings.Join(f.put.GetCommand(), " ") != "serve" {
		t.Fatalf("options/command %v %v", f.put.GetOptions(), f.put.GetCommand())
	}
	if strings.Contains(out.String(), plantedEnvValue) || !strings.Contains(out.String(), "version 2") {
		t.Fatalf("output %q", out.String())
	}
}

func TestContainerDefinitionPutReadsNamedFile(t *testing.T) {
	f := &fakeDefinitions{}
	opened := ""
	open := func(p string) (io.ReadCloser, error) {
		opened = p
		return io.NopCloser(strings.NewReader(definitionJSON("db"))), nil
	}
	var out bytes.Buffer
	if err := containerCmd(context.Background(), f, []string{"definition", "put", "db-1", "db", "/etc/db.json"}, strings.NewReader(""), open, &out); err != nil {
		t.Fatal(err)
	}
	if opened != "/etc/db.json" || f.put == nil || f.put.GetContainerName() != "db" {
		t.Fatalf("opened %q put %v", opened, f.put)
	}
	// "-" is stdin, not a file named "-".
	f.put = nil
	if err := containerCmd(context.Background(), f, []string{"definition", "put", "db-1", "db", "-"}, strings.NewReader(definitionJSON("db")), noFile, &out); err != nil {
		t.Fatal(err)
	}
	if f.put == nil {
		t.Fatal("stdin put not sent")
	}
}

// A refused definition is never sent, and the error names the rule but
// never a value from the file.
func TestContainerDefinitionPutRefusesBadInputWithoutEchoingIt(t *testing.T) {
	cases := map[string]struct {
		host, name, body string
	}{
		"other container":    {"web-1", "web", definitionJSON("db")},
		"unknown field":      {"web-1", "web", strings.Replace(definitionJSON("web"), `"command"`, `"secret_`+plantedEnvValue+`":1,"command"`, 1)},
		"not json":           {"web-1", "web", plantedEnvValue},
		"trailing data":      {"web-1", "web", definitionJSON("web") + `{"x":"` + plantedEnvValue + `"}`},
		"newline in env":     {"web-1", "web", strings.Replace(definitionJSON("web"), plantedEnvValue, plantedEnvValue+`\nX=1`, 1)},
		"over the limit":     {"web-1", "web", strings.Replace(definitionJSON("web"), plantedEnvValue, plantedEnvValue+strings.Repeat("a", containerdef.MaxEncodedBytes), 1)},
		"empty input":        {"web-1", "web", ""},
		"bad host":           {"web 1", "web", definitionJSON("web")},
		"bad name":           {"web-1", "we b", definitionJSON("web")},
		"docker-chosen port": {"web-1", "web", strings.Replace(definitionJSON("web"), "--publish=8080:80", "--publish=80", 1)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeDefinitions{}
			var out bytes.Buffer
			err := containerCmd(context.Background(), f, []string{"definition", "put", tc.host, tc.name}, strings.NewReader(tc.body), noFile, &out)
			if err == nil {
				t.Fatal("accepted")
			}
			if f.put != nil {
				t.Fatal("a refused definition was sent")
			}
			if strings.Contains(err.Error(), plantedEnvValue) || strings.Contains(out.String(), plantedEnvValue) {
				t.Fatalf("value echoed: %v / %q", err, out.String())
			}
		})
	}
}

// The executor's refusal reaches the admin; the request content does not.
func TestContainerDefinitionPutExecutorRefusalHoldsNoContent(t *testing.T) {
	f := &fakeDefinitions{putErr: grpcstatus.Error(codes.FailedPrecondition, "the executor vault is locked")}
	var out bytes.Buffer
	err := containerCmd(context.Background(), f, []string{"definition", "put", "web-1", "web"}, strings.NewReader(definitionJSON("web")), noFile, &out)
	if err == nil || !strings.Contains(err.Error(), "vault is locked") || strings.Contains(err.Error(), plantedEnvValue) {
		t.Fatalf("err %v", err)
	}
}

// put takes the definition from a file or stdin only: extra arguments
// (where a value could be typed into the shell history) are refused.
func TestContainerDefinitionPutRefusesDefinitionOnArgv(t *testing.T) {
	f := &fakeDefinitions{}
	var out bytes.Buffer
	err := containerCmd(context.Background(), f, []string{"definition", "put", "web-1", "web", "file", "TOKEN=" + plantedEnvValue}, strings.NewReader(""), noFile, &out)
	if err == nil || f.put != nil {
		t.Fatalf("accepted extra arguments: %v", err)
	}
}

func TestContainerDefinitionRemoveNeedsConfirmation(t *testing.T) {
	f := &fakeDefinitions{}
	var out bytes.Buffer
	if err := containerCmd(context.Background(), f, []string{"definition", "remove", "web-1", "web"}, strings.NewReader("no\n"), noFile, &out); err == nil || f.removed != nil {
		t.Fatalf("removed without yes: %v", err)
	}
	if err := containerCmd(context.Background(), f, []string{"definition", "remove", "web-1", "web"}, strings.NewReader("yes\n"), noFile, &out); err != nil {
		t.Fatal(err)
	}
	if f.removed.GetVersion() != 0 || !strings.Contains(out.String(), "removed version(s) 1, 2") {
		t.Fatalf("remove %v out %q", f.removed, out.String())
	}
	f.removed = nil
	if err := containerCmd(context.Background(), f, []string{"definition", "remove", "--version", "1", "web-1", "web"}, strings.NewReader("yes\n"), noFile, &out); err != nil {
		t.Fatal(err)
	}
	if f.removed.GetVersion() != 1 {
		t.Fatalf("version %d", f.removed.GetVersion())
	}
	for _, bad := range [][]string{{"--version", "0", "web-1", "web"}, {"--version", "x", "web-1", "web"}, {"--version"}, {"web-1"}} {
		f.removed = nil
		if err := containerCmd(context.Background(), f, append([]string{"definition", "remove"}, bad...), strings.NewReader("yes\n"), noFile, &out); err == nil || f.removed != nil {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestContainerDefinitionListShowsMetadataEscaped(t *testing.T) {
	f := &fakeDefinitions{list: []*pb.ContainerDefinitionInfo{
		{HostId: "web-1", ContainerName: "web", DefinitionId: "0b8f2c1e-6a0d-4e57-9f43-1f7f0f5d9a11", Version: 3, CreatedBy: "alice\x1b[2J", CreatedAtUnix: 1700000000, Latest: true},
	}}
	var out bytes.Buffer
	if err := containerCmd(context.Background(), f, []string{"definition", "list", "web-1"}, strings.NewReader(""), noFile, &out); err != nil {
		t.Fatal(err)
	}
	if f.listed.GetHostId() != "web-1" {
		t.Fatalf("host %q", f.listed.GetHostId())
	}
	s := out.String()
	if !strings.Contains(s, "web-1") || !strings.Contains(s, "2023-11-14T22:13:20Z") || !strings.Contains(s, "yes") || strings.Contains(s, "\x1b") {
		t.Fatalf("list output %q", s)
	}
	if err := containerCmd(context.Background(), f, []string{"definition", "list", "bad host"}, strings.NewReader(""), noFile, &out); err == nil {
		t.Fatal("bad host accepted")
	}
	f.list = nil
	out.Reset()
	if err := containerCmd(context.Background(), f, []string{"definition", "list"}, strings.NewReader(""), noFile, &out); err != nil || !strings.Contains(out.String(), "no container definitions") {
		t.Fatalf("%v %q", err, out.String())
	}
}

func TestContainerCmdUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"definition"}, {"other", "put"}, {"definition", "show"}} {
		if err := containerCmd(context.Background(), &fakeDefinitions{}, args, strings.NewReader(""), noFile, io.Discard); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}
