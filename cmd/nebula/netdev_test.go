// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	netdevTestSecret = "Nd-Test-Credential-7f3a9c"
	netdevTestPin    = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd"
	netdevTestNewPin = "1111111111111111222222222222222233333333333333334444444444444444"
)

// netdevFake is a fake executor client that records every call, with the
// request in its protobuf text form, into one ordered log.
type netdevFake struct {
	pb.ExecutorServiceClient
	log []string
	// secrets are the request secret buffers as passed by the CLI (checked
	// for wiping afterwards); sentSecrets are copies taken at call time.
	// The secret field is the only place a secret may travel, so the
	// request log records each request with that field removed.
	secrets     [][]byte
	sentSecrets []string
	devices     []*pb.NetDeviceInfo
	probe       *pb.ProbeNetDeviceResponse
	pending     []*pb.PendingPermit
	outAtAsk    string
}

func (f *netdevFake) record(name string, req fmt.Stringer) {
	f.log = append(f.log, name+" "+req.String())
}

func (f *netdevFake) keepSecret(b []byte) {
	f.secrets = append(f.secrets, b)
	f.sentSecrets = append(f.sentSecrets, string(b))
}

func (f *netdevFake) calls() []string {
	var out []string
	for _, l := range f.log {
		out = append(out, strings.SplitN(l, " ", 2)[0])
	}
	return out
}

func (f *netdevFake) ProbeNetDevice(_ context.Context, in *pb.ProbeNetDeviceRequest, _ ...grpc.CallOption) (*pb.ProbeNetDeviceResponse, error) {
	f.record("Probe", in)
	return f.probe, nil
}

func (f *netdevFake) RegisterNetDevice(_ context.Context, in *pb.RegisterNetDeviceRequest, _ ...grpc.CallOption) (*pb.RegisterNetDeviceResponse, error) {
	f.record("Register", in)
	return &pb.RegisterNetDeviceResponse{Device: &pb.NetDeviceInfo{
		DeviceId: in.DeviceId, Family: in.Family, EndpointIp: "192.0.2.10", Port: in.Port,
		PinKind: in.PinKind, TrustPin: in.ConfirmedPin, TrustGeneration: 1,
	}}, nil
}

func (f *netdevFake) SetNetDeviceCredential(_ context.Context, in *pb.SetNetDeviceCredentialRequest, _ ...grpc.CallOption) (*pb.SetNetDeviceCredentialResponse, error) {
	f.keepSecret(in.Secret)
	logged := proto.Clone(in).(*pb.SetNetDeviceCredentialRequest)
	logged.Secret = nil
	f.record("SetCredential", logged)
	return &pb.SetNetDeviceCredentialResponse{Device: &pb.NetDeviceInfo{DeviceId: in.DeviceId, CredentialVersion: 1}}, nil
}

func (f *netdevFake) RotateNetDeviceCredential(_ context.Context, in *pb.RotateNetDeviceCredentialRequest, _ ...grpc.CallOption) (*pb.RotateNetDeviceCredentialResponse, error) {
	f.keepSecret(in.Secret)
	logged := proto.Clone(in).(*pb.RotateNetDeviceCredentialRequest)
	logged.Secret = nil
	f.record("RotateCredential", logged)
	return &pb.RotateNetDeviceCredentialResponse{Device: &pb.NetDeviceInfo{DeviceId: in.DeviceId, CredentialVersion: in.ExpectedCredentialVersion + 1}}, nil
}

func (f *netdevFake) ListNetDevices(_ context.Context, in *pb.ListNetDevicesRequest, _ ...grpc.CallOption) (*pb.ListNetDevicesResponse, error) {
	f.record("List", in)
	return &pb.ListNetDevicesResponse{Devices: f.devices}, nil
}

func (f *netdevFake) BlockNetDevice(_ context.Context, in *pb.BlockNetDeviceRequest, _ ...grpc.CallOption) (*pb.BlockNetDeviceResponse, error) {
	f.record("Block", in)
	return &pb.BlockNetDeviceResponse{Device: &pb.NetDeviceInfo{DeviceId: in.DeviceId, Blocked: true}}, nil
}

func (f *netdevFake) UnblockNetDevice(_ context.Context, in *pb.UnblockNetDeviceRequest, _ ...grpc.CallOption) (*pb.UnblockNetDeviceResponse, error) {
	f.record("Unblock", in)
	return &pb.UnblockNetDeviceResponse{Device: &pb.NetDeviceInfo{DeviceId: in.DeviceId}}, nil
}

func (f *netdevFake) RemoveNetDevice(_ context.Context, in *pb.RemoveNetDeviceRequest, _ ...grpc.CallOption) (*pb.RemoveNetDeviceResponse, error) {
	f.record("Remove", in)
	return &pb.RemoveNetDeviceResponse{Device: &pb.NetDeviceInfo{DeviceId: in.DeviceId}}, nil
}

func (f *netdevFake) ProposeNetDeviceRepin(_ context.Context, in *pb.ProposeNetDeviceRepinRequest, _ ...grpc.CallOption) (*pb.ProposeNetDeviceRepinResponse, error) {
	f.record("ProposeRepin", in)
	digest := strings.Repeat("e", 64)
	f.pending = []*pb.PendingPermit{{ExecutionDigest: digest, Request: &pb.ExecutionRequest{RiskClass: pb.RiskClass_RISK_CLASS_HIGH, ActionId: "netdev.repin"}}}
	return &pb.ProposeNetDeviceRepinResponse{Permit: &pb.ProposeExecutionResponse{ExecutionDigest: digest}}, nil
}

func (f *netdevFake) ListPending(_ context.Context, in *pb.ListPendingRequest, _ ...grpc.CallOption) (*pb.ListPendingResponse, error) {
	f.record("ListPending", in)
	return &pb.ListPendingResponse{Permits: f.pending}, nil
}

func (f *netdevFake) ApproveCLI(_ context.Context, in *pb.ApproveCLIRequest, _ ...grpc.CallOption) (*pb.ApproveCLIResponse, error) {
	f.record("ApproveCLI", in)
	return &pb.ApproveCLIResponse{}, nil
}

func (f *netdevFake) CommitNetDeviceRepin(_ context.Context, in *pb.CommitNetDeviceRepinRequest, _ ...grpc.CallOption) (*pb.CommitNetDeviceRepinResponse, error) {
	f.record("CommitRepin", in)
	return &pb.CommitNetDeviceRepinResponse{Device: &pb.NetDeviceInfo{DeviceId: in.DeviceId, TrustPin: in.ConfirmedNewPin, TrustGeneration: 2}}, nil
}

// netdevHarness wires a fake client, a fake prompter and buffers.
type netdevHarness struct {
	fake      *netdevFake
	out       bytes.Buffer
	promptOut bytes.Buffer
	fds       map[int]*netdevFakeFD
	env       netdevEnv
}

type netdevFakeFD struct {
	r      io.Reader
	closed bool
}

func (f *netdevFakeFD) Read(p []byte) (int, error) { return f.r.Read(p) }
func (f *netdevFakeFD) Close() error {
	f.closed = true
	return nil
}

func newNetdevHarness(t *testing.T, stdin string, tty bool) *netdevHarness {
	t.Helper()
	h := &netdevHarness{fds: map[int]*netdevFakeFD{}}
	h.fake = &netdevFake{
		probe: &pb.ProbeNetDeviceResponse{
			EndpointIp: "192.0.2.10", Port: 22, PinKind: "ssh-host-key", ObservedPin: netdevTestPin,
			Facts: &pb.NetDeviceProbeFacts{SshServerVersion: "SSH-2.0-test", SshHostKeyType: "ssh-ed25519"},
		},
	}
	h.env = netdevEnv{
		in:              bufio.NewReader(strings.NewReader(stdin)),
		stdinIsTerminal: tty,
		ask: func(prompt string) ([]byte, error) {
			h.fake.log = append(h.fake.log, "Ask "+prompt)
			h.fake.outAtAsk = h.out.String()
			return []byte(netdevTestSecret), nil
		},
		openFD: func(fd int) (io.ReadCloser, error) {
			f, ok := h.fds[fd]
			if !ok {
				return nil, fmt.Errorf("--secret-fd %d: not an open descriptor", fd)
			}
			return f, nil
		},
		out:       &h.out,
		promptOut: &h.promptOut,
		dial: func() (pb.ExecutorServiceClient, func(), error) {
			h.fake.log = append(h.fake.log, "Dial")
			return h.fake, func() {}, nil
		},
	}
	return h
}

// assertNoSecret checks that the credential appears in no output, in no
// recorded request and that every request buffer was wiped afterwards.
func (h *netdevHarness) assertNoSecret(t *testing.T, err error) {
	t.Helper()
	for name, s := range map[string]string{
		"stdout": h.out.String(), "prompts": h.promptOut.String(),
		"request log": strings.Join(h.fake.log, "\n"),
	} {
		if strings.Contains(s, netdevTestSecret) {
			t.Fatalf("secret appears in %s:\n%s", name, s)
		}
	}
	if err != nil && strings.Contains(err.Error(), netdevTestSecret) {
		t.Fatalf("secret appears in error: %v", err)
	}
	for _, s := range h.fake.sentSecrets {
		if s != netdevTestSecret {
			t.Fatal("the secret field did not carry exactly the entered credential")
		}
	}
	for _, b := range h.fake.secrets {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("secret buffer not cleared after the command")
		}
	}
}

func TestNetdevAddProbesAndConfirmsBeforeCredentialPrompt(t *testing.T) {
	h := newNetdevHarness(t, "yes\n", true)
	err := netdevCmd([]string{"add", "sw-1", "--family", "cbs", "--endpoint", "sw1.example", "--username", "nos-read"}, h.env)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	want := []string{"Dial", "Probe", "Ask", "Register", "SetCredential"}
	if got := h.fake.calls(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("call order = %v, want %v", got, want)
	}
	for _, s := range []string{"cbs", "192.0.2.10:22", "sha256:" + netdevTestPin, "SSH-2.0-test"} {
		if !strings.Contains(h.fake.outAtAsk, s) {
			t.Fatalf("probe output before the credential prompt lacks %q:\n%s", s, h.fake.outAtAsk)
		}
	}
	if !strings.Contains(h.promptOut.String(), "Type 'yes'") {
		t.Fatalf("no typed confirmation prompt: %q", h.promptOut.String())
	}
	reg := h.fake.log[3]
	for _, s := range []string{`confirmed_pin:"` + netdevTestPin + `"`, `confirm:"yes"`, `pin_kind:"ssh-host-key"`, `endpoint:"sw1.example"`, "port:22"} {
		if !strings.Contains(reg, s) {
			t.Fatalf("register request lacks %s: %s", s, reg)
		}
	}
	h.assertNoSecret(t, err)
}

func TestNetdevAddRefusesAnythingButTypedYes(t *testing.T) {
	for _, in := range []string{"y\n", "YES\n", "Yes\n", "yes please\n", "\n", "", strings.Repeat("y", 200) + "\n"} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			h := newNetdevHarness(t, in, true)
			err := netdevCmd([]string{"add", "sw-1", "--family", "cbs", "--endpoint", "sw1.example"}, h.env)
			if err == nil {
				t.Fatal("add succeeded without a typed yes")
			}
			for _, c := range h.fake.calls() {
				if c == "Register" || c == "Ask" || c == "SetCredential" {
					t.Fatalf("%s called after confirmation %q", c, in)
				}
			}
		})
	}
}

func TestNetdevSecretAbsentFromOutputAndRequestLog(t *testing.T) {
	h := newNetdevHarness(t, "", true)
	h.fake.devices = []*pb.NetDeviceInfo{{DeviceId: "fw-1", Family: "panos", CredentialVersion: 4}}
	err := netdevCmd([]string{"credential", "rotate", "fw-1"}, h.env)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := strings.Join(h.fake.calls(), ","); got != "Dial,List,Ask,RotateCredential" {
		t.Fatalf("calls = %s", got)
	}
	if !strings.Contains(h.fake.log[3], "expected_credential_version:4") {
		t.Fatalf("rotate did not bind the current version: %s", h.fake.log[3])
	}
	if len(h.fake.secrets) != 1 {
		t.Fatalf("secret not sent")
	}
	h.assertNoSecret(t, err)

	h = newNetdevHarness(t, "", true)
	err = netdevCmd([]string{"credential", "set", "fw-1"}, h.env)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	h.assertNoSecret(t, err)
}

func TestNetdevCredentialRefusedWhenStdinIsNotTerminal(t *testing.T) {
	t.Setenv("NEBULA_NETDEV_SECRET", netdevTestSecret)
	for _, args := range [][]string{
		{"credential", "set", "fw-1"},
		{"credential", "rotate", "fw-1"},
		{"add", "fw-1", "--family", "panos", "--endpoint", "fw.example"},
	} {
		h := newNetdevHarness(t, "yes\n"+netdevTestSecret+"\n", false)
		err := netdevCmd(args, h.env)
		if !errors.Is(err, errNetdevNoTerminal) {
			t.Fatalf("%v: err = %v, want errNetdevNoTerminal", args, err)
		}
		if len(h.fake.log) != 0 {
			t.Fatalf("%v: contacted the executor or prompted: %v", args, h.fake.log)
		}
	}
	// --no-credential needs no terminal.
	h := newNetdevHarness(t, "yes\n", false)
	if err := netdevCmd([]string{"add", "fw-1", "--family", "panos", "--endpoint", "fw.example", "--no-credential"}, h.env); err != nil {
		t.Fatalf("add --no-credential: %v", err)
	}
	if got := strings.Join(h.fake.calls(), ","); got != "Dial,Probe,Register" {
		t.Fatalf("calls = %s", got)
	}
}

func TestNetdevSecretNeverFromArgv(t *testing.T) {
	for _, flagName := range []string{"--secret", "--password", "--token", "--credential", "--api-key"} {
		h := newNetdevHarness(t, "", true)
		err := netdevCmd([]string{"credential", "set", "fw-1", flagName, netdevTestSecret}, h.env)
		if err == nil {
			t.Fatalf("%s accepted", flagName)
		}
		if len(h.fake.log) != 0 {
			t.Fatalf("%s: contacted the executor: %v", flagName, h.fake.log)
		}
		h.assertNoSecret(t, err)
	}
}

func TestNetdevSecretFDReadOnceAndClosed(t *testing.T) {
	h := newNetdevHarness(t, "", false)
	fd := &netdevFakeFD{r: strings.NewReader(netdevTestSecret + "\n")}
	h.fds[5] = fd
	err := netdevCmd([]string{"credential", "set", "fw-1", "--secret-fd", "5"}, h.env)
	if err != nil {
		t.Fatalf("set --secret-fd: %v", err)
	}
	if !fd.closed {
		t.Fatal("descriptor not closed")
	}
	if got := strings.Join(h.fake.calls(), ","); got != "Dial,SetCredential" {
		t.Fatalf("calls = %s (the terminal prompter must not be used)", got)
	}
	if !strings.Contains(h.fake.log[1], "fw-1") {
		t.Fatalf("request: %s", h.fake.log[1])
	}
	h.assertNoSecret(t, err)
}

func TestNetdevSecretFDRejections(t *testing.T) {
	cases := []struct {
		name  string
		fd    string
		input string
	}{
		{"stdin", "0", "x"},
		{"stdout", "1", "x"},
		{"stderr", "2", "x"},
		{"negative", "-4", "x"},
		{"not open", "9", ""},
		{"empty", "5", "\n"},
		{"oversized", "5", strings.Repeat("s", maxNetdevSecretBytes+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newNetdevHarness(t, "", false)
			h.fds[5] = &netdevFakeFD{r: strings.NewReader(tc.input)}
			err := netdevCmd([]string{"credential", "set", "fw-1", "--secret-fd", tc.fd}, h.env)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, c := range h.fake.calls() {
				if c == "SetCredential" {
					t.Fatal("credential sent")
				}
			}
		})
	}
}

func TestNetdevRemoveAndUnblockRequireTypedYes(t *testing.T) {
	for _, op := range []string{"remove", "unblock"} {
		for _, in := range []string{"y\n", "YES\n", "no\n", ""} {
			h := newNetdevHarness(t, in, true)
			if err := netdevCmd([]string{op, "sw-1"}, h.env); err == nil {
				t.Fatalf("%s with %q succeeded", op, in)
			}
			if got := strings.Join(h.fake.calls(), ","); got != "Dial" {
				t.Fatalf("%s with %q: calls = %s", op, in, got)
			}
		}
		h := newNetdevHarness(t, "yes\n", true)
		if err := netdevCmd([]string{op, "sw-1"}, h.env); err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if last := h.fake.log[len(h.fake.log)-1]; !strings.Contains(last, `confirm:"yes"`) {
			t.Fatalf("%s request: %s", op, last)
		}
	}
}

func TestNetdevBlock(t *testing.T) {
	h := newNetdevHarness(t, "", true)
	if err := netdevCmd([]string{"block", "sw-1", "--reason", "maintenance"}, h.env); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !strings.Contains(h.fake.log[1], `reason:"maintenance"`) || h.out.String() != "device sw-1 blocked\n" {
		t.Fatalf("log %v out %q", h.fake.log, h.out.String())
	}
}

func TestNetdevRepinShowsBothPinsAndNeedsApproval(t *testing.T) {
	h := newNetdevHarness(t, "yes\nyes\n", true)
	h.fake.devices = []*pb.NetDeviceInfo{{DeviceId: "sw-1", Family: "cbs", EndpointIp: "192.0.2.10", Port: 22, TrustPin: netdevTestPin, TrustGeneration: 1}}
	h.fake.probe.ObservedPin = netdevTestNewPin
	if err := netdevCmd([]string{"repin", "sw-1"}, h.env); err != nil {
		t.Fatalf("repin: %v", err)
	}
	want := "Dial,List,Probe,ProposeRepin,ListPending,ApproveCLI,CommitRepin"
	if got := strings.Join(h.fake.calls(), ","); got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}
	for _, s := range []string{netdevTestPin, netdevTestNewPin} {
		if !strings.Contains(h.out.String(), s) {
			t.Fatalf("output lacks %s:\n%s", s, h.out.String())
		}
	}
	commit := h.fake.log[len(h.fake.log)-1]
	if !strings.Contains(commit, `old_pin:"`+netdevTestPin) || !strings.Contains(commit, `confirmed_new_pin:"`+netdevTestNewPin) {
		t.Fatalf("commit: %s", commit)
	}

	h = newNetdevHarness(t, "YES\n", true)
	h.fake.devices = []*pb.NetDeviceInfo{{DeviceId: "sw-1", Family: "cbs", TrustPin: netdevTestPin}}
	h.fake.probe.ObservedPin = netdevTestNewPin
	if err := netdevCmd([]string{"repin", "sw-1"}, h.env); err == nil {
		t.Fatal("repin accepted YES")
	}
	if got := strings.Join(h.fake.calls(), ","); got != "Dial,List,Probe" {
		t.Fatalf("calls = %s", got)
	}
}

func TestNetdevProbeEscapesDeviceOutput(t *testing.T) {
	h := newNetdevHarness(t, "", true)
	h.fake.probe = &pb.ProbeNetDeviceResponse{
		EndpointIp: "192.0.2.20", Port: 443, ResolvedFrom: "fw.example", PinKind: "tls-leaf", ObservedPin: netdevTestPin,
		Facts: &pb.NetDeviceProbeFacts{TlsSubject: "CN=fw\x1b[2J\r\nfingerprint sha256:" + netdevTestNewPin, TlsDnsNames: []string{"fw.example"}, TlsNotAfterUnix: 1893456000},
	}
	if err := netdevCmd([]string{"probe", "--family", "panos", "--endpoint", "fw.example"}, h.env); err != nil {
		t.Fatalf("probe: %v", err)
	}
	out := h.out.String()
	if strings.ContainsAny(out, "\x1b\r") || strings.Count(out, "\n") != 8 {
		t.Fatalf("device output not escaped:\n%q", out)
	}
	if !strings.Contains(h.fake.log[1], "port:443") {
		t.Fatalf("default panos port not used: %s", h.fake.log[1])
	}
	if !strings.Contains(out, "tls expires  2030-01-01T00:00:00Z") {
		t.Fatalf("expiry: %s", out)
	}
}

func TestNetdevListOutputStable(t *testing.T) {
	h := newNetdevHarness(t, "", true)
	h.fake.devices = []*pb.NetDeviceInfo{
		{DeviceId: "fw-1", Family: "panos", Label: "edge", EndpointIp: "192.0.2.1", Port: 443, PinKind: "tls-leaf", TrustPin: netdevTestPin, TrustGeneration: 2, CredentialVersion: 3, UpdatedAtUnix: 1700000000},
		{DeviceId: "sw-1", Family: "cbs", EndpointIp: "192.0.2.2", Port: 22, PinKind: "ssh-host-key", TrustPin: netdevTestNewPin, TrustGeneration: 1, Blocked: true, BlockReason: "maint", UpdatedAtUnix: 1700000060},
		{DeviceId: "sw-2", Family: "cbs", EndpointIp: "192.0.2.3", Port: 22, PinKind: "ssh-host-key", TrustPin: netdevTestPin, TrustGeneration: 1, CredentialMissing: true, UpdatedAtUnix: 1700000120},
	}
	if err := netdevCmd([]string{"list"}, h.env); err != nil {
		t.Fatalf("list: %v", err)
	}
	want := "" +
		"ID    FAMILY  LABEL  ENDPOINT       PIN (GEN)                               STATE            CREDENTIAL  UPDATED\n" +
		"fw-1  panos   edge   192.0.2.1:443  tls-leaf aaaaaaaaaaaaaaaa… (gen 2)      active           v3          2023-11-14T22:13:20Z\n" +
		"sw-1  cbs            192.0.2.2:22   ssh-host-key 1111111111111111… (gen 1)  blocked (maint)  none        2023-11-14T22:14:20Z\n" +
		"sw-2  cbs            192.0.2.3:22   ssh-host-key aaaaaaaaaaaaaaaa… (gen 1)  active           missing     2023-11-14T22:15:20Z\n"
	if got := h.out.String(); got != want {
		t.Fatalf("list output changed:\n%s\nwant:\n%s", got, want)
	}

	h = newNetdevHarness(t, "", true)
	if err := netdevCmd([]string{"list"}, h.env); err != nil || h.out.String() != "no network devices\n" {
		t.Fatalf("empty list: %v %q", err, h.out.String())
	}
}

func TestNetdevUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"credential"}, {"credential", "show", "x"}, {"add"}, {"remove"}, {"list", "extra"}} {
		h := newNetdevHarness(t, "", true)
		if err := netdevCmd(args, h.env); err == nil || !strings.Contains(err.Error(), "usage: nebula netdev") {
			t.Fatalf("%v: err = %v", args, err)
		}
		if len(h.fake.log) != 0 {
			t.Fatalf("%v: contacted the executor", args)
		}
	}
	h := newNetdevHarness(t, "", true)
	if err := netdevCmd([]string{"probe", "--family", "ios", "--endpoint", "x"}, h.env); err == nil {
		t.Fatal("unknown family accepted")
	}
	if err := netdevCmd([]string{"probe", "--family", "cbs", "--endpoint", "x", "--port", "70000"}, h.env); err == nil {
		t.Fatal("port out of range accepted")
	}
}

func TestNetdevHelpUsesPlaceholdersOnly(t *testing.T) {
	ip := regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-f]{1,4}::`)
	for name, text := range map[string]string{"netdevUsage": netdevUsage, "usage": usage} {
		if m := ip.FindString(text); m != "" {
			t.Fatalf("%s contains an address %q", name, m)
		}
	}
	if !strings.Contains(usage, "netdev") {
		t.Fatal("main help does not mention netdev")
	}
}
