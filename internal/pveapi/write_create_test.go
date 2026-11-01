// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const upidCreate = "UPID:pve1:00001234:00ABCDEF:6900A000:qmcreate:9000:nos@pve!action:"

func okImageVM() ImageVMRequest {
	return ImageVMRequest{Node: "pve1", VMID: 9000, Name: "tpl-ubuntu-24-04", Storage: "local-lvm",
		ImportStorage: "local", ImportFilename: "nos-ubuntu-24.04-amd64.qcow2"}
}

func TestCreateImageVMSendsCloudInitAndAgent(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidCreate)}
	w := newTestWriter(t, f)
	got, err := w.CreateImageVM(context.Background(), okImageVM())
	if err != nil || got != upidCreate {
		t.Fatalf("CreateImageVM = %q, %v", got, err)
	}
	r := f.only(t)
	if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/qemu" || r.auth != testToken {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	want := url.Values{
		"vmid":    {"9000"},
		"name":    {"tpl-ubuntu-24-04"},
		"ostype":  {"l26"},
		"cores":   {"1"},
		"memory":  {"1024"},
		"scsihw":  {"virtio-scsi-single"},
		"scsi0":   {"local-lvm:0,import-from=local:import/nos-ubuntu-24.04-amd64.qcow2"},
		"ide2":    {"local-lvm:cloudinit"},
		"boot":    {"order=scsi0"},
		"serial0": {"socket"},
		"vga":     {"serial0"},
		"agent":   {"enabled=1"},
	}
	if r.form.Encode() != want.Encode() {
		t.Errorf("form = %v\nwant %v", r.form, want)
	}
}

func TestCreateImageVMRejectsInvalidArguments(t *testing.T) {
	cases := map[string]func(*ImageVMRequest){
		"node":             func(r *ImageVMRequest) { r.Node = "pve1/../x" },
		"vmid low":         func(r *ImageVMRequest) { r.VMID = 99 },
		"name":             func(r *ImageVMRequest) { r.Name = "Bad Name" },
		"name empty":       func(r *ImageVMRequest) { r.Name = "" },
		"storage":          func(r *ImageVMRequest) { r.Storage = "local:lvm" },
		"import storage":   func(r *ImageVMRequest) { r.ImportStorage = "local,x=1" },
		"filename path":    func(r *ImageVMRequest) { r.ImportFilename = "../x.qcow2" },
		"filename comma":   func(r *ImageVMRequest) { r.ImportFilename = "x,cache=unsafe.qcow2" },
		"filename iso":     func(r *ImageVMRequest) { r.ImportFilename = "x.iso" },
		"filename missing": func(r *ImageVMRequest) { r.ImportFilename = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidCreate)}
			w := newTestWriter(t, f)
			r := okImageVM()
			mut(&r)
			if _, err := w.CreateImageVM(context.Background(), r); !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

func TestCreateImageVMRejectsMismatchedUPID(t *testing.T) {
	for name, upid := range map[string]string{
		"other vmid": strings.Replace(upidCreate, ":9000:", ":9001:", 1),
		"other type": strings.Replace(upidCreate, ":qmcreate:", ":qmclone:", 1),
		"other node": strings.Replace(upidCreate, "UPID:pve1:", "UPID:pve2:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			w := newTestWriter(t, &fakeWriteServer{body: upidBody(upid)})
			_, err := w.CreateImageVM(context.Background(), okImageVM())
			var we *WriteError
			if !errors.As(err, &we) || we.Reason != ReasonSchema {
				t.Fatalf("err = %v, want schema error", err)
			}
		})
	}
}
