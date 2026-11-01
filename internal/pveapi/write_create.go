// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// Fixed hardware of a VM created from an image (CreateImageVM). It is the
// smallest preset (ADR 0008 section 1, size S); provisioning sets the real
// size on each clone.
const (
	imageVMCores     = 1
	imageVMMemoryMiB = 1024
)

// ImageVMRequest creates a QEMU guest from an imported disk image for
// template preparation (POST /nodes/{node}/qemu, ADR 0008 section 2): the
// image becomes scsi0, a cloud-init drive is attached as ide2, the QEMU
// guest agent option is enabled (agent=1) and the console is serial. No
// other configuration can be set through this call.
type ImageVMRequest struct {
	// Node is the node that creates the guest.
	Node string
	// VMID is the VMID of the new guest.
	VMID int64
	// Name is the guest name (a DNS name), required.
	Name string
	// Storage holds the guest disk and the cloud-init drive.
	Storage string
	// ImportStorage and ImportFilename name the imported image, as
	// DownloadURL stored it with ContentImport.
	ImportStorage  string
	ImportFilename string
}

// CreateImageVM creates the guest and returns the UPID of the qmcreate
// task.
func (w *Writer) CreateImageVM(ctx context.Context, r ImageVMRequest) (string, error) {
	const op = "create"
	if validNodeName(r.Node) != nil {
		return "", invalid(op, "node")
	}
	if validVMID(r.VMID) != nil {
		return "", invalid(op, "vmid")
	}
	if !validDNSName(r.Name) {
		return "", invalid(op, "name")
	}
	if validStorageID(r.Storage) != nil {
		return "", invalid(op, "storage")
	}
	if validStorageID(r.ImportStorage) != nil {
		return "", invalid(op, "import storage")
	}
	if !validDownloadName(ContentImport, r.ImportFilename) {
		return "", invalid(op, "import filename")
	}
	vmid := strconv.FormatInt(r.VMID, 10)
	form := url.Values{
		"vmid":    {vmid},
		"name":    {r.Name},
		"ostype":  {"l26"},
		"cores":   {strconv.Itoa(imageVMCores)},
		"memory":  {strconv.Itoa(imageVMMemoryMiB)},
		"scsihw":  {"virtio-scsi-single"},
		"scsi0":   {r.Storage + ":0,import-from=" + r.ImportStorage + ":import/" + r.ImportFilename},
		"ide2":    {r.Storage + ":cloudinit"},
		"boot":    {"order=scsi0"},
		"serial0": {"socket"},
		"vga":     {"serial0"},
		"agent":   {"enabled=1"},
	}
	path := "/nodes/" + url.PathEscape(r.Node) + "/qemu"
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path, form: form}, r.Node, "qmcreate", vmid)
}
