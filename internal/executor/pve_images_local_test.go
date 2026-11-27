// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	localTestServerUID uint32 = 51001
	localTestAdminUID  uint32 = 51002
	localTestCollUID   uint32 = 51003
)

func localRocky() release.Image {
	return release.Image{ID: imgLocalID, OS: "rocky", Release: "9", Arch: "amd64", URL: imgLocalURL, SHA256: imgLocalSHA, DiskFormat: "qcow2"}
}

func localRockyProto() *pb.PVECatalogImage {
	return &pb.PVECatalogImage{Id: imgLocalID, Os: "rocky", Release: "9", Arch: "amd64", Url: imgLocalURL, Sha256: imgLocalSHA, DiskFormat: "qcow2"}
}

// localImagesEnv is a Service with a state directory, so its one
// provisioner (and image catalog) is the production wiring.
type localImagesEnv struct {
	svc  *Service
	dir  string
	logs *syncBuffer
}

func newLocalImagesEnv(t *testing.T) *localImagesEnv {
	t.Helper()
	logs := &syncBuffer{}
	dir := t.TempDir()
	svc := &Service{log: slog.New(slog.NewJSONHandler(logs, nil))}
	svc.SetBackupDirs(dir, filepath.Join(dir, "keys"))
	return &localImagesEnv{svc: svc, dir: dir, logs: logs}
}

func (e *localImagesEnv) catalog(t *testing.T) *PveImageCatalog {
	t.Helper()
	p := e.svc.pveProvisioner()
	if p == nil || p.Images == nil || p.Images.Catalog == nil {
		t.Fatal("no production image catalog")
	}
	return p.Images.Catalog
}

// call runs handler as the RPC method would run behind the executor's
// peer-credential policy for uid. methodRoles overrides the role table
// (nil: the production MethodRoles), to show the handler's own check.
func call[Req, Resp any](uid uint32, method string, methodRoles map[string][]peercred.Role, handler func(context.Context, Req) (Resp, error), in Req) (Resp, bool, error) {
	if methodRoles == nil {
		methodRoles = MethodRoles()
	}
	policy := peercred.NewPolicy(map[uint32][]peercred.Role{
		localTestServerUID: {peercred.RoleServer},
		localTestAdminUID:  {peercred.RoleAdmin},
		localTestCollUID:   {peercred.RolePVECollector},
	}, methodRoles)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: peercred.AuthInfo{UID: uid}})
	reached := false
	out, err := policy.UnaryInterceptor(nil)(ctx, in, &grpc.UnaryServerInfo{FullMethod: method},
		func(ctx context.Context, req any) (any, error) {
			reached = true
			return handler(ctx, req.(Req))
		})
	var resp Resp
	if out != nil {
		resp, _ = out.(Resp)
	}
	return resp, reached, err
}

func (e *localImagesEnv) add(uid uint32, img *pb.PVECatalogImage) (*pb.AddPVELocalImageResponse, bool, error) {
	return call(uid, pb.ExecutorService_AddPVELocalImage_FullMethodName, nil, e.svc.AddPVELocalImage, &pb.AddPVELocalImageRequest{Image: img})
}

func (e *localImagesEnv) remove(uid uint32, id string) (*pb.RemovePVELocalImageResponse, bool, error) {
	return call(uid, pb.ExecutorService_RemovePVELocalImage_FullMethodName, nil, e.svc.RemovePVELocalImage, &pb.RemovePVELocalImageRequest{ImageId: id})
}

func (e *localImagesEnv) list(uid uint32) (*pb.ListPVEImagesResponse, bool, error) {
	return call(uid, pb.ExecutorService_ListPVEImages_FullMethodName, nil, e.svc.ListPVEImages, &pb.ListPVEImagesRequest{})
}

func (e *localImagesEnv) localFile() string { return filepath.Join(e.dir, pveCatalogLocalFile) }

// TestLocalImageSurvivesCatalogRestart: an entry added through the catalog
// is in pve-catalog-local.json (mode 0600) and a new catalog on the same
// file serves it; a removal survives a restart as well.
func TestLocalImageSurvivesCatalogRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), pveCatalogLocalFile)
	newCat := func() *PveImageCatalog { return &PveImageCatalog{Local: &FilePveLocalImages{Path: path}} }

	c := newCat()
	if err := c.AddLocal(localRocky()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("local entries not persisted: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}

	c = newCat()
	if err := c.LoadLocal(); err != nil {
		t.Fatal(err)
	}
	img, ok := c.Lookup(imgLocalID)
	if !ok || img.Image != localRocky() || img.Trust != ImageTrustLocal {
		t.Fatalf("after restart: %+v %v", img, ok)
	}

	if removed, err := c.RemoveLocal(imgLocalID); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	c = newCat()
	if _, ok := c.Lookup(imgLocalID); ok {
		t.Fatal("removed entry back after restart")
	}
}

// TestLocalImageServiceRestart: the same through the Service's wiring:
// an entry added over the RPC is served by a new Service on the same state
// directory.
func TestLocalImageServiceRestart(t *testing.T) {
	e := newLocalImagesEnv(t)
	if _, _, err := e.add(localTestAdminUID, localRockyProto()); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	svc := &Service{log: slog.New(slog.NewJSONHandler(logs, nil))}
	svc.SetBackupDirs(e.dir, filepath.Join(e.dir, "keys"))
	e2 := &localImagesEnv{svc: svc, dir: e.dir, logs: logs}
	if img, ok := e2.catalog(t).Lookup(imgLocalID); !ok || img.Image != localRocky() {
		t.Fatalf("after restart: %+v %v", img, ok)
	}
}

// TestAddPVELocalImageRefusesInvalidEntries: an ID without the local-
// prefix, and every entry that fails release.ValidateImage, is refused
// with InvalidArgument; nothing is persisted and nothing is served.
func TestAddPVELocalImageRefusesInvalidEntries(t *testing.T) {
	mod := func(f func(*pb.PVECatalogImage)) *pb.PVECatalogImage {
		img := localRockyProto()
		f(img)
		return img
	}
	tests := []struct {
		name string
		img  *pb.PVECatalogImage
	}{
		{"no local prefix", mod(func(i *pb.PVECatalogImage) { i.Id = "rocky-9-amd64" })},
		{"signed id", mod(func(i *pb.PVECatalogImage) { i.Id = imgUbuntuID })},
		{"http url", mod(func(i *pb.PVECatalogImage) { i.Url = "http://insecure.example/x.qcow2" })},
		{"url with user info", mod(func(i *pb.PVECatalogImage) { i.Url = "https://u:p@example.org/x.qcow2" })},
		{"url with query", mod(func(i *pb.PVECatalogImage) { i.Url = "https://example.org/x.qcow2?token=x" })},
		{"oversize url", mod(func(i *pb.PVECatalogImage) { i.Url = "https://example.org/" + strings.Repeat("a", release.MaxImageURL) })},
		{"oversize id", mod(func(i *pb.PVECatalogImage) { i.Id = "local-" + strings.Repeat("a", 64) })},
		{"bad sha256", mod(func(i *pb.PVECatalogImage) { i.Sha256 = strings.Repeat("Z", 64) })},
		{"bad arch", mod(func(i *pb.PVECatalogImage) { i.Arch = "mips" })},
		{"bad disk format", mod(func(i *pb.PVECatalogImage) { i.DiskFormat = "vmdk" })},
		{"invalid utf-8 os", mod(func(i *pb.PVECatalogImage) { i.Os = "rocky\xff" })},
		{"dot dot id", mod(func(i *pb.PVECatalogImage) { i.Id = "local-a..b" })},
		{"no image", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newLocalImagesEnv(t)
			_, reached, err := e.add(localTestAdminUID, tc.img)
			if !reached || status.Code(err) != codes.InvalidArgument {
				t.Fatalf("reached %v err %v, want InvalidArgument from the handler", reached, err)
			}
			if _, err := os.Stat(e.localFile()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused entry persisted: %v", err)
			}
			if tc.img != nil {
				if _, ok := e.catalog(t).Lookup(tc.img.GetId()); ok {
					t.Fatal("refused entry served")
				}
			}
			if !strings.Contains(e.logs.String(), `"kind":"pve_local_image_refused"`) {
				t.Fatalf("no refusal audit: %s", e.logs.String())
			}
		})
	}
}

// TestAddPVELocalImagePersistsAndAudits: an admin's entry is validated,
// persisted, served with trust "local" and audited with the caller.
func TestAddPVELocalImagePersistsAndAudits(t *testing.T) {
	e := newLocalImagesEnv(t)
	if _, reached, err := e.add(localTestAdminUID, localRockyProto()); err != nil || !reached {
		t.Fatalf("add: %v %v", reached, err)
	}
	if _, err := os.Stat(e.localFile()); err != nil {
		t.Fatalf("not persisted: %v", err)
	}
	img, ok := e.catalog(t).Lookup(imgLocalID)
	if !ok || img.Trust != ImageTrustLocal || img.SHA256 != imgLocalSHA {
		t.Fatalf("lookup: %+v %v", img, ok)
	}
	logs := e.logs.String()
	want := fmt.Sprintf(`"by":"admin:uid%d"`, localTestAdminUID)
	if !strings.Contains(logs, `"kind":"pve_local_image_added"`) || !strings.Contains(logs, want) || !strings.Contains(logs, imgLocalSHA) {
		t.Fatalf("audit line missing: %s", logs)
	}

	res, _, err := e.remove(localTestAdminUID, imgLocalID)
	if err != nil || !res.GetRemoved() {
		t.Fatalf("remove: %+v %v", res, err)
	}
	if _, ok := e.catalog(t).Lookup(imgLocalID); ok {
		t.Fatal("removed entry still served")
	}
	if !strings.Contains(e.logs.String(), `"kind":"pve_local_image_removed"`) {
		t.Fatalf("no removal audit: %s", e.logs.String())
	}
	res, _, err = e.remove(localTestAdminUID, imgLocalID)
	if err != nil || res.GetRemoved() {
		t.Fatalf("remove again: %+v %v", res, err)
	}
}

// TestRemovePVELocalImageRefusesNonLocalID: a signed or malformed ID is
// refused; the signed catalog is never touched by the local RPCs.
func TestRemovePVELocalImageRefusesNonLocalID(t *testing.T) {
	e := newLocalImagesEnv(t)
	for _, id := range []string{imgUbuntuID, "", "local-" + strings.Repeat("a", 64), "local-\xff"} {
		if _, reached, err := e.remove(localTestAdminUID, id); !reached || status.Code(err) != codes.InvalidArgument {
			t.Fatalf("remove %q: reached %v err %v, want InvalidArgument", id, reached, err)
		}
	}
}

// TestLocalImageLimit: at most maxPveLocalImages entries; the next new one
// is refused, a replacement of an existing one is not.
func TestLocalImageLimit(t *testing.T) {
	e := newLocalImagesEnv(t)
	for i := range maxPveLocalImages {
		img := localRockyProto()
		img.Id = fmt.Sprintf("local-img-%d", i)
		if _, _, err := e.add(localTestAdminUID, img); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	img := localRockyProto()
	img.Id = "local-one-too-many"
	if _, _, err := e.add(localTestAdminUID, img); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over limit: %v, want ResourceExhausted", err)
	}
	img.Id = "local-img-0"
	img.Release = "10"
	if _, _, err := e.add(localTestAdminUID, img); err != nil {
		t.Fatalf("replace at limit: %v", err)
	}
}

// TestLocalImageRPCsRefuseServerRole: D3 (a). The server role is refused by
// the role table before the handler runs, and the handler refuses it on its
// own even if the role table allowed it.
func TestLocalImageRPCsRefuseServerRole(t *testing.T) {
	e := newLocalImagesEnv(t)
	if _, reached, err := e.add(localTestServerUID, localRockyProto()); reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server add: reached %v err %v", reached, err)
	}
	if _, reached, err := e.remove(localTestServerUID, imgLocalID); reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("server remove: reached %v err %v", reached, err)
	}

	wide := MethodRoles()
	addM, rmM := pb.ExecutorService_AddPVELocalImage_FullMethodName, pb.ExecutorService_RemovePVELocalImage_FullMethodName
	wide[addM] = []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector}
	wide[rmM] = wide[addM]
	for _, uid := range []uint32{localTestServerUID, localTestCollUID} {
		if _, reached, err := call(uid, addM, wide, e.svc.AddPVELocalImage, &pb.AddPVELocalImageRequest{Image: localRockyProto()}); !reached || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("uid %d add past a wide role table: reached %v err %v", uid, reached, err)
		}
		if _, reached, err := call(uid, rmM, wide, e.svc.RemovePVELocalImage, &pb.RemovePVELocalImageRequest{ImageId: imgLocalID}); !reached || status.Code(err) != codes.PermissionDenied {
			t.Fatalf("uid %d remove past a wide role table: reached %v err %v", uid, reached, err)
		}
	}
	// No caller in the context at all.
	if _, err := e.svc.AddPVELocalImage(context.Background(), &pb.AddPVELocalImageRequest{Image: localRockyProto()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no caller: %v", err)
	}
	if _, err := os.Stat(e.localFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused caller persisted an entry: %v", err)
	}
}

// TestListPVEImagesRefusesCollector: D4 (a). The pve-collector gets no
// access to ListPVEImages, by the role table and by the handler.
func TestListPVEImagesRefusesCollector(t *testing.T) {
	e := newLocalImagesEnv(t)
	if _, reached, err := e.list(localTestCollUID); reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector list: reached %v err %v", reached, err)
	}
	wide := MethodRoles()
	m := pb.ExecutorService_ListPVEImages_FullMethodName
	wide[m] = append(wide[m], peercred.RolePVECollector)
	if _, reached, err := call(localTestCollUID, m, wide, e.svc.ListPVEImages, &pb.ListPVEImagesRequest{}); !reached || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("collector list past a wide role table: reached %v err %v", reached, err)
	}
	if _, err := e.svc.ListPVEImages(context.Background(), &pb.ListPVEImagesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("no caller: %v", err)
	}
}

// TestListPVEImagesShowsCatalogAndRecords: server and admin see the signed
// and local entries with their trust and the template records with VMID,
// generation and source digest, and nothing else.
func TestListPVEImagesShowsCatalogAndRecords(t *testing.T) {
	e := newLocalImagesEnv(t)
	cat := e.catalog(t)
	sk := newReleaseSK(t)
	raw := catalogDoc(t, 3, ubuntuEntry(imgUbuntuSHA))
	if err := cat.LoadSigned([]release.Root{sk.root()}, raw, sk.sign(t, raw)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.add(localTestAdminUID, localRockyProto()); err != nil {
		t.Fatal(err)
	}
	prepared := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	rec := PveTemplateRecord{
		PveTemplateKey: PveTemplateKey{RemoteID: "pve-a", Node: "n1", Storage: "local-lvm", ImageID: imgUbuntuID},
		Trust:          ImageTrustSigned, VMID: 9000, Generation: 2, SourceSHA256: imgUbuntuSHA,
		ConfigDigest: strings.Repeat("e1", 32), TrustGeneration: 4, ExecutionID: "00000000-0000-4000-b000-000000000001", PreparedAt: prepared,
	}
	store := &FilePveTemplateStore{Path: filepath.Join(e.dir, pveTemplatesFile)}
	if err := store.PutPveTemplate(rec); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}

	for _, uid := range []uint32{localTestAdminUID, localTestServerUID} {
		res, reached, err := e.list(uid)
		if err != nil || !reached {
			t.Fatalf("uid %d: %v %v", uid, reached, err)
		}
		if res.GetCatalogSequence() != 3 || !validHexDigest(res.GetCatalogDigest()) {
			t.Fatalf("catalog %d %q", res.GetCatalogSequence(), res.GetCatalogDigest())
		}
		if len(res.GetImages()) != 2 {
			t.Fatalf("images %v", res.GetImages())
		}
		signed, local := res.GetImages()[0], res.GetImages()[1]
		if signed.GetImage().GetId() != imgUbuntuID || signed.GetTrust() != string(ImageTrustSigned) || signed.GetCatalogSequence() != 3 ||
			signed.GetCatalogDigest() != res.GetCatalogDigest() || signed.GetImage().GetSha256() != imgUbuntuSHA || signed.GetImage().GetUrl() != imgUbuntuURL {
			t.Fatalf("signed entry %v", signed)
		}
		if local.GetImage().GetId() != imgLocalID || local.GetTrust() != string(ImageTrustLocal) || local.GetCatalogSequence() != 0 ||
			local.GetCatalogDigest() != "" || local.GetImage().GetSha256() != imgLocalSHA || local.GetImage().GetDiskFormat() != "qcow2" {
			t.Fatalf("local entry %v", local)
		}
		if len(res.GetTemplates()) != 1 {
			t.Fatalf("templates %v", res.GetTemplates())
		}
		got := res.GetTemplates()[0]
		if got.GetRemoteId() != "pve-a" || got.GetNode() != "n1" || got.GetStorage() != "local-lvm" || got.GetImageId() != imgUbuntuID ||
			got.GetTrust() != "signed" || got.GetVmid() != 9000 || got.GetGeneration() != 2 || got.GetSourceSha256() != imgUbuntuSHA ||
			got.GetConfigDigest() != rec.ConfigDigest || got.GetTrustGeneration() != 4 || got.GetExecutionId() != rec.ExecutionID ||
			got.GetPreparedAtUnix() != prepared.Unix() {
			t.Fatalf("record %v", got)
		}
	}
	after, err := os.ReadFile(store.Path)
	if err != nil || string(after) != string(before) {
		t.Fatalf("list changed the template records: %v", err)
	}
}

// TestListPVEImagesEmpty: no catalog, no local entries and no records list
// as empty, not as an error.
func TestListPVEImagesEmpty(t *testing.T) {
	e := newLocalImagesEnv(t)
	res, _, err := e.list(localTestAdminUID)
	if err != nil || res.GetCatalogSequence() != 0 || res.GetCatalogDigest() != "" || len(res.GetImages()) != 0 || len(res.GetTemplates()) != 0 {
		t.Fatalf("empty list: %v %v", res, err)
	}
}

// TestLocalImageCorruptFileFailsClosed: an unreadable local-entry file
// serves no local entry, refuses add and remove without overwriting it, and
// fails the list instead of hiding the entries.
func TestLocalImageCorruptFileFailsClosed(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":        "{not json",
		"unknown field":  `{"format":"nebula-local-images-v1","images":[],"extra":1}`,
		"wrong format":   `{"format":"other","images":[]}`,
		"trailing data":  `{"format":"nebula-local-images-v1","images":[]} {}`,
		"signed id":      `{"format":"nebula-local-images-v1","images":[{"id":"ubuntu-24.04-amd64","os":"ubuntu","release":"24.04","arch":"amd64","url":"https://example.org/x.img","sha256":"` + imgUbuntuSHA + `","disk_format":"qcow2"}]}`,
		"duplicate id":   `{"format":"nebula-local-images-v1","images":[` + localJSON("local-a") + `,` + localJSON("local-a") + `]}`,
		"oversize":       `{"format":"nebula-local-images-v1","images":[],"pad":"` + strings.Repeat("x", maxPveLocalImageFile) + `"}`,
		"too many items": localFileWith(maxPveLocalImages + 1),
	} {
		t.Run(name, func(t *testing.T) {
			e := newLocalImagesEnv(t)
			if err := os.WriteFile(e.localFile(), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			e2 := newLocalImagesEnv(t)
			e2.dir = e.dir
			e2.svc.SetBackupDirs(e.dir, filepath.Join(e.dir, "keys"))
			if _, ok := e2.catalog(t).Lookup("local-a"); ok {
				t.Fatal("entry served from a corrupt file")
			}
			if _, _, err := e2.add(localTestAdminUID, localRockyProto()); status.Code(err) != codes.Unavailable {
				t.Fatalf("add over a corrupt file: %v, want Unavailable", err)
			}
			if _, _, err := e2.remove(localTestAdminUID, "local-a"); status.Code(err) != codes.Unavailable {
				t.Fatalf("remove over a corrupt file: %v, want Unavailable", err)
			}
			if _, _, err := e2.list(localTestAdminUID); status.Code(err) != codes.Unavailable {
				t.Fatalf("list over a corrupt file: %v, want Unavailable", err)
			}
			got, err := os.ReadFile(e.localFile())
			if err != nil || string(got) != content {
				t.Fatalf("corrupt file overwritten: %v", err)
			}
		})
	}
}

func localJSON(id string) string {
	return `{"id":"` + id + `","os":"rocky","release":"9","arch":"amd64","url":"` + imgLocalURL + `","sha256":"` + imgLocalSHA + `","disk_format":"qcow2"}`
}

func localFileWith(n int) string {
	items := make([]string, 0, n)
	for i := range n {
		items = append(items, localJSON(fmt.Sprintf("local-a%03d", i)))
	}
	return `{"format":"nebula-local-images-v1","images":[` + strings.Join(items, ",") + `]}`
}

// TestPVEImageRPCsWithoutStateDirectory: without a state directory there
// is no catalog to write to; the RPCs fail as a precondition.
func TestPVEImageRPCsWithoutStateDirectory(t *testing.T) {
	svc := &Service{log: slog.New(slog.NewJSONHandler(&syncBuffer{}, nil))}
	e := &localImagesEnv{svc: svc, logs: &syncBuffer{}}
	if _, _, err := e.add(localTestAdminUID, localRockyProto()); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("add: %v", err)
	}
	if _, _, err := e.remove(localTestAdminUID, imgLocalID); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("remove: %v", err)
	}
	if _, _, err := e.list(localTestAdminUID); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("list: %v", err)
	}
}
