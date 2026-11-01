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

const (
	testImageURL = "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"
	testSHA256   = "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"
)

func okDownload() DownloadRequest {
	return DownloadRequest{
		Node: "pve1", Storage: "local", Content: ContentImport, Filename: "jammy.qcow2",
		SourceURL: testImageURL, SHA256: testSHA256,
	}
}

func TestDownloadURLSendsChecksumAndVerification(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(upidDownload)}
	w := newTestWriter(t, f)
	got, err := w.DownloadURL(context.Background(), okDownload())
	if err != nil || got != upidDownload {
		t.Fatalf("DownloadURL = %q, %v", got, err)
	}
	r := f.only(t)
	if r.method != http.MethodPost || r.path != "/api2/json/nodes/pve1/storage/local/download-url" {
		t.Errorf("request = %s %s", r.method, r.path)
	}
	want := url.Values{
		"content":             {"import"},
		"filename":            {"jammy.qcow2"},
		"url":                 {testImageURL},
		"checksum":            {strings.ToLower(testSHA256)},
		"checksum-algorithm":  {"sha256"},
		"verify-certificates": {"1"},
	}
	if r.form.Encode() != want.Encode() {
		t.Errorf("form = %v, want %v", r.form, want)
	}
}

func TestDownloadURLISO(t *testing.T) {
	f := &fakeWriteServer{body: upidBody(strings.Replace(upidDownload, "jammy.qcow2", "debian.iso", 1))}
	w := newTestWriter(t, f)
	r := okDownload()
	r.Content, r.Filename = ContentISO, "debian.iso"
	if _, err := w.DownloadURL(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadURLRejectsInvalidArguments(t *testing.T) {
	cases := map[string]func(*DownloadRequest){
		"node":              func(r *DownloadRequest) { r.Node = "pve1/../x" },
		"storage":           func(r *DownloadRequest) { r.Storage = "local/../etc" },
		"content":           func(r *DownloadRequest) { r.Content = "vztmpl" },
		"content empty":     func(r *DownloadRequest) { r.Content = "" },
		"filename slash":    func(r *DownloadRequest) { r.Filename = "../jammy.qcow2" },
		"filename dotdot":   func(r *DownloadRequest) { r.Filename = "a..qcow2" },
		"filename ext":      func(r *DownloadRequest) { r.Filename = "jammy.img" },
		"filename iso ext":  func(r *DownloadRequest) { r.Filename = "jammy.iso" },
		"filename bare ext": func(r *DownloadRequest) { r.Filename = ".qcow2" },
		"filename long":     func(r *DownloadRequest) { r.Filename = strings.Repeat("a", MaxDownloadFilenameBytes) + ".qcow2" },
		"url http":          func(r *DownloadRequest) { r.SourceURL = "http://example.com/a.img" },
		"url file":          func(r *DownloadRequest) { r.SourceURL = "file:///etc/shadow" },
		"url relative":      func(r *DownloadRequest) { r.SourceURL = "/a.img" },
		"url userinfo":      func(r *DownloadRequest) { r.SourceURL = "https://user:pw@example.com/a.img" },
		"url query":         func(r *DownloadRequest) { r.SourceURL = "https://example.com/a.img?token=x" },
		"url empty query":   func(r *DownloadRequest) { r.SourceURL = "https://example.com/a.img?" },
		"url fragment":      func(r *DownloadRequest) { r.SourceURL = "https://example.com/a.img#x" },
		"url space":         func(r *DownloadRequest) { r.SourceURL = "https://example.com/a b.img" },
		"url newline":       func(r *DownloadRequest) { r.SourceURL = "https://example.com/a\n.img" },
		"url no host":       func(r *DownloadRequest) { r.SourceURL = "https:///a.img" },
		"url port only":     func(r *DownloadRequest) { r.SourceURL = "https://:443/a.img" },
		"url long": func(r *DownloadRequest) {
			r.SourceURL = "https://example.com/" + strings.Repeat("a", MaxSourceURLBytes)
		},
		"checksum missing":   func(r *DownloadRequest) { r.SHA256 = "" },
		"checksum short":     func(r *DownloadRequest) { r.SHA256 = testSHA256[:62] },
		"checksum not hex":   func(r *DownloadRequest) { r.SHA256 = strings.Repeat("z", 64) },
		"checksum md5 sized": func(r *DownloadRequest) { r.SHA256 = testSHA256[:32] },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeWriteServer{body: upidBody(upidDownload)}
			w := newTestWriter(t, f)
			r := okDownload()
			mut(&r)
			_, err := w.DownloadURL(context.Background(), r)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
			if strings.Contains(err.Error(), "example.com") || strings.Contains(err.Error(), "pw@") {
				t.Errorf("error echoes the URL: %v", err)
			}
			if f.count() != 0 {
				t.Error("invalid request reached the server")
			}
		})
	}
}

func TestDownloadURLRejectsMismatchedUPID(t *testing.T) {
	for name, upid := range map[string]string{
		"other file": strings.Replace(upidDownload, "jammy.qcow2", "other.qcow2", 1),
		"other type": strings.Replace(upidDownload, ":download:", ":imgcopy:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			w := newTestWriter(t, &fakeWriteServer{body: upidBody(upid)})
			_, err := w.DownloadURL(context.Background(), okDownload())
			var we *WriteError
			if !errors.As(err, &we) || we.Reason != ReasonSchema {
				t.Fatalf("err = %v, want schema error", err)
			}
		})
	}
}
