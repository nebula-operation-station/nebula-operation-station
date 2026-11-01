// SPDX-License-Identifier: AGPL-3.0-or-later

package pveapi

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Download limits, named next to the code that enforces them.
const (
	// MaxSourceURLBytes bounds a download source URL.
	MaxSourceURLBytes = 2048
	// MaxDownloadFilenameBytes bounds the target file name on the storage.
	MaxDownloadFilenameBytes = 200
)

// Download content types offered by DownloadURL.
const (
	// ContentISO stores the file as an ISO image (".iso").
	ContentISO = "iso"
	// ContentImport stores the file as an importable disk image (PVE 8.4+;
	// ".qcow2", ".raw" or ".vmdk").
	ContentImport = "import"
)

// downloadNameRe allowlists a plain file name without path components.
var downloadNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// DownloadRequest makes PVE fetch a file into a storage
// (POST /nodes/{node}/storage/{storage}/download-url). PVE verifies the
// SHA-256 checksum and the TLS certificate of the source; both are
// mandatory here.
type DownloadRequest struct {
	// Node is the node that downloads.
	Node string
	// Storage is the target storage id.
	Storage string
	// Content is ContentISO or ContentImport.
	Content string
	// Filename is the target file name; its extension must fit Content.
	Filename string
	// SourceURL is the https source, e.g. a vendor cloud-image URL from
	// the signed image catalog. User info, query and fragment are refused.
	// It is a request body value, never part of the API path.
	SourceURL string
	// SHA256 is the expected lowercase or uppercase hex SHA-256 of the file.
	SHA256 string
}

// DownloadURL starts a storage download and returns the UPID of the
// download task.
func (w *Writer) DownloadURL(ctx context.Context, r DownloadRequest) (string, error) {
	const op = "download-url"
	if validNodeName(r.Node) != nil {
		return "", invalid(op, "node")
	}
	if validStorageID(r.Storage) != nil {
		return "", invalid(op, "storage")
	}
	if !validDownloadName(r.Content, r.Filename) {
		return "", invalid(op, "content/filename")
	}
	if !validSourceURL(r.SourceURL) {
		return "", invalid(op, "url")
	}
	sum, err := hex.DecodeString(r.SHA256)
	if err != nil || len(sum) != 32 {
		return "", invalid(op, "checksum")
	}
	form := url.Values{
		"content":             {r.Content},
		"filename":            {r.Filename},
		"url":                 {r.SourceURL},
		"checksum":            {hex.EncodeToString(sum)},
		"checksum-algorithm":  {"sha256"},
		"verify-certificates": {"1"},
	}
	path := "/nodes/" + url.PathEscape(r.Node) + "/storage/" + url.PathEscape(r.Storage) + "/download-url"
	return w.dispatch(ctx, writeRequest{op: op, method: http.MethodPost, path: path, form: form},
		r.Node, "download", r.Filename)
}

// validDownloadName checks the content type and that the file name is a
// plain name with an extension matching it.
func validDownloadName(content, name string) bool {
	if len(name) > MaxDownloadFilenameBytes || !downloadNameRe.MatchString(name) || strings.Contains(name, "..") {
		return false
	}
	var exts []string
	switch content {
	case ContentISO:
		exts = []string{".iso"}
	case ContentImport:
		exts = []string{".qcow2", ".raw", ".vmdk"}
	default:
		return false
	}
	for _, e := range exts {
		if strings.HasSuffix(name, e) && len(name) > len(e) {
			return true
		}
	}
	return false
}

// validSourceURL accepts an absolute https URL with a host, without user
// info, query or fragment, of printable ASCII only.
func validSourceURL(s string) bool {
	if s == "" || len(s) > MaxSourceURLBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7F {
			return false
		}
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Opaque == "" &&
		!u.ForceQuery && u.RawQuery == "" && u.Fragment == "" && !strings.Contains(s, "#")
}
