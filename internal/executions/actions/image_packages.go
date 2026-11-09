// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
)

// imagePackages is image.packages 1.0.0 (ADR 0011 D3, VU-06): the package
// list of one local image digest from the host's own Trivy, reduced on the
// host to the fields dockerhost.ParseImagePackages judges.
//
//go:embed scripts/image_packages.sh
var imagePackages []byte

// ImagePackagesFormat is the format of an image.packages result.
const ImagePackagesFormat = "image-packages-v1"

// ReasonImageNotLocal is the reason of an image.packages read whose image
// is not present on the host: it is never fetched, so its packages are
// unknown. It never contains host data.
const ReasonImageNotLocal = "image_not_local"

// maxImagePackagesResult bounds the result document ParseImagePackagesResult
// accepts; it equals the attached-run result limit (hostrun.MaxResult).
const maxImagePackagesResult = 1 << 20

// imagePackagesFrame is the image.packages result document. Report is the
// reduced Trivy report, passed to dockerhost.ParseImagePackages as is.
type imagePackagesFrame struct {
	Format  string          `json:"format"`
	Phase   string          `json:"phase"`
	Image   string          `json:"image"`
	Status  string          `json:"status"`
	Present *bool           `json:"present"`
	RC      *int            `json:"rc"`
	Output  string          `json:"output"`
	Report  json.RawMessage `json:"report"`
}

// ParseImagePackagesResult parses the result of an image.packages run for
// the requested image digest reference. The result is untrusted host data:
// a malformed result, one for another image, a missing image or an absent
// Trivy is an unknown read (Known false), never an empty one; a reduced
// Trivy report is judged by dockerhost.ParseImagePackages, which alone
// decides whether the read is complete. The only error is an invalid
// requested digest (dockerhost.ErrImagePackagesDigest).
func ParseImagePackagesResult(digest string, result []byte) (dockerhost.ImagePackages, error) {
	absent, err := dockerhost.ParseImagePackages(digest, dockerhost.TrivyPackagesRun{})
	if err != nil {
		return dockerhost.ImagePackages{}, fmt.Errorf("parse image.packages result: %w", err)
	}
	unknown := dockerhost.ImagePackages{Digest: digest, Reason: dockerhost.ReasonUnparseable}
	f, ok := decodeImagePackagesFrame(digest, result)
	if !ok {
		return unknown, nil
	}
	switch f.Status {
	case "absent":
		if *f.Present || f.RC != nil || f.Output != "" || f.Report != nil {
			return unknown, nil
		}
		return absent, nil
	case "notlocal":
		if f.Present != nil || f.RC != nil || f.Output != "" || f.Report != nil {
			return unknown, nil
		}
		return dockerhost.ImagePackages{Digest: digest, Reason: ReasonImageNotLocal}, nil
	case "ok":
		if !*f.Present {
			return unknown, nil
		}
		run := dockerhost.TrivyPackagesRun{Present: true}
		if f.RC != nil {
			run.ExitCode = *f.RC
		}
		switch f.Output {
		case "ok":
			if f.RC == nil || f.Report == nil || bytes.Equal(f.Report, []byte("null")) {
				return unknown, nil
			}
			run.Output = f.Report
		case "truncated", "unparseable", "toolarge":
			if f.Report != nil {
				return unknown, nil
			}
		default:
			return unknown, nil
		}
		return dockerhost.ParseImagePackages(digest, run)
	}
	return unknown, nil
}

// decodeImagePackagesFrame decodes one bounded, valid UTF-8 result
// document for digest. Decode errors are discarded: they can quote host
// bytes.
func decodeImagePackagesFrame(digest string, result []byte) (imagePackagesFrame, bool) {
	var f imagePackagesFrame
	if len(result) == 0 || len(result) > maxImagePackagesResult || !utf8.Valid(result) {
		return f, false
	}
	dec := json.NewDecoder(bytes.NewReader(result))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return f, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return f, false // trailing data
	}
	switch {
	case f.Format != ImagePackagesFormat, f.Phase != "done", f.Image != digest:
		return f, false
	case f.Status != "notlocal" && f.Present == nil:
		return f, false
	}
	return f, true
}
