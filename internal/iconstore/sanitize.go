// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iconstore turns untrusted icon uploads into freshly encoded PNG
// files and stores them content-addressed (ADR 0009, TM06).
//
// Sanitize never passes input bytes through: the input type is decided by
// magic bytes only (PNG, JPEG, GIF), header dimensions are checked before
// any pixel is decoded, and the decoded pixels are resampled into new
// 64×64 and 128×128 canvases and encoded as new PNG streams that contain
// only IHDR, IDAT and IEND. Metadata (EXIF, text chunks), trailing data
// and polyglot payloads therefore cannot survive. SVG, WebP, ICO, BMP and
// every other format are rejected. Only the standard library decoders are
// used, and they are called directly rather than through image.Decode, so
// a decoder registered elsewhere in the binary can never be reached.
package iconstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
)

// Limits enforced by Sanitize.
const (
	// MaxInputBytes is the largest accepted upload (256 KiB).
	MaxInputBytes = 256 << 10
	// MaxDimension is the largest accepted width or height in pixels, as
	// declared in the header and as decoded. It bounds decoder memory to
	// about 8 MiB (1024² pixels at 16-bit RGBA).
	MaxDimension = 1024
	// MaxJPEGScans bounds the number of SOS markers in a JPEG. Each scan of
	// a progressive JPEG walks every block, so many tiny scans are a CPU
	// bomb. Counting is conservative: SOS byte pairs inside metadata
	// segments count too.
	MaxJPEGScans = 64
	// SmallSize and LargeSize are the edge lengths of the output icons.
	SmallSize = 64
	LargeSize = 128
)

// Errors returned by Sanitize. All rejections wrap exactly one of them.
var (
	// ErrEmpty means the input has no bytes.
	ErrEmpty = errors.New("iconstore: empty image")
	// ErrTooLarge means the input exceeds MaxInputBytes.
	ErrTooLarge = errors.New("iconstore: image larger than 256 KiB")
	// ErrUnsupportedFormat means the magic bytes are not PNG, JPEG or GIF.
	// The error is a *FormatError naming what was recognised.
	ErrUnsupportedFormat = errors.New("iconstore: unsupported image format")
	// ErrDimensions means a width or height is zero or above MaxDimension.
	ErrDimensions = errors.New("iconstore: image dimensions out of range")
	// ErrMalformed means the image could not be parsed or decoded.
	ErrMalformed = errors.New("iconstore: malformed image")
)

// FormatError reports a rejected input format. It wraps
// ErrUnsupportedFormat.
type FormatError struct {
	// Kind is a fixed label, never derived from input text: "svg" (markup
	// of any kind), "webp", "ico", "bmp" or "unknown".
	Kind string
}

// Error implements error.
func (e *FormatError) Error() string {
	return fmt.Sprintf("%v: %s", ErrUnsupportedFormat, e.Kind)
}

// Unwrap returns ErrUnsupportedFormat.
func (e *FormatError) Unwrap() error { return ErrUnsupportedFormat }

// Icon is a sanitized icon in both output sizes.
type Icon struct {
	// SHA256 is the lowercase hex SHA-256 of PNG128; it is the content
	// address used by Store.
	SHA256 string
	// PNG64 is the 64×64 PNG encoding.
	PNG64 []byte
	// PNG128 is the 128×128 PNG encoding.
	PNG128 []byte
}

type format int

const (
	formatPNG format = iota + 1
	formatJPEG
	formatGIF
)

func (f format) String() string {
	switch f {
	case formatPNG:
		return "png"
	case formatJPEG:
		return "jpeg"
	case formatGIF:
		return "gif"
	}
	return "unknown"
}

var (
	pngMagic  = []byte("\x89PNG\r\n\x1a\n")
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
	gif87     = []byte("GIF87a")
	gif89     = []byte("GIF89a")
)

// markupScanBytes is how much of a rejected input is searched for markup
// markers when labelling the rejection.
const markupScanBytes = 1024

// detect decides the format from magic bytes alone.
func detect(b []byte) (format, error) {
	switch {
	case bytes.HasPrefix(b, pngMagic):
		return formatPNG, nil
	case bytes.HasPrefix(b, jpegMagic):
		return formatJPEG, nil
	case bytes.HasPrefix(b, gif87), bytes.HasPrefix(b, gif89):
		return formatGIF, nil
	}
	return 0, &FormatError{Kind: rejectKind(b)}
}

// rejectKind labels an input that is not PNG, JPEG or GIF. The label only
// improves the error; every such input is rejected regardless.
func rejectKind(b []byte) string {
	switch {
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return "webp"
	case len(b) >= 4 && b[0] == 0 && b[1] == 0 && (b[2] == 1 || b[2] == 2) && b[3] == 0:
		return "ico"
	case bytes.HasPrefix(b, []byte("BM")):
		return "bmp"
	case looksLikeMarkup(b):
		return "svg"
	}
	return "unknown"
}

// looksLikeMarkup reports whether b starts like SVG, XML or HTML, after an
// optional byte-order mark and whitespace, or carries an svg/xml marker
// near the start.
func looksLikeMarkup(b []byte) bool {
	for _, bom := range [][]byte{{0xEF, 0xBB, 0xBF}, {0xFF, 0xFE}, {0xFE, 0xFF}} {
		if bytes.HasPrefix(b, bom) {
			b = b[len(bom):]
			break
		}
	}
	// UTF-16 interleaves NUL bytes; drop them for the check.
	head := b[:min(len(b), markupScanBytes)]
	head = bytes.ReplaceAll(head, []byte{0}, nil)
	trimmed := bytes.TrimLeft(head, " \t\r\n\f")
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return true
	}
	lower := bytes.ToLower(head)
	return bytes.Contains(lower, []byte("<svg")) || bytes.Contains(lower, []byte("<?xml"))
}

// Sanitize validates an untrusted image and re-encodes it as 64×64 and
// 128×128 PNG icons (aspect ratio kept, transparent padding). On error the
// returned Icon is the zero value.
func Sanitize(input []byte) (Icon, error) {
	if len(input) == 0 {
		return Icon{}, ErrEmpty
	}
	if len(input) > MaxInputBytes {
		return Icon{}, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(input))
	}
	f, err := detect(input)
	if err != nil {
		return Icon{}, err
	}
	src, err := decode(f, input)
	if err != nil {
		return Icon{}, err
	}
	rgba := toRGBA(src)
	small, err := encodeIcon(fit(rgba, SmallSize))
	if err != nil {
		return Icon{}, err
	}
	large, err := encodeIcon(fit(rgba, LargeSize))
	if err != nil {
		return Icon{}, err
	}
	sum := sha256.Sum256(large)
	return Icon{SHA256: hex.EncodeToString(sum[:]), PNG64: small, PNG128: large}, nil
}

// decode checks the header dimensions and only then decodes the pixels.
func decode(f format, input []byte) (image.Image, error) {
	var (
		cfg image.Config
		err error
	)
	switch f {
	case formatPNG:
		cfg, err = png.DecodeConfig(bytes.NewReader(input))
	case formatJPEG:
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(input))
	case formatGIF:
		cfg, err = gif.DecodeConfig(bytes.NewReader(input))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s header: %w", ErrMalformed, f, err)
	}
	if err := checkDimensions(cfg.Width, cfg.Height); err != nil {
		return nil, fmt.Errorf("%s header: %w", f, err)
	}
	if f == formatJPEG {
		if n := bytes.Count(input, []byte{0xFF, 0xDA}); n > MaxJPEGScans {
			return nil, fmt.Errorf("%w: jpeg has %d scan markers, limit %d", ErrMalformed, n, MaxJPEGScans)
		}
	}

	var m image.Image
	switch f {
	case formatPNG:
		m, err = png.Decode(bytes.NewReader(input))
	case formatJPEG:
		m, err = jpeg.Decode(bytes.NewReader(input))
	case formatGIF:
		// gif.Decode stops after the first frame and rejects frames that
		// extend beyond the logical screen checked above.
		m, err = gif.Decode(bytes.NewReader(input))
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrMalformed, f, err)
	}
	b := m.Bounds()
	if err := checkDimensions(b.Dx(), b.Dy()); err != nil {
		return nil, fmt.Errorf("%s pixels: %w", f, err)
	}
	return m, nil
}

func checkDimensions(w, h int) error {
	if w <= 0 || h <= 0 || w > MaxDimension || h > MaxDimension {
		return fmt.Errorf("%w: %dx%d, limit %dx%d", ErrDimensions, w, h, MaxDimension, MaxDimension)
	}
	return nil
}

func encodeIcon(m image.Image) ([]byte, error) {
	var b bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&b, m); err != nil {
		return nil, fmt.Errorf("encode png: %w", err)
	}
	return b.Bytes(), nil
}
