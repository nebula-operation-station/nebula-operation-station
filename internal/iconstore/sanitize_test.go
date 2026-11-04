// SPDX-License-Identifier: AGPL-3.0-or-later

package iconstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/color/palette"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

// testImage returns a w×h image with an opaque gradient and a transparent
// corner so that resampling and alpha handling are exercised.
func testImage(w, h int) *image.NRGBA {
	m := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			a := uint8(255)
			if x < w/4 && y < h/4 {
				a = 0
			}
			m.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 255 / w), G: uint8(y * 255 / h), B: 128, A: a})
		}
	}
	return m
}

func encodePNG(t testing.TB, m image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, m); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return b.Bytes()
}

func encodeJPEG(t testing.TB, m image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, m, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatalf("encode jpeg: %v", err)
	}
	return b.Bytes()
}

func encodeGIF(t testing.TB, frames ...image.Image) []byte {
	t.Helper()
	g := &gif.GIF{}
	for _, f := range frames {
		p := image.NewPaletted(f.Bounds(), palette.Plan9)
		for y := f.Bounds().Min.Y; y < f.Bounds().Max.Y; y++ {
			for x := f.Bounds().Min.X; x < f.Bounds().Max.X; x++ {
				p.Set(x, y, f.At(x, y))
			}
		}
		g.Image = append(g.Image, p)
		g.Delay = append(g.Delay, 10)
	}
	var b bytes.Buffer
	if err := gif.EncodeAll(&b, g); err != nil {
		t.Fatalf("encode gif: %v", err)
	}
	return b.Bytes()
}

func solid(w, h int, c color.Color) *image.NRGBA {
	m := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			m.Set(x, y, c)
		}
	}
	return m
}

// pngChunk builds one PNG chunk with a correct CRC.
func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	_ = binary.Write(&b, binary.BigEndian, crc.Sum32())
	return b.Bytes()
}

// pngHeaderOnly returns a PNG signature plus an IHDR claiming w×h RGBA and
// nothing else: DecodeConfig succeeds, a full decode cannot.
func pngHeaderOnly(w, h uint32) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8] = 8 // bit depth
	ihdr[9] = 6 // RGBA
	out := append([]byte(nil), pngMagic...)
	return append(out, pngChunk("IHDR", ihdr)...)
}

// pngChunkTypes lists the chunk types of a PNG stream in order.
func pngChunkTypes(t *testing.T, b []byte) []string {
	t.Helper()
	if !bytes.HasPrefix(b, pngMagic) {
		t.Fatalf("output is not a PNG")
	}
	var types []string
	rest := b[len(pngMagic):]
	for len(rest) > 0 {
		if len(rest) < 12 {
			t.Fatalf("trailing garbage after PNG chunks: %d bytes", len(rest))
		}
		n := int(binary.BigEndian.Uint32(rest))
		if 12+n > len(rest) {
			t.Fatalf("chunk length %d overruns output", n)
		}
		types = append(types, string(rest[4:8]))
		rest = rest[12+n:]
	}
	return types
}

// checkIcon verifies the structural guarantees of every sanitized icon.
func checkIcon(t *testing.T, ic Icon) {
	t.Helper()
	sum := sha256.Sum256(ic.PNG128)
	if ic.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("SHA256 %q does not match PNG128", ic.SHA256)
	}
	for _, c := range []struct {
		data []byte
		size int
	}{{ic.PNG64, 64}, {ic.PNG128, 128}} {
		for _, typ := range pngChunkTypes(t, c.data) {
			switch typ {
			case "IHDR", "IDAT", "IEND":
			default:
				t.Errorf("unexpected chunk %q in %d px output", typ, c.size)
			}
		}
		m, err := png.Decode(bytes.NewReader(c.data))
		if err != nil {
			t.Fatalf("output does not decode: %v", err)
		}
		if b := m.Bounds(); b.Dx() != c.size || b.Dy() != c.size {
			t.Errorf("output size %v, want %dx%d", b, c.size, c.size)
		}
	}
}

func TestSanitizeAcceptsValidImages(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"png square", encodePNG(t, testImage(256, 256))},
		{"png wide", encodePNG(t, testImage(300, 40))},
		{"png tiny upscaled", encodePNG(t, testImage(3, 5))},
		{"png max dimension", encodePNG(t, solid(1024, 1024, color.White))},
		{"png 16 bit", encodePNG(t, image.NewNRGBA64(image.Rect(0, 0, 20, 20)))},
		{"png gray", encodePNG(t, image.NewGray(image.Rect(0, 0, 20, 20)))},
		{"jpeg", encodeJPEG(t, testImage(200, 100))},
		{"jpeg gray", encodeJPEG(t, image.NewGray(image.Rect(0, 0, 33, 77)))},
		{"gif", encodeGIF(t, testImage(48, 48))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ic, err := Sanitize(c.data)
			if err != nil {
				t.Fatalf("Sanitize: %v", err)
			}
			checkIcon(t, ic)
		})
	}
}

func TestSanitizeIsDeterministic(t *testing.T) {
	in := encodePNG(t, testImage(100, 60))
	a, err := Sanitize(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sanitize(in)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 != b.SHA256 || !bytes.Equal(a.PNG64, b.PNG64) || !bytes.Equal(a.PNG128, b.PNG128) {
		t.Fatal("same input produced different output")
	}
}

func TestSanitizeFitsWithTransparentPadding(t *testing.T) {
	// A 200×100 opaque red image fits as 128×64, centred vertically.
	ic, err := Sanitize(encodePNG(t, solid(200, 100, color.NRGBA{R: 255, A: 255})))
	if err != nil {
		t.Fatal(err)
	}
	m, err := png.Decode(bytes.NewReader(ic.PNG128))
	if err != nil {
		t.Fatal(err)
	}
	probe := func(x, y int) color.NRGBA {
		return color.NRGBAModel.Convert(m.At(x, y)).(color.NRGBA)
	}
	if c := probe(64, 5); c.A != 0 {
		t.Errorf("top padding not transparent: %v", c)
	}
	if c := probe(64, 122); c.A != 0 {
		t.Errorf("bottom padding not transparent: %v", c)
	}
	if c := probe(64, 64); c != (color.NRGBA{R: 255, A: 255}) {
		t.Errorf("centre pixel %v, want opaque red", c)
	}
	if c := probe(0, 64); c != (color.NRGBA{R: 255, A: 255}) {
		t.Errorf("left edge pixel %v, want opaque red", c)
	}
}

func TestSanitizeTransparentPixelsDoNotBleed(t *testing.T) {
	// Half fully transparent green, half opaque blue: the transparent colour
	// must not tint the result (premultiplied filtering).
	m := image.NewNRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			if x < 50 {
				m.SetNRGBA(x, y, color.NRGBA{G: 255})
			} else {
				m.SetNRGBA(x, y, color.NRGBA{B: 255, A: 255})
			}
		}
	}
	ic, err := Sanitize(encodePNG(t, m))
	if err != nil {
		t.Fatal(err)
	}
	out, err := png.Decode(bytes.NewReader(ic.PNG128))
	if err != nil {
		t.Fatal(err)
	}
	for x := 0; x < 128; x++ {
		c := color.NRGBAModel.Convert(out.At(x, 64)).(color.NRGBA)
		if c.A != 0 && c.G != 0 {
			t.Fatalf("pixel %d bled transparent green: %v", x, c)
		}
	}
}

func TestSanitizeStripsPolyglotPayloads(t *testing.T) {
	base := encodePNG(t, testImage(40, 40))
	zipPayload := append([]byte("PK\x03\x04"), []byte("ZIP-PAYLOAD-MARKER evil.sh")...)
	htmlPayload := []byte("<html><script>alert('HTML-PAYLOAD-MARKER')</script></html>")

	// Text chunk with markup inserted after IHDR.
	ihdrEnd := len(pngMagic) + 12 + 13
	withText := append([]byte(nil), base[:ihdrEnd]...)
	withText = append(withText, pngChunk("tEXt", []byte("Comment\x00<svg onload=alert('TEXT-CHUNK-MARKER')>"))...)
	withText = append(withText, base[ihdrEnd:]...)

	cases := []struct {
		name, marker string
		data         []byte
	}{
		{"png trailing zip", "ZIP-PAYLOAD-MARKER", append(append([]byte(nil), base...), zipPayload...)},
		{"png trailing html", "HTML-PAYLOAD-MARKER", append(append([]byte(nil), base...), htmlPayload...)},
		{"png text chunk", "TEXT-CHUNK-MARKER", withText},
		{"jpeg trailing html", "HTML-PAYLOAD-MARKER", append(encodeJPEG(t, testImage(40, 40)), htmlPayload...)},
		{"gif trailing zip", "ZIP-PAYLOAD-MARKER", append(encodeGIF(t, testImage(40, 40)), zipPayload...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ic, err := Sanitize(c.data)
			if err != nil {
				t.Fatalf("Sanitize: %v", err)
			}
			checkIcon(t, ic)
			for _, out := range [][]byte{ic.PNG64, ic.PNG128} {
				if bytes.Contains(out, []byte(c.marker)) || bytes.Contains(out, []byte("PK\x03\x04")) {
					t.Fatalf("output still carries the payload")
				}
			}
		})
	}
}

func TestSanitizeStripsJPEGExif(t *testing.T) {
	plain := encodeJPEG(t, testImage(64, 48))
	// APP1 Exif segment with a little-endian TIFF header and a marker
	// string standing in for GPS data.
	payload := append([]byte("Exif\x00\x00II*\x00\x08\x00\x00\x00"), []byte("GPS-SECRET-MARKER 52.52N 13.40E")...)
	seg := []byte{0xFF, 0xE1, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(payload)+2))
	seg = append(seg, payload...)
	withExif := append([]byte(nil), plain[:2]...)
	withExif = append(withExif, seg...)
	withExif = append(withExif, plain[2:]...)

	ic, err := Sanitize(withExif)
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	checkIcon(t, ic)
	if bytes.Contains(ic.PNG128, []byte("GPS-SECRET")) || bytes.Contains(ic.PNG64, []byte("Exif")) {
		t.Fatal("EXIF data survived")
	}
}

func TestSanitizeGIFUsesFirstFrameOnly(t *testing.T) {
	red := solid(32, 32, color.NRGBA{R: 255, A: 255})
	blue := solid(32, 32, color.NRGBA{B: 255, A: 255})
	ic, err := Sanitize(encodeGIF(t, red, blue))
	if err != nil {
		t.Fatal(err)
	}
	want, err := Sanitize(encodeGIF(t, red))
	if err != nil {
		t.Fatal(err)
	}
	if ic.SHA256 != want.SHA256 {
		t.Fatal("animated GIF did not reduce to its first frame")
	}
}

// jpegWithSOF returns a minimal JPEG whose SOF0 claims w×h; it has no
// scan data, so a full decode fails while DecodeConfig succeeds.
func jpegWithSOF(w, h uint16) []byte {
	b := []byte{0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08}
	b = binary.BigEndian.AppendUint16(b, h)
	b = binary.BigEndian.AppendUint16(b, w)
	b = append(b, 0x01, 0x01, 0x11, 0x00)
	// Without a JFIF APP0 segment DecodeConfig reads on to the first SOS.
	return append(b, 0xFF, 0xDA, 0x00, 0x02)
}

// gifWithScreen returns a GIF header with a w×h logical screen and nothing
// else.
func gifWithScreen(w, h uint16) []byte {
	b := []byte("GIF89a")
	b = binary.LittleEndian.AppendUint16(b, w)
	b = binary.LittleEndian.AppendUint16(b, h)
	return append(b, 0x00, 0x00, 0x00, 0x3B)
}

func TestSanitizeRejectsBombDimensionsBeforeDecode(t *testing.T) {
	// Every input here is header-only: if the dimension check did not run
	// before the full decode, the error would be ErrMalformed instead.
	cases := []struct {
		name string
		data []byte
	}{
		{"png 100000 square", pngHeaderOnly(100000, 100000)},
		{"png wide", pngHeaderOnly(1025, 1)},
		{"png tall", pngHeaderOnly(1, 1025)},
		{"png max int width", pngHeaderOnly(0x7FFFFFFF, 1)},
		{"jpeg 65535 square", jpegWithSOF(65535, 65535)},
		{"jpeg wide", jpegWithSOF(1025, 10)},
		{"gif 65535 square", gifWithScreen(65535, 65535)},
		{"gif zero width", gifWithScreen(0, 10)},
		{"gif zero height", gifWithScreen(10, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Sanitize(c.data)
			if !errors.Is(err, ErrDimensions) {
				t.Fatalf("err = %v, want ErrDimensions", err)
			}
		})
	}
	// The PNG header parser itself refuses dimensions whose pixel count
	// overflows; that is still a rejection from the header alone.
	if _, err := Sanitize(pngHeaderOnly(0x7FFFFFFF, 0x7FFFFFFF)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("overflowing png header: err = %v, want ErrMalformed", err)
	}
}

func TestSanitizeRejectsGIFFrameOutsideScreen(t *testing.T) {
	// Logical screen 8×8, first frame claims 2000×2000 at the origin.
	b := gifWithScreen(8, 8)
	b = b[:len(b)-1] // drop trailer
	b = append(b, 0x2C, 0, 0, 0, 0)
	b = binary.LittleEndian.AppendUint16(b, 2000)
	b = binary.LittleEndian.AppendUint16(b, 2000)
	b = append(b, 0x00, 0x02, 0x02, 0x4C, 0x01, 0x00, 0x3B)
	_, err := Sanitize(b)
	if err == nil {
		t.Fatal("frame larger than the logical screen was accepted")
	}
	if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrDimensions) {
		t.Fatalf("err = %v, want ErrMalformed or ErrDimensions", err)
	}
}

func TestSanitizeRejectsUnsupportedFormats(t *testing.T) {
	webp := []byte("RIFF\x24\x00\x00\x00WEBPVP8 \x18\x00\x00\x00")
	cases := []struct {
		name string
		data []byte
		kind string
	}{
		{"svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`), "svg"},
		{"svg xml decl", []byte(`<?xml version="1.0"?><svg/>`), "svg"},
		{"svg doctype", []byte("<!DOCTYPE svg><svg/>"), "svg"},
		{"svg leading whitespace", []byte(" \n\t<svg/>"), "svg"},
		{"svg utf8 bom", []byte("\xEF\xBB\xBF<svg/>"), "svg"},
		{"svg utf16 bom", []byte("\xFF\xFE<\x00s\x00v\x00g\x00"), "svg"},
		{"html", []byte("<html><body>hi</body></html>"), "svg"},
		{"svgz gzip", []byte{0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0}, "unknown"},
		{"webp", webp, "webp"},
		{"riff other", []byte("RIFF\x24\x00\x00\x00AVI LIST"), "unknown"},
		{"ico", []byte{0, 0, 1, 0, 1, 0, 16, 16, 0, 0}, "ico"},
		{"cur", []byte{0, 0, 2, 0, 1, 0, 16, 16, 0, 0}, "ico"},
		{"bmp", []byte("BM\x36\x00\x00\x00\x00\x00\x00\x00\x36\x00\x00\x00"), "bmp"},
		{"tiff", []byte("II*\x00\x08\x00\x00\x00"), "unknown"},
		{"pdf", []byte("%PDF-1.7\n"), "unknown"},
		{"zip", []byte("PK\x03\x04\x14\x00"), "unknown"},
		{"text", []byte("hello world"), "unknown"},
		{"png magic short", pngMagic[:7], "unknown"},
		{"gif bad version", []byte("GIF88a\x01\x00\x01\x00"), "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Sanitize(c.data)
			if !errors.Is(err, ErrUnsupportedFormat) {
				t.Fatalf("err = %v, want ErrUnsupportedFormat", err)
			}
			var fe *FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v, want *FormatError", err)
			}
			if fe.Kind != c.kind {
				t.Fatalf("Kind = %q, want %q", fe.Kind, c.kind)
			}
		})
	}
}

func TestSanitizeRejectsEmptyInput(t *testing.T) {
	for _, in := range [][]byte{nil, {}} {
		if _, err := Sanitize(in); !errors.Is(err, ErrEmpty) {
			t.Fatalf("err = %v, want ErrEmpty", err)
		}
	}
}

func TestSanitizeSizeLimit(t *testing.T) {
	// A valid PNG padded with trailing bytes to exactly the limit passes;
	// one byte more is rejected before any parsing.
	base := encodePNG(t, testImage(16, 16))
	atLimit := append(append([]byte(nil), base...), make([]byte, MaxInputBytes-len(base))...)
	if _, err := Sanitize(atLimit); err != nil {
		t.Fatalf("input of exactly MaxInputBytes rejected: %v", err)
	}
	over := append(atLimit, 0)
	if _, err := Sanitize(over); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// Even a header-only bomb is rejected for size first.
	bomb := append(pngHeaderOnly(100000, 100000), make([]byte, MaxInputBytes)...)
	if _, err := Sanitize(bomb); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestSanitizeRejectsTruncatedFiles(t *testing.T) {
	sources := map[string][]byte{
		"png":  encodePNG(t, testImage(64, 64)),
		"jpeg": encodeJPEG(t, testImage(64, 64)),
		"gif":  encodeGIF(t, testImage(64, 64)),
	}
	for name, full := range sources {
		for _, frac := range []int{1, 2, 3} {
			cut := len(full) * frac / 4
			t.Run(fmt.Sprintf("%s cut %d of 4", name, frac), func(t *testing.T) {
				_, err := Sanitize(full[:cut])
				if !errors.Is(err, ErrMalformed) {
					t.Fatalf("cut at %d/%d: err = %v, want ErrMalformed", cut, len(full), err)
				}
			})
		}
	}
	// Truncated right after the magic bytes.
	for name, in := range map[string][]byte{
		"png magic only":  pngMagic,
		"jpeg magic only": {0xFF, 0xD8, 0xFF},
		"gif magic only":  []byte("GIF89a"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sanitize(in); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestSanitizeRejectsTooManyJPEGScans(t *testing.T) {
	in := encodeJPEG(t, testImage(16, 16))
	// Inject a COM segment full of SOS markers; the counter is
	// deliberately conservative and counts these too.
	var com []byte
	for i := 0; i <= MaxJPEGScans; i++ {
		com = append(com, 0xFF, 0xDA)
	}
	seg := []byte{0xFF, 0xFE, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(com)+2))
	seg = append(seg, com...)
	bad := append(append(append([]byte(nil), in[:2]...), seg...), in[2:]...)
	if _, err := Sanitize(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add(encodePNG(f, testImage(20, 10)))
	f.Add(encodeJPEG(f, testImage(10, 20)))
	f.Add(encodeGIF(f, testImage(8, 8)))
	f.Add(pngHeaderOnly(100000, 100000))
	f.Add(jpegWithSOF(65535, 1))
	f.Add(gifWithScreen(0, 0))
	f.Add([]byte("<svg/>"))
	f.Add([]byte("RIFF\x00\x00\x00\x00WEBP"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		ic, err := Sanitize(in)
		if err != nil {
			if ic.SHA256 != "" || ic.PNG64 != nil || ic.PNG128 != nil {
				t.Fatal("error returned together with a non-empty Icon")
			}
			return
		}
		if len(in) > MaxInputBytes {
			t.Fatal("oversized input accepted")
		}
		checkIcon(t, ic)
	})
}
