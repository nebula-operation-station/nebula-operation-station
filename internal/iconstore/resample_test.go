// SPDX-License-Identifier: AGPL-3.0-or-later

package iconstore

import (
	"bytes"
	"image"
	"image/color"
	"math"
	"math/rand/v2"
	"testing"
)

// maxWeightSumError bounds how far the normalised weights of one destination
// sample may deviate from 1. Each weight is a float32 with a relative rounding
// error of at most 2^-24 (about 6e-8). A destination sample covers at most
// 300 source samples in these tests, so the accumulated error is at most
// 300 * 6e-8 = 1.8e-5. 1e-4 leaves a safety margin without hiding a wrong
// weight, which would be off by far more.
const maxWeightSumError = 1e-4

// resampleTestMax is the largest source or destination length exercised for
// boxWeights. It matches the 300 in the invariant tests of this file.
const resampleTestMax = 300

// fitTestDims are source edge lengths for fit. They cover the degenerate 1
// case, odd and even sizes, and sizes that do not divide evenly into the
// destination sizes below.
var fitTestDims = []int{1, 2, 3, 5, 8, 13, 31, 64, 100}

// fitTestSizes are destination edge lengths for fit, from a single pixel up to
// a size that is larger than most of the sources above.
var fitTestSizes = []int{1, 2, 3, 4, 7, 8, 16, 31, 32, 64}

// opaqueSource returns a w×h image filled with the fully opaque colour c.
func opaqueSource(w, h int, c color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.R, c.G, c.B, c.A
	}
	return img
}

// randomPremul returns a w×h premultiplied RGBA image with random pixels that
// satisfy colour ≤ alpha on every pixel. Only valid premultiplied input is a
// legal input to fit, since toRGBA always produces it.
func randomPremul(rng *rand.Rand, w, h int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		a := uint8(rng.IntN(256))
		img.Pix[i+3] = a
		img.Pix[i+0] = uint8(rng.IntN(int(a) + 1))
		img.Pix[i+1] = uint8(rng.IntN(int(a) + 1))
		img.Pix[i+2] = uint8(rng.IntN(int(a) + 1))
	}
	return img
}

// alphaBox returns the bounding box [minX,maxX)×[minY,maxY) of all pixels with
// alpha > 0. ok is false if no pixel has alpha > 0.
func alphaBox(img *image.RGBA) (minX, minY, maxX, maxY int, ok bool) {
	minX, minY = img.Rect.Dx(), img.Rect.Dy()
	maxX, maxY = -1, -1
	for y := img.Rect.Min.Y; y < img.Rect.Max.Y; y++ {
		for x := img.Rect.Min.X; x < img.Rect.Max.X; x++ {
			if img.Pix[img.PixOffset(x, y)+3] == 0 {
				continue
			}
			ok = true
			minX, minY = min(minX, x), min(minY, y)
			maxX, maxY = max(maxX, x+1), max(maxY, y+1)
		}
	}
	return minX, minY, maxX, maxY, ok
}

func TestBoxWeightsCountMatchesDestination(t *testing.T) {
	for sn := 1; sn <= resampleTestMax; sn++ {
		for dn := 1; dn <= resampleTestMax; dn++ {
			if got := len(boxWeights(sn, dn)); got != dn {
				t.Fatalf("boxWeights(%d, %d) returned %d entries, want %d", sn, dn, got, dn)
			}
		}
	}
}

func TestBoxWeightsEntriesAreNonEmptyAndInRange(t *testing.T) {
	for sn := 1; sn <= resampleTestMax; sn++ {
		for dn := 1; dn <= resampleTestMax; dn++ {
			for d, cs := range boxWeights(sn, dn) {
				if len(cs) == 0 {
					t.Fatalf("boxWeights(%d, %d)[%d] is empty", sn, dn, d)
				}
				prev := -1
				for _, c := range cs {
					if c.index < 0 || c.index >= sn {
						t.Fatalf("boxWeights(%d, %d)[%d] index %d outside [0, %d)", sn, dn, d, c.index, sn)
					}
					if c.index <= prev {
						t.Fatalf("boxWeights(%d, %d)[%d] indices not strictly ascending: %d after %d", sn, dn, d, c.index, prev)
					}
					prev = c.index
				}
			}
		}
	}
}

func TestBoxWeightsAreNonNegativeAndSumToOne(t *testing.T) {
	for sn := 1; sn <= resampleTestMax; sn++ {
		for dn := 1; dn <= resampleTestMax; dn++ {
			for d, cs := range boxWeights(sn, dn) {
				var sum float64
				for _, c := range cs {
					if c.weight < 0 {
						t.Fatalf("boxWeights(%d, %d)[%d] has negative weight %v", sn, dn, d, c.weight)
					}
					sum += float64(c.weight)
				}
				if math.Abs(sum-1) > maxWeightSumError {
					t.Fatalf("boxWeights(%d, %d)[%d] weights sum to %v, want 1 ± %v", sn, dn, d, sum, maxWeightSumError)
				}
			}
		}
	}
}

func TestBoxWeightsIdentityWhenSizesMatch(t *testing.T) {
	for n := 1; n <= resampleTestMax; n++ {
		got := boxWeights(n, n)
		for d, cs := range got {
			if len(cs) != 1 {
				t.Fatalf("boxWeights(%d, %d)[%d] has %d contributions, want exactly 1", n, n, d, len(cs))
			}
			if cs[0].index != d {
				t.Fatalf("boxWeights(%d, %d)[%d] samples index %d, want %d", n, n, d, cs[0].index, d)
			}
			if cs[0].weight != 1 {
				t.Fatalf("boxWeights(%d, %d)[%d] weight %v, want exactly 1", n, n, d, cs[0].weight)
			}
		}
	}
}

func TestBoxWeightsDownscaleAveragesCoveredSamples(t *testing.T) {
	// 4 source samples into 2 destination samples: each destination covers
	// exactly two whole source samples with equal weight.
	got := boxWeights(4, 2)
	want := [][]contrib{
		{{index: 0, weight: 0.5}, {index: 1, weight: 0.5}},
		{{index: 2, weight: 0.5}, {index: 3, weight: 0.5}},
	}
	for d := range want {
		if len(got[d]) != len(want[d]) {
			t.Fatalf("boxWeights(4, 2)[%d] = %v, want %v", d, got[d], want[d])
		}
		for i := range want[d] {
			if got[d][i] != want[d][i] {
				t.Fatalf("boxWeights(4, 2)[%d][%d] = %v, want %v", d, i, got[d][i], want[d][i])
			}
		}
	}
}

func TestFitOutputIsSquareOfRequestedSize(t *testing.T) {
	for _, w := range fitTestDims {
		for _, h := range fitTestDims {
			for _, size := range fitTestSizes {
				out := fit(opaqueSource(w, h, color.RGBA{R: 1, G: 2, B: 3, A: 255}), size)
				if got := out.Rect; got != image.Rect(0, 0, size, size) {
					t.Fatalf("fit(%dx%d, %d) bounds = %v, want (0,0)-(%d,%d)", w, h, size, got, size, size)
				}
			}
		}
	}
}

// TestFitCentresContentWithTransparentMargins checks, for square, wide and
// tall sources, that the scaled content is centred on the canvas and that
// everything outside it is fully transparent. The source is opaque, so the
// alpha>0 bounding box is exactly the content box.
func TestFitCentresContentWithTransparentMargins(t *testing.T) {
	for _, w := range fitTestDims {
		for _, h := range fitTestDims {
			for _, size := range fitTestSizes {
				out := fit(opaqueSource(w, h, color.RGBA{R: 200, G: 100, B: 50, A: 255}), size)
				minX, minY, maxX, maxY, ok := alphaBox(out)
				if !ok {
					t.Fatalf("fit(%dx%d, %d) produced no opaque pixels", w, h, size)
				}
				cw, ch := maxX-minX, maxY-minY
				if cw < 1 || ch < 1 || cw > size || ch > size {
					t.Fatalf("fit(%dx%d, %d) content %dx%d outside canvas", w, h, size, cw, ch)
				}
				// The longer side fills the canvas, the shorter side keeps the
				// aspect ratio. Integer rounding stays under one pixel.
				switch {
				case w >= h:
					if cw != size {
						t.Fatalf("fit(%dx%d, %d) width %d, want full width %d", w, h, size, cw, size)
					}
					exact := float64(h) * float64(size) / float64(w)
					if math.Abs(float64(ch)-exact) >= 1 {
						t.Fatalf("fit(%dx%d, %d) height %d, aspect wants %.3f", w, h, size, ch, exact)
					}
				default:
					if ch != size {
						t.Fatalf("fit(%dx%d, %d) height %d, want full height %d", w, h, size, ch, size)
					}
					exact := float64(w) * float64(size) / float64(h)
					if math.Abs(float64(cw)-exact) >= 1 {
						t.Fatalf("fit(%dx%d, %d) width %d, aspect wants %.3f", w, h, size, cw, exact)
					}
				}
				// Margins differ by at most one pixel on each axis.
				left, right := minX, size-maxX
				top, bottom := minY, size-maxY
				if left-right > 1 || right-left > 1 {
					t.Fatalf("fit(%dx%d, %d) horizontal margins %d/%d not centred", w, h, size, left, right)
				}
				if top-bottom > 1 || bottom-top > 1 {
					t.Fatalf("fit(%dx%d, %d) vertical margins %d/%d not centred", w, h, size, top, bottom)
				}
				// Every pixel outside the content box is fully transparent.
				for y := range size {
					for x := range size {
						inside := x >= minX && x < maxX && y >= minY && y < maxY
						a := out.Pix[out.PixOffset(x, y)+3]
						if !inside && a != 0 {
							t.Fatalf("fit(%dx%d, %d) pixel (%d,%d) outside content has alpha %d", w, h, size, x, y, a)
						}
					}
				}
			}
		}
	}
}

// TestFitKeepsColourBelowAlpha checks the premultiplied invariant on random
// valid input: no output pixel may have a colour channel above its alpha.
func TestFitKeepsColourBelowAlpha(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, w := range fitTestDims {
		for _, h := range fitTestDims {
			for _, size := range fitTestSizes {
				src := randomPremul(rng, w, h)
				out := fit(src, size)
				for i := 0; i < len(out.Pix); i += 4 {
					a := out.Pix[i+3]
					for c := range 3 {
						if out.Pix[i+c] > a {
							t.Fatalf("fit(%dx%d, %d) pixel %d: channel %d = %d > alpha %d",
								w, h, size, i/4, c, out.Pix[i+c], a)
						}
					}
				}
			}
		}
	}
}

// TestFitFlatOpaqueSourceStaysFlat checks that a single-colour opaque source
// still looks like one colour inside the content box. Rounding may move each
// channel by at most one level.
func TestFitFlatOpaqueSourceStaysFlat(t *testing.T) {
	colours := []color.RGBA{
		{R: 0, G: 0, B: 0, A: 255},
		{R: 255, G: 255, B: 255, A: 255},
		{R: 12, G: 130, B: 251, A: 255},
	}
	for _, c := range colours {
		for _, w := range fitTestDims {
			for _, h := range fitTestDims {
				for _, size := range fitTestSizes {
					out := fit(opaqueSource(w, h, c), size)
					minX, minY, maxX, maxY, ok := alphaBox(out)
					if !ok {
						t.Fatalf("fit(%dx%d, %d) produced no opaque pixels", w, h, size)
					}
					for y := minY; y < maxY; y++ {
						for x := minX; x < maxX; x++ {
							o := out.PixOffset(x, y)
							got := out.Pix[o : o+4]
							if got[3] != 255 {
								t.Fatalf("fit(%dx%d, %d) pixel (%d,%d) alpha %d, want 255", w, h, size, x, y, got[3])
							}
							want := []uint8{c.R, c.G, c.B}
							for ch := range 3 {
								d := int(got[ch]) - int(want[ch])
								if d < -1 || d > 1 {
									t.Fatalf("fit(%dx%d, %d) pixel (%d,%d) channel %d = %d, want %d ±1",
										w, h, size, x, y, ch, got[ch], want[ch])
								}
							}
						}
					}
				}
			}
		}
	}
}

// TestFitIsDeterministic checks that the same input always produces the same
// bytes, which the icon store relies on for stable content hashes.
func TestFitIsDeterministic(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for _, w := range fitTestDims {
		for _, h := range fitTestDims {
			for _, size := range fitTestSizes {
				src := randomPremul(rng, w, h)
				a := fit(src, size)
				b := fit(src, size)
				if !bytes.Equal(a.Pix, b.Pix) || a.Rect != b.Rect {
					t.Fatalf("fit(%dx%d, %d) gave different output for identical input", w, h, size)
				}
			}
		}
	}
}

func TestToRGBAProducesPremultipliedPixels(t *testing.T) {
	// draw.Src converts to premultiplied RGBA. fit depends on colour ≤ alpha
	// holding for everything toRGBA returns, so check it on a non-premultiplied
	// source where the colour channels exceed alpha.
	src := image.NewNRGBA(image.Rect(10, 20, 17, 29))
	rng := rand.New(rand.NewPCG(5, 6))
	for i := range src.Pix {
		src.Pix[i] = uint8(rng.IntN(256))
	}
	out := toRGBA(src)
	if out.Rect != image.Rect(0, 0, 7, 9) {
		t.Fatalf("toRGBA bounds = %v, want (0,0)-(7,9)", out.Rect)
	}
	for i := 0; i < len(out.Pix); i += 4 {
		for c := range 3 {
			if out.Pix[i+c] > out.Pix[i+3] {
				t.Fatalf("toRGBA pixel %d: channel %d = %d > alpha %d", i/4, c, out.Pix[i+c], out.Pix[i+3])
			}
		}
	}
}

func TestClamp8Boundaries(t *testing.T) {
	tests := []struct {
		name string
		in   float32
		want uint8
	}{
		{"large negative clamps to 0", -1e9, 0},
		{"minus one clamps to 0", -1, 0},
		{"minus half rounds to 0 and clamps", -0.5, 0},
		{"exact zero", 0, 0},
		{"just below half rounds to 0", math.Nextafter32(0.5, 0), 0},
		{"half rounds up to 1", 0.5, 1},
		{"one", 1, 1},
		{"just below 254.5 rounds to 254", math.Nextafter32(254.5, 0), 254},
		{"254.5 rounds up to 255", 254.5, 255},
		{"254.4 rounds to 254", 254.4, 254},
		{"exact 255", 255, 255},
		{"above 255 clamps to 255", 255.4, 255},
		{"large positive clamps to 255", 1e9, 255},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clamp8(tc.in); got != tc.want {
				t.Fatalf("clamp8(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestClamp8NonFiniteInputDoesNotPanic documents the behaviour for non-finite
// input. ±Inf clamp like any out-of-range value. NaN is not ordered, so both
// range checks fail and the result comes from the Go conversion of NaN to
// uint8, which the spec leaves implementation-defined. The test therefore only
// requires that it does not panic and gives the same answer on every call.
func TestClamp8NonFiniteInputDoesNotPanic(t *testing.T) {
	inf := float32(math.Inf(1))
	if got := clamp8(inf); got != 255 {
		t.Fatalf("clamp8(+Inf) = %d, want 255", got)
	}
	if got := clamp8(-inf); got != 0 {
		t.Fatalf("clamp8(-Inf) = %d, want 0", got)
	}
	nan := float32(math.NaN())
	first := clamp8(nan)
	for range 16 {
		if got := clamp8(nan); got != first {
			t.Fatalf("clamp8(NaN) not stable: got %d then %d", first, got)
		}
	}
}
