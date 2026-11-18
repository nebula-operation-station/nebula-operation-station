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

// maxWeightError bounds how far one stored weight may deviate from its exact
// rational value. A single weight is at most 1, so one float32 rounding is
// about 6e-8; 1e-6 is a generous margin that still rejects any shifted weight.
const maxWeightError = 1e-6

// boxTestSizes are the source and destination lengths for the boxWeights
// invariants. Every length from 1 to 40 is covered, which exercises all small
// integer ratios. The larger entries sit around the production edges:
// SmallSize 64, LargeSize 128, and MaxDimension, the largest length fit can
// ever receive. Sampling instead of sweeping 1..MaxDimension keeps the roughly
// 3 300 pairs fast under -race while still including non-trivial ratios.
var boxTestSizes = func() []int {
	sizes := make([]int, 0, 57)
	for n := 1; n <= 40; n++ {
		sizes = append(sizes, n)
	}
	return append(sizes, 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 300,
		511, 512, 513, 1000, 1023, MaxDimension)
}()

// fitTestDims are source edge lengths for fit. They cover the degenerate 1
// case, odd and even sizes, sizes that do not divide evenly into the
// destination sizes below, and LargeSize itself.
var fitTestDims = []int{1, 2, 3, 5, 8, 13, 31, 64, 100, LargeSize}

// fitTestSizes are destination edge lengths for fit, from a single pixel up to
// LargeSize, the production output size.
var fitTestSizes = []int{1, 2, 3, 4, 7, 8, 16, 31, 32, 64, LargeSize}

// fitExtremeShapes are extreme aspect ratios up to MaxDimension. A 1×1024
// source fit into a 64 canvas gives a short side of 64·1/1024 = 0.0625 pixels,
// so only the max(1, …) clamp in fit keeps it visible. These shapes make that
// clamp run on both axes and at the largest accepted length.
var fitExtremeShapes = [][2]int{
	{1, MaxDimension},
	{MaxDimension, 1},
	{2, MaxDimension},
	{MaxDimension, 3},
	{1, 512},
	{513, 1},
}

// fitTestShapes is the cross product of fitTestDims with itself, followed by
// fitExtremeShapes. Each entry is {width, height}.
var fitTestShapes = func() [][2]int {
	var shapes [][2]int
	for _, w := range fitTestDims {
		for _, h := range fitTestDims {
			shapes = append(shapes, [2]int{w, h})
		}
	}
	return append(shapes, fitExtremeShapes...)
}()

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

// wantContribs returns the source samples that destination d of dn covers when
// sn source samples are resampled onto it, with their exact share of the
// destination. Destination d spans [d*sn/dn, (d+1)*sn/dn) in source units.
// Scaling every coordinate by dn makes all boundaries integers: destination d
// spans [d*sn, (d+1)*sn) and source sample s spans [s*dn, (s+1)*dn). The
// overlap of those integer intervals, divided by the destination length sn, is
// the exact weight, so the expectation involves no floating-point arithmetic.
func wantContribs(sn, dn, d int) []contrib {
	dLo, dHi := d*sn, (d+1)*sn
	var want []contrib
	for s := d * sn / dn; s < sn && s*dn < dHi; s++ {
		lo := max(dLo, s*dn)
		hi := min(dHi, (s+1)*dn)
		if hi > lo {
			want = append(want, contrib{index: s, weight: float32(float64(hi-lo) / float64(sn))})
		}
	}
	return want
}

func TestBoxWeightsCountMatchesDestination(t *testing.T) {
	for _, sn := range boxTestSizes {
		for _, dn := range boxTestSizes {
			if got := len(boxWeights(sn, dn)); got != dn {
				t.Fatalf("boxWeights(%d, %d) returned %d entries, want %d", sn, dn, got, dn)
			}
		}
	}
}

func TestBoxWeightsEntriesAreNonEmptyAndInRange(t *testing.T) {
	for _, sn := range boxTestSizes {
		for _, dn := range boxTestSizes {
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
	for _, sn := range boxTestSizes {
		for _, dn := range boxTestSizes {
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

// TestBoxWeightsMatchDestinationIntervals ties every destination d to its own
// source interval [d*sn/dn, (d+1)*sn/dn). The sum and range checks above pass
// for a shifted or misordered mapping, so this test compares the covered
// indices and weights against the exact expectation for each destination.
//
// boxWeights computes overlaps in float64, so a boundary that is a hair past a
// source sample can produce an extra index with a weight near 1e-14. Such an
// entry is allowed only if its weight is below maxWeightError. Every exact
// contribution must still be present with its exact weight.
func TestBoxWeightsMatchDestinationIntervals(t *testing.T) {
	for _, sn := range boxTestSizes {
		for _, dn := range boxTestSizes {
			got := boxWeights(sn, dn)
			for d := range dn {
				want := wantContribs(sn, dn, d)
				byIndex := make(map[int]float32, len(got[d]))
				for _, c := range got[d] {
					byIndex[c.index] = c.weight
				}
				for _, w := range want {
					gw, ok := byIndex[w.index]
					if !ok || math.Abs(float64(gw)-float64(w.weight)) > maxWeightError {
						t.Fatalf("boxWeights(%d, %d)[%d] = %v, want destination %d to cover %v",
							sn, dn, d, got[d], d, want)
					}
					delete(byIndex, w.index)
				}
				for idx, gw := range byIndex {
					if gw > maxWeightError {
						t.Fatalf("boxWeights(%d, %d)[%d] gives source %d weight %v, outside destination %d's interval",
							sn, dn, d, idx, gw, d)
					}
				}
			}
		}
	}
}

// TestBoxWeightsSourceTotalsMatchRatio checks conservation from the source
// side. Each source sample spans dn units of the destination grid and each
// destination sample has total weight 1, so the weights a source sample
// contributes over all destinations must add up to dn/sn.
func TestBoxWeightsSourceTotalsMatchRatio(t *testing.T) {
	for _, sn := range boxTestSizes {
		for _, dn := range boxTestSizes {
			totals := make([]float64, sn)
			for _, cs := range boxWeights(sn, dn) {
				for _, c := range cs {
					totals[c.index] += float64(c.weight)
				}
			}
			want := float64(dn) / float64(sn)
			for s, got := range totals {
				if math.Abs(got-want) > maxWeightSumError*max(1, want) {
					t.Fatalf("boxWeights(%d, %d): source %d total weight %v, want dn/sn = %v",
						sn, dn, s, got, want)
				}
			}
		}
	}
}

// TestBoxWeightsCoverageMovesForward checks that the first and last covered
// source index never decrease as the destination index grows. A mapping that
// runs backwards, or that jumps between two halves of the source, fails here.
func TestBoxWeightsCoverageMovesForward(t *testing.T) {
	for _, sn := range boxTestSizes {
		for _, dn := range boxTestSizes {
			var prevFirst, prevLast int
			for d, cs := range boxWeights(sn, dn) {
				if len(cs) == 0 {
					t.Fatalf("boxWeights(%d, %d)[%d] is empty", sn, dn, d)
				}
				first, last := cs[0].index, cs[len(cs)-1].index
				if d > 0 && (first < prevFirst || last < prevLast) {
					t.Fatalf("boxWeights(%d, %d)[%d] covers [%d, %d], moves back from [%d, %d]",
						sn, dn, d, first, last, prevFirst, prevLast)
				}
				prevFirst, prevLast = first, last
			}
		}
	}
}

func TestBoxWeightsIdentityWhenSizesMatch(t *testing.T) {
	for _, n := range boxTestSizes {
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
	for _, sh := range fitTestShapes {
		for _, size := range fitTestSizes {
			w, h := sh[0], sh[1]
			out := fit(opaqueSource(w, h, color.RGBA{R: 1, G: 2, B: 3, A: 255}), size)
			if got := out.Rect; got != image.Rect(0, 0, size, size) {
				t.Fatalf("fit(%dx%d, %d) bounds = %v, want (0,0)-(%d,%d)", w, h, size, got, size, size)
			}
		}
	}
}

// TestFitCentresContentWithTransparentMargins checks, for square, wide, tall
// and extreme sources, that the scaled content is centred on the canvas and
// that everything outside it is fully transparent. The source is opaque, so
// the alpha>0 bounding box is exactly the content box.
func TestFitCentresContentWithTransparentMargins(t *testing.T) {
	for _, sh := range fitTestShapes {
		for _, size := range fitTestSizes {
			w, h := sh[0], sh[1]
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

// TestFitBlendsHalfTransparentEdgePremultiplied uses known values for a
// two-pixel source that is downscaled to one pixel. One pixel is opaque white.
// The other is red at 50% alpha, stored premultiplied as (128,0,0,128). The
// averaged premultiplied result is r=(255+128)/2=191.5, g=b=127.5, a=191.5,
// which rounds to (192,128,128,192).
//
// Filtering in non-premultiplied space gives a different answer. It would
// unpremultiply the red pixel to (255,0,0,128), average to colour
// (255,127.5,127.5) and then premultiply by the averaged alpha 192/255. That
// yields (192,96,96,192), so this test fails for such a filter. Both edge
// orders are checked.
func TestFitBlendsHalfTransparentEdgePremultiplied(t *testing.T) {
	white := [4]uint8{255, 255, 255, 255}
	halfRed := [4]uint8{128, 0, 0, 128}
	want := [4]uint8{192, 128, 128, 192}
	tests := []struct {
		name        string
		left, right [4]uint8
	}{
		{"opaque white left, half red right", white, halfRed},
		{"half red left, opaque white right", halfRed, white},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := image.NewRGBA(image.Rect(0, 0, 2, 1))
			copy(src.Pix[0:4], tc.left[:])
			copy(src.Pix[4:8], tc.right[:])
			out := fit(src, 1)
			if out.Rect != image.Rect(0, 0, 1, 1) {
				t.Fatalf("fit bounds = %v, want (0,0)-(1,1)", out.Rect)
			}
			if got := [4]uint8(out.Pix[0:4]); got != want {
				t.Fatalf("fit pixel = %v, want premultiplied average %v", got, want)
			}
		})
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
		for _, sh := range fitTestShapes {
			for _, size := range fitTestSizes {
				w, h := sh[0], sh[1]
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

// TestFitIsDeterministic checks that the same input always produces the same
// bytes, which the icon store relies on for stable content hashes.
func TestFitIsDeterministic(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for _, sh := range fitTestShapes {
		for _, size := range fitTestSizes {
			w, h := sh[0], sh[1]
			src := randomPremul(rng, w, h)
			a := fit(src, size)
			b := fit(src, size)
			if !bytes.Equal(a.Pix, b.Pix) || a.Rect != b.Rect {
				t.Fatalf("fit(%dx%d, %d) gave different output for identical input", w, h, size)
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
