// SPDX-License-Identifier: AGPL-3.0-or-later

package iconstore

import (
	"image"
	"image/draw"
	"math"
)

// toRGBA copies m into a premultiplied RGBA canvas anchored at the origin.
// The caller has bounded m to MaxDimension², so this allocates at most
// 4 MiB.
func toRGBA(m image.Image) *image.RGBA {
	b := m.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), m, b.Min, draw.Src)
	return dst
}

// contrib is one source sample's share of a destination sample.
type contrib struct {
	index  int
	weight float32
}

// boxWeights returns, for each of dn destination samples, the source
// samples it covers and their normalised overlap. Downscaling averages the
// covered area; upscaling degenerates to near-nearest-neighbour with
// blended seams, which keeps small pixel-art icons crisp.
func boxWeights(sn, dn int) [][]contrib {
	scale := float64(sn) / float64(dn)
	out := make([][]contrib, dn)
	for d := range dn {
		lo := float64(d) * scale
		hi := float64(d+1) * scale
		var cs []contrib
		var sum float64
		for s := int(lo); s < sn && float64(s) < hi; s++ {
			w := math.Min(hi, float64(s+1)) - math.Max(lo, float64(s))
			if w <= 0 {
				continue
			}
			cs = append(cs, contrib{index: s, weight: float32(w)})
			sum += w
		}
		for i := range cs {
			cs[i].weight = float32(float64(cs[i].weight) / sum)
		}
		out[d] = cs
	}
	return out
}

// fit scales src to fit a size×size canvas, keeping the aspect ratio and
// centring it on a fully transparent background. Filtering happens on
// premultiplied values so transparent pixels do not tint their neighbours.
func fit(src *image.RGBA, size int) *image.RGBA {
	sw, sh := src.Rect.Dx(), src.Rect.Dy()
	dw, dh := size, size
	if sw >= sh {
		dh = max(1, (sh*size+sw/2)/sw)
	} else {
		dw = max(1, (sw*size+sh/2)/sh)
	}
	ox, oy := (size-dw)/2, (size-dh)/2

	xw := boxWeights(sw, dw)
	yw := boxWeights(sh, dh)

	// Horizontal pass: sh rows × dw columns × 4 channels.
	tmp := make([]float32, sh*dw*4)
	for y := range sh {
		row := src.Pix[y*src.Stride : y*src.Stride+sw*4]
		for x, cs := range xw {
			var r, g, b, a float32
			for _, c := range cs {
				p := row[c.index*4 : c.index*4+4]
				r += float32(p[0]) * c.weight
				g += float32(p[1]) * c.weight
				b += float32(p[2]) * c.weight
				a += float32(p[3]) * c.weight
			}
			t := tmp[(y*dw+x)*4 : (y*dw+x)*4+4]
			t[0], t[1], t[2], t[3] = r, g, b, a
		}
	}

	// Vertical pass into the padded output.
	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	for y, cs := range yw {
		for x := range dw {
			var r, g, b, a float32
			for _, c := range cs {
				t := tmp[(c.index*dw+x)*4 : (c.index*dw+x)*4+4]
				r += t[0] * c.weight
				g += t[1] * c.weight
				b += t[2] * c.weight
				a += t[3] * c.weight
			}
			o := dst.PixOffset(ox+x, oy+y)
			pa := clamp8(a)
			dst.Pix[o+0] = min(clamp8(r), pa)
			dst.Pix[o+1] = min(clamp8(g), pa)
			dst.Pix[o+2] = min(clamp8(b), pa)
			dst.Pix[o+3] = pa
		}
	}
	return dst
}

func clamp8(v float32) uint8 {
	v = float32(math.Round(float64(v)))
	switch {
	case v <= 0:
		return 0
	case v >= 255:
		return 255
	}
	return uint8(v)
}
