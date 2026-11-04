// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import "math"

// LogScale maps v onto [0, 1] logarithmically relative to max, for line
// widths and brightness on the traffic map: log(1+v)/log(1+max). Values
// above max clamp to 1; max == 0 yields 0. The mapping is monotonic in v.
func LogScale(v, max uint64) float64 {
	if max == 0 || v == 0 {
		return 0
	}
	if v >= max {
		return 1
	}
	return math.Log1p(float64(v)) / math.Log1p(float64(max))
}
