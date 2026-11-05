// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"math/bits"
	"time"
)

const secondsPerHour = 3600

// hourPart is the share of a report interval that falls into one hour,
// with the same proportional split flowagg.Aggregator uses, so the store
// and the in-memory aggregator place the same bytes into the same hours.
type hourPart struct {
	start    time.Time // hour start
	num, den uint64    // fraction of the interval in this hour
	done     uint64    // nanoseconds of the interval before this part
}

// share returns this part's share of v: floor(v*end/den) -
// floor(v*start/den) over the cumulative interval, so the parts of v add
// up to v exactly.
func (p hourPart) share(v uint64) uint64 {
	if p.den == 0 {
		return v
	}
	upTo := func(n uint64) uint64 {
		if n >= p.den {
			return v
		}
		hi, lo := bits.Mul64(v, n)
		q, _ := bits.Div64(hi, lo, p.den)
		return q
	}
	return upTo(p.done+p.num) - upTo(p.done)
}

func floorHour(t time.Time) int64 {
	s := t.Unix()
	h := s / secondsPerHour
	if s%secondsPerHour < 0 {
		h--
	}
	return h
}

// splitHours divides [from, to) into hourly parts. A zero-length
// interval is one part in the hour of to.
func splitHours(from, to time.Time) []hourPart {
	total := to.Sub(from)
	if total <= 0 {
		return []hourPart{{start: time.Unix(floorHour(to)*secondsPerHour, 0).UTC()}}
	}
	var parts []hourPart
	var done uint64
	for h := floorHour(from); ; h++ {
		hs := time.Unix(h*secondsPerHour, 0).UTC()
		start, end := hs, hs.Add(time.Hour)
		if start.Before(from) {
			start = from
		}
		if end.After(to) {
			end = to
		}
		if seg := end.Sub(start); seg > 0 {
			parts = append(parts, hourPart{start: hs, num: uint64(seg), den: uint64(total), done: done})
			done += uint64(seg)
		}
		if !end.Before(to) {
			break
		}
	}
	return parts
}
