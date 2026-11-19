// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import (
	"cmp"
	"math/rand/v2"
	"slices"
	"testing"
)

// keepHeapReferenceSteps is the number of random add/remove operations the
// reference test applies to one heap. Every step is checked against a plain
// set.
const keepHeapReferenceSteps = 3000

// keepHeapKeySpace bounds the keys the reference test draws, so that adds
// and removes hit both present and absent keys often.
const keepHeapKeySpace = 200

// checkKeepHeap verifies the heap against the reference set ref and the
// compare function it was built with:
//   - Len equals the size of ref;
//   - pos has exactly the keys of ref and items[pos[k]] == k for each one;
//   - the heap property holds: no item is kept before its parent;
//   - last() is ok and is a maximum of the keep order over ref (for an empty
//     ref, last() is not ok).
//
// With a strict compare the maximum is unique and last() must equal it; with
// ties any maximal element is accepted.
func checkKeepHeap(t *testing.T, h *keepHeap[int], ref map[int]bool, compare func(x, y int) int) {
	t.Helper()
	if got, want := h.Len(), len(ref); got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}
	if got, want := len(h.pos), len(ref); got != want {
		t.Fatalf("len(pos) = %d, want %d", got, want)
	}
	for k := range ref {
		i, ok := h.pos[k]
		if !ok {
			t.Fatalf("key %d is in the reference set but not in pos", k)
		}
		if i < 0 || i >= len(h.items) || h.items[i] != k {
			t.Fatalf("pos[%d] = %d, but items[%d] is not %d", k, i, i, k)
		}
	}
	for i := 1; i < len(h.items); i++ {
		parent := (i - 1) / 2
		if compare(h.items[parent], h.items[i]) < 0 {
			t.Fatalf("heap property broken: items[%d]=%d is kept before its parent items[%d]=%d",
				i, h.items[i], parent, h.items[parent])
		}
	}
	got, ok := h.last()
	if len(ref) == 0 {
		if ok {
			t.Fatalf("last() on a heap without items = (%d, true), want ok == false", got)
		}
		return
	}
	if !ok {
		t.Fatalf("last() ok == false for a heap with %d items", len(ref))
	}
	if !ref[got] {
		t.Fatalf("last() = %d, which is not in the reference set", got)
	}
	best := maxKept(ref, compare)
	if compare(got, best) != 0 {
		t.Fatalf("last() = %d, want a maximum of the keep order such as %d", got, best)
	}
}

// maxKept returns the element of ref that is kept last under compare. Ties
// are resolved to the smallest key so that the result is deterministic.
func maxKept(ref map[int]bool, compare func(x, y int) int) int {
	first := true
	var best int
	for k := range ref {
		if first || compare(k, best) > 0 || (compare(k, best) == 0 && k < best) {
			best = k
			first = false
		}
	}
	return best
}

// keepInt is the strict keep order used by most tests: larger keys are kept
// later, so the root is the largest key.
func keepInt(x, y int) int { return cmp.Compare(x, y) }

// keepIntClass is a keep order with ties: keys with the same remainder modulo
// 3 compare equal.
func keepIntClass(x, y int) int { return cmp.Compare(x%3, y%3) }

func TestKeepHeapLastOfEmptyHeapIsNotOK(t *testing.T) {
	h := newKeepHeap(keepInt)
	if k, ok := h.last(); ok {
		t.Fatalf("last() on an empty heap = (%d, true), want ok == false", k)
	}
}

func TestKeepHeapSingleItemIsLastAndRemovingItEmptiesHeap(t *testing.T) {
	h := newKeepHeap(keepInt)
	h.add(7)
	if k, ok := h.last(); !ok || k != 7 {
		t.Fatalf("last() = (%d, %t), want (7, true)", k, ok)
	}
	h.remove(7)
	if h.Len() != 0 {
		t.Fatalf("Len() = %d after removing the only item, want 0", h.Len())
	}
	if len(h.pos) != 0 {
		t.Fatalf("len(pos) = %d after removing the only item, want 0", len(h.pos))
	}
	if k, ok := h.last(); ok {
		t.Fatalf("last() after removing the only item = (%d, true), want ok == false", k)
	}
}

func TestKeepHeapRemoveLastRemainingItemEmptiesPosToo(t *testing.T) {
	h := newKeepHeap(keepInt)
	for _, k := range []int{4, 9, 1} {
		h.add(k)
	}
	for _, k := range []int{9, 4, 1} {
		h.remove(k)
	}
	if h.Len() != 0 || len(h.pos) != 0 || len(h.items) != 0 {
		t.Fatalf("after removing all items: Len=%d len(pos)=%d len(items)=%d, want 0 0 0",
			h.Len(), len(h.pos), len(h.items))
	}
}

func TestKeepHeapRemoveUnknownItemChangesNothing(t *testing.T) {
	h := newKeepHeap(keepInt)
	ref := map[int]bool{}
	for _, k := range []int{3, 8, 5} {
		h.add(k)
		ref[k] = true
	}
	before := slices.Clone(h.items)
	h.remove(99)
	if !slices.Equal(before, h.items) {
		t.Fatalf("remove of an unknown key changed items: %v, want %v", h.items, before)
	}
	checkKeepHeap(t, h, ref, keepInt)
}

func TestKeepHeapPushWrongTypeChangesNothing(t *testing.T) {
	h := newKeepHeap(keepInt)
	ref := map[int]bool{}
	for _, k := range []int{2, 6, 4} {
		h.add(k)
		ref[k] = true
	}
	itemsBefore := slices.Clone(h.items)
	posBefore := make(map[int]int, len(h.pos))
	for k, i := range h.pos {
		posBefore[k] = i
	}

	h.Push("not an int")
	h.Push(3.5)

	if !slices.Equal(itemsBefore, h.items) {
		t.Fatalf("Push of a wrong type changed items: %v, want %v", h.items, itemsBefore)
	}
	if len(h.pos) != len(posBefore) {
		t.Fatalf("Push of a wrong type changed len(pos): %d, want %d", len(h.pos), len(posBefore))
	}
	for k, i := range posBefore {
		if h.pos[k] != i {
			t.Fatalf("Push of a wrong type changed pos[%d] = %d, want %d", k, h.pos[k], i)
		}
	}
	checkKeepHeap(t, h, ref, keepInt)
}

func TestKeepHeapPushWrongTypeOnEmptyHeapChangesNothing(t *testing.T) {
	h := newKeepHeap(keepInt)
	h.Push("not an int")
	if h.Len() != 0 || len(h.pos) != 0 {
		t.Fatalf("Push of a wrong type on an empty heap: Len=%d len(pos)=%d, want 0 0", h.Len(), len(h.pos))
	}
	checkKeepHeap(t, h, map[int]bool{}, keepInt)
}

func TestKeepHeapMatchesSortedReferenceUnderRandomAddAndRemove(t *testing.T) {
	// A fixed seed makes the sequence reproducible; no clock and no
	// unseeded randomness is involved.
	rng := rand.New(rand.NewPCG(0x6e6562756c61, 0x75633036))
	h := newKeepHeap(keepInt)
	ref := map[int]bool{}

	for step := 0; step < keepHeapReferenceSteps; step++ {
		k := rng.IntN(keepHeapKeySpace)
		// Adds are drawn a little more often than removes so the heap grows
		// and shrinks over the run.
		if rng.IntN(3) < 2 {
			if !ref[k] {
				h.add(k)
				ref[k] = true
			}
		} else {
			h.remove(k)
			delete(ref, k)
		}
		checkKeepHeap(t, h, ref, keepInt)
	}
	if len(ref) == 0 || len(ref) == keepHeapKeySpace {
		t.Fatalf("reference run did not exercise a mixed heap: final size %d", len(ref))
	}
}

func TestKeepHeapWithTiesKeepsLastMaximalAndLosesNothing(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x7469657301, 0x75633036))
	h := newKeepHeap(keepIntClass)
	ref := map[int]bool{}

	for step := 0; step < keepHeapReferenceSteps; step++ {
		k := rng.IntN(keepHeapKeySpace)
		if rng.IntN(3) < 2 {
			if !ref[k] {
				h.add(k)
				ref[k] = true
			}
		} else {
			h.remove(k)
			delete(ref, k)
		}
		checkKeepHeap(t, h, ref, keepIntClass)
	}
}

func TestKeepHeapDrainingEvictsInDescendingKeepOrder(t *testing.T) {
	tests := []struct {
		name    string
		compare func(x, y int) int
		keys    []int
	}{
		{name: "strict order", compare: keepInt, keys: []int{5, 1, 9, 3, 7, 0, 8, 2, 6, 4}},
		{name: "strict order with a single key", compare: keepInt, keys: []int{42}},
		{name: "ties are evicted in non-increasing order", compare: keepIntClass, keys: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newKeepHeap(tt.compare)
			ref := map[int]bool{}
			for _, k := range tt.keys {
				h.add(k)
				ref[k] = true
			}
			checkKeepHeap(t, h, ref, tt.compare)

			var evicted []int
			for {
				k, ok := h.last()
				if !ok {
					break
				}
				evicted = append(evicted, k)
				h.remove(k)
				delete(ref, k)
				checkKeepHeap(t, h, ref, tt.compare)
			}

			if len(evicted) != len(tt.keys) {
				t.Fatalf("evicted %d items, want %d: %v", len(evicted), len(tt.keys), evicted)
			}
			for i := 1; i < len(evicted); i++ {
				if tt.compare(evicted[i-1], evicted[i]) < 0 {
					t.Fatalf("eviction order %v: %d was evicted before %d, but is kept before it",
						evicted, evicted[i], evicted[i-1])
				}
			}
			want := slices.Clone(tt.keys)
			got := slices.Clone(evicted)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(want, got) {
				t.Fatalf("evicted set %v, want %v: an item was lost or duplicated", got, want)
			}
		})
	}
}
