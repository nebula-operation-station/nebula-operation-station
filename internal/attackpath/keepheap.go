// SPDX-License-Identifier: AGPL-3.0-or-later

package attackpath

import "container/heap"

// keepHeap is an indexed binary heap over the items a Builder holds. Its
// root is the item kept last under the keep order, i.e. the first to evict
// when an input limit is reached. All operations are O(log n).
type keepHeap[K comparable] struct {
	items []K
	pos   map[K]int
	// compare is the keep order: negative if x is kept before y.
	compare func(x, y K) int
}

func newKeepHeap[K comparable](compare func(x, y K) int) *keepHeap[K] {
	return &keepHeap[K]{pos: map[K]int{}, compare: compare}
}

// Len, Less, Swap, Push and Pop implement heap.Interface; use add, remove
// and last instead.
func (h *keepHeap[K]) Len() int           { return len(h.items) }
func (h *keepHeap[K]) Less(i, j int) bool { return h.compare(h.items[i], h.items[j]) > 0 }
func (h *keepHeap[K]) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.pos[h.items[i]] = i
	h.pos[h.items[j]] = j
}

func (h *keepHeap[K]) Push(x any) {
	k, ok := x.(K)
	if !ok {
		return
	}
	h.pos[k] = len(h.items)
	h.items = append(h.items, k)
}

func (h *keepHeap[K]) Pop() any {
	n := len(h.items) - 1
	k := h.items[n]
	var zero K
	h.items[n] = zero
	h.items = h.items[:n]
	delete(h.pos, k)
	return k
}

func (h *keepHeap[K]) add(k K) { heap.Push(h, k) }

func (h *keepHeap[K]) remove(k K) {
	if i, ok := h.pos[k]; ok {
		heap.Remove(h, i)
	}
}

// last returns the item kept last; ok is false for an empty heap.
func (h *keepHeap[K]) last() (k K, ok bool) {
	if len(h.items) == 0 {
		return k, false
	}
	return h.items[0], true
}
