// SPDX-License-Identifier: AGPL-3.0-or-later

package trust

import "sort"

func sortModules(m []ModuleReview) {
	sort.Slice(m, func(i, j int) bool { return m[i].Name < m[j].Name })
}

func sortActions(a []ActionReview) {
	sort.Slice(a, func(i, j int) bool { return a[i].ActionID < a[j].ActionID })
}
