// SPDX-License-Identifier: AGPL-3.0-or-later

package backup

import "io"

func writeWithManifest(w io.Writer, m Manifest, files []File) error {
	return writeArchive(w, m, files, nil)
}
