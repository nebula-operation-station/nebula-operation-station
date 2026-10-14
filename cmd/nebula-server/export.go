// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
)

// exportActions writes the built-in action scripts so that the admin can
// read them and trust them on the executor host (`nebula artifact trust`).
// A trusted script's minimum risk is the level the admin gives it, instead
// of HIGH for an unknown script (spec 10). The directory must not exist:
// nothing is overwritten.
func exportActions(dir string, w io.Writer) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("export actions: %w", err)
	}
	fmt.Fprintf(w, "Built-in action scripts written to %s. Read them, then trust the ones you want on the executor host:\n\n", dir)
	for _, a := range actions.Builtin {
		name := strings.ReplaceAll(a.ID, ".", "_") + "-" + a.Version + ".sh"
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, a.Script, 0o644); err != nil {
			return fmt.Errorf("export actions: %w", err)
		}
		risk := strings.TrimPrefix(a.Risk.String(), "RISK_CLASS_")
		fmt.Fprintf(w, "  # %s (sha256 %s)\n  nebula artifact trust --action %s --version %s --risk %s --label %q %s\n\n",
			a.Title, a.SHA256(), a.ID, a.Version, risk, "built-in "+a.ID, p)
	}
	fmt.Fprintln(w, "The risk shown is the declared one; you may trust a script at a higher level. Host criticality can still raise it.")
	return nil
}
