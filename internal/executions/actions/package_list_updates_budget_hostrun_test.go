// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// simulationBudgetMargin is the fixed margin package_list_updates.sh keeps
// out of the simulation budget.
const simulationBudgetMargin = 64

// simulationBudget is the byte budget package_list_updates.sh gives the
// simulation next to a document of skel bytes: sim_budget in the script.
func simulationBudget(skel int) int {
	return (hostrun.MaxResult - skel - simulationBudgetMargin) / 4 * 3
}

// listUpdatesScriptRun runs script through hostrun.Attached with path in
// front of it, the way the executor runs package.list_updates.
func listUpdatesScriptRun(t *testing.T, script []byte, path string) hostrun.Result {
	t.Helper()
	a, ok := Lookup("package.list_updates")
	if !ok {
		t.Fatal("package.list_updates is not registered")
	}
	s := "PATH='" + path + "'; export PATH\n" + string(script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), netHostrunExecutionID, []byte(`{}`), []byte(s), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// simulationSkeletonLen is the length of the document the script budgets
// from: the document with an empty simulation and no candidates. The host
// gives it (reboot and list-age fields are host facts), so the test does not
// copy them. An empty simulation prints exactly that document and a newline.
func simulationSkeletonLen(t *testing.T, script []byte) int {
	t.Helper()
	f := simulationHostWith(t, "", 1)
	r := listUpdatesScriptRun(t, script, f.bin+":/usr/bin:/bin")
	if r.Class != hostrun.ClassSuccess || len(r.Result) == 0 || r.Result[len(r.Result)-1] != '\n' {
		t.Fatalf("empty simulation: class %s, result %q", r.Class, r.Result)
	}
	return len(r.Result) - 1
}

// sizedSimulation is a simulation of exactly size bytes: whole Inst lines
// from simulationLine, then one padded Inst line that fills the rest. The
// byte total alone decides whether the budget cuts it.
func sizedSimulation(t *testing.T, size int) string {
	t.Helper()
	const minTail = 16
	var b strings.Builder
	for i := 1; ; i++ {
		line := simulationLine(i) + "\n"
		if size-b.Len()-len(line) < minTail {
			break
		}
		b.WriteString(line)
	}
	rest := size - b.Len()
	if rest < minTail {
		t.Fatalf("size %d: last line %d bytes, want at least %d", size, rest, minTail)
	}
	const prefix = "Inst \n"
	b.WriteString("Inst " + strings.Repeat("p", rest-len(prefix)) + "\n")
	if b.Len() != size {
		t.Fatalf("simulation is %d bytes, want %d", b.Len(), size)
	}
	return b.String()
}

// The simulation of exactly the budget is listed in full: the run succeeds,
// the simulate field is the whole simulation, and the result stays within
// hostrun.MaxResult with the candidates filling what is left.
func TestListUpdatesSimulationAtBudgetThroughHostrun(t *testing.T) {
	budget := simulationBudget(simulationSkeletonLen(t, packageListUpdates))
	sim := sizedSimulation(t, budget)
	f := simulationHostWith(t, sim, 1)
	r := listUpdatesScriptRun(t, packageListUpdates, f.bin+":/usr/bin:/bin")
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	if len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, over hostrun.MaxResult %d", len(r.Result), hostrun.MaxResult)
	}
	var doc map[string]any
	if err := json.Unmarshal(r.Result, &doc); err != nil {
		t.Fatal(err)
	}
	if got := requireDecodedField(t, doc, "simulate"); string(got) != sim {
		t.Fatalf("simulate has %d bytes, want the %d bytes of the simulation", len(got), len(sim))
	}
	requireBudgetUsed(t, r.Result)
}

// One byte more than the budget does not fit: the simulation is cut, and the
// run fails with exit status 5 and no result. The byte budget is the only
// thing that differs from the case above.
func TestListUpdatesSimulationOneOverBudgetFailsThroughHostrun(t *testing.T) {
	budget := simulationBudget(simulationSkeletonLen(t, packageListUpdates))
	f := simulationHostWith(t, sizedSimulation(t, budget+1), 1)
	r := listUpdatesScriptRun(t, packageListUpdates, f.bin+":/usr/bin:/bin")
	requireListUpdatesFailure(t, r)
}

// A script whose budget is too large by one base64 quad (3 bytes) lets the
// simulation one byte over the real budget through. The classifier used by
// the tests above must reject that result, so the test of the real budget
// would fail on such a script.
func TestListUpdatesBudgetTooLargeFailsClassifier(t *testing.T) {
	const orig = "sim_budget=$(( (max_result - ${#skel} - 64) / 4 * 3 ))"
	const mutated = "sim_budget=$(( (max_result - ${#skel} - 64) / 4 * 3 + 3 ))"
	if !bytes.Contains(packageListUpdates, []byte(orig)) {
		t.Fatal("the sim_budget line changed: update this test with it")
	}
	mutant := bytes.Replace(packageListUpdates, []byte(orig), []byte(mutated), 1)
	budget := simulationBudget(simulationSkeletonLen(t, packageListUpdates))
	f := simulationHostWith(t, sizedSimulation(t, budget+1), 1)
	r := listUpdatesScriptRun(t, mutant, f.bin+":/usr/bin:/bin")
	if err := listUpdatesFailure(r); err == nil {
		t.Fatalf("a budget of %d bytes admits a simulation of %d bytes, and the classifier accepts it", budget+3, budget+1)
	}
}

// Repository text can contain the cut marker: an Inst line that carries
// "nebula-apt-cut=1" is not a cut. The upgrade is listed in full, whether
// the text is in the middle of the simulation or on its last line.
func TestListUpdatesCutMarkerTextInInstLineIsNotACut(t *testing.T) {
	marked := "Inst libmarker1 [1.0-1] (1.0-2 Debian:12/stable [amd64]) nebula-apt-cut=1\n"
	cases := map[string]string{
		"middle": simulationText(2) + marked + simulationLine(3) + "\n",
		"last":   simulationText(2) + marked,
	}
	for name, sim := range cases {
		t.Run(name, func(t *testing.T) {
			f := simulationHostWith(t, sim, 1)
			r := listUpdatesScriptRun(t, packageListUpdates, f.bin+":/usr/bin:/bin")
			if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
				t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
			}
			var doc map[string]any
			if err := json.Unmarshal(r.Result, &doc); err != nil {
				t.Fatal(err)
			}
			if got := string(requireDecodedField(t, doc, "simulate")); got != sim {
				t.Fatalf("simulate has %d bytes, want the %d bytes of the simulation", len(got), len(sim))
			}
		})
	}
}

// A line longer than the whole budget is cut at the first line. That is the
// cut the marker check must still catch, with the marker as the first line
// of the stream.
func TestListUpdatesCutOnFirstLineFailsThroughHostrun(t *testing.T) {
	sim := fmt.Sprintf("Inst %s\n", strings.Repeat("q", hostrun.MaxResult))
	f := simulationHostWith(t, sim, 1)
	r := listUpdatesScriptRun(t, packageListUpdates, f.bin+":/usr/bin:/bin")
	requireListUpdatesFailure(t, r)
}
