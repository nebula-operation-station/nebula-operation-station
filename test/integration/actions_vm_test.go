// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build integration

// Shipped read-only actions on the lab VMs (spec 08 / H05), run exactly as
// the executor runs them: the unchanged script from the actions registry,
// the canonical parameters document a grant carries, sshtransport with the
// host key pinned on first contact, and hostrun's own result classifier.
//
// Configuration is the one of ssh_vm_test.go (NEBULA_IT_TARGETS,
// NEBULA_IT_KEY, NEBULA_IT_KEY_PASSPHRASE, NEBULA_IT_USER); without it the
// test skips. With NEBULA_IT_DURABLE=1 every action runs as a durable job
// (hostrun.Dispatch, Check, Collect, Remove under DefaultJobConfig: needs
// the enrollment's NOPASSWD sudo and systemd); otherwise attached
// (hostrun.Attached), the executor's RunAttached path.
//
// The actions are the read-only, risk LOW ones the vulnerability agent
// needs for a Debian/Ubuntu host (ADR 0011 D3, permit.ReadOnlyAllowlist):
//
//	core.facts              distribution, to pick the parser's distro
//	package.list_installed  the package inventory (>= 10 packages)
//	package.list_updates    pending updates and their security share
//
// image.packages is left out: it needs an operator-installed Trivy and a
// local image digest on the VM. Write actions are never run here.
//
// Nothing in this file is a secret: the key and its passphrase are read
// from the environment only.
package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// minInstalledPackages is the least a real Debian/Ubuntu server has
// installed; fewer means the inventory was not read.
const minInstalledPackages = 10

// vulnReadActions are the shipped read-only LOW actions the vulnerability
// agent needs, in run order (core.facts first: it names the distro).
var vulnReadActions = []string{"core.facts", "package.list_installed", "package.list_updates"}

// randomExecutionID is a fresh UUIDv4, so a durable job left over from an
// aborted earlier run never collides with this one.
func randomExecutionID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// runAction runs one shipped action as the executor does and returns the
// classified result. Parameterless actions get the canonical "{}" a grant
// carries (actions.ParametersJSON, then canonical.CanonicalParameters).
func runAction(t *testing.T, ctx context.Context, c *ssh.Client, a actions.Action, durable bool) hostrun.Result {
	t.Helper()
	raw, err := a.ParametersJSON(map[string]string{}, nil)
	if err != nil {
		t.Fatalf("%s parameters: %v", a.ID, err)
	}
	params, _, err := canonical.CanonicalParameters(raw)
	if err != nil {
		t.Fatalf("%s canonical parameters: %v", a.ID, err)
	}
	id := randomExecutionID(t)
	if !durable {
		r, err := hostrun.Attached(ctx, c, id, params, a.Script, a.Timeout)
		if err != nil {
			t.Fatalf("%s attached: %v", a.ID, err)
		}
		return r
	}
	out, detail, err := hostrun.Dispatch(ctx, c, hostrun.DefaultJobConfig, id, params, a.Script, a.Timeout)
	if err != nil || out != hostrun.Dispatched {
		t.Fatalf("%s durable dispatch: %v %s %v", a.ID, out, detail, err)
	}
	defer func() {
		if err := hostrun.Remove(ctx, c, hostrun.DefaultJobConfig, id); err != nil {
			t.Errorf("%s durable remove: %v", a.ID, err)
		}
	}()
	deadline := time.Now().Add(a.Timeout + time.Minute)
	for {
		st, err := hostrun.Check(ctx, c, hostrun.DefaultJobConfig, id)
		if err != nil {
			t.Fatalf("%s durable check: %v", a.ID, err)
		}
		switch st.Phase {
		case "finished":
			r, err := hostrun.Collect(ctx, c, hostrun.DefaultJobConfig, id, st.ExitCode)
			if err != nil {
				t.Fatalf("%s durable collect: %v", a.ID, err)
			}
			return r
		case "dead", "missing":
			t.Fatalf("%s durable job is %s", a.ID, st.Phase)
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s durable job still %s after %s", a.ID, st.Phase, a.Timeout+time.Minute)
		}
		time.Sleep(time.Second)
	}
}

// distroOf maps core.facts' "OS ID" (os-release ID and VERSION_ID) to the
// parser's distro; the lab VMs are Debian or Ubuntu only.
func distroOf(t *testing.T, facts []executions.Fact) vulnver.Distro {
	t.Helper()
	for _, f := range facts {
		if f.Name != "OS ID" {
			continue
		}
		id, _, _ := strings.Cut(f.Value, " ")
		switch id {
		case "debian":
			return vulnver.DistroDebian
		case "ubuntu":
			return vulnver.DistroUbuntu
		}
		t.Fatalf("OS ID %q is neither debian nor ubuntu", f.Value)
	}
	t.Fatal("core.facts has no OS ID")
	return 0
}

func TestShippedReadActionsOnLabVM(t *testing.T) {
	// The set is what the executor treats as ordinary reads: shipped,
	// read-only, risk LOW, attached by declaration, in the read allowlist.
	// Checked before the VM configuration, so it holds without VMs too.
	acts := make(map[string]actions.Action, len(vulnReadActions))
	for _, id := range vulnReadActions {
		a, ok := actions.Lookup(id)
		if !ok {
			t.Fatalf("%s is not a shipped action", id)
		}
		if !a.ReadOnly || a.Risk != pb.RiskClass_RISK_CLASS_LOW || a.Durable || len(a.Params) != 0 || len(a.Secrets) != 0 {
			t.Fatalf("%s is not a parameterless read-only LOW action", id)
		}
		if !slices.Contains(permit.ReadOnlyAllowlist, id) {
			t.Fatalf("%s is not in permit.ReadOnlyAllowlist", id)
		}
		acts[id] = a
	}

	targets, signer, user := config(t)
	durable := os.Getenv("NEBULA_IT_DURABLE") == "1"
	var cfg sshtransport.Config
	for _, tg := range targets {
		t.Run(tg.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			pin, err := cfg.Probe(ctx, tg.endpoints[0])
			if err != nil {
				t.Fatalf("probe %s: %v", tg.endpoints[0], err)
			}
			c, err := cfg.Dial(ctx, sshtransport.Target{HostID: tg.name, Endpoints: tg.endpoints, User: user, HostKey: pin}, signer)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer c.Close()

			mode := "attached"
			if durable {
				mode = "durable"
			}
			var distro vulnver.Distro
			for _, id := range vulnReadActions {
				r := runAction(t, ctx, c.Client, acts[id], durable)
				if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
					t.Fatalf("%s (%s): class %s (%s), exit %d, log %q", id, mode, r.Class, r.Detail, r.ExitCode, r.Log)
				}
				switch id {
				case "core.facts":
					f := executions.DecodeFacts(r.Result)
					if len(f) == 0 {
						t.Fatalf("core.facts result unreadable (%d bytes)", len(r.Result))
					}
					distro = distroOf(t, f)
				case "package.list_installed":
					inv := osdebian.ParseInstalledResult(r.Result, osdebian.ReadStatus{ExitCode: r.ExitCode}, distro)
					if !inv.Complete || inv.Reason != "" || inv.Dropped != 0 {
						t.Fatalf("package.list_installed: complete=%v reason=%q dropped=%d", inv.Complete, inv.Reason, inv.Dropped)
					}
					if len(inv.Packages) < minInstalledPackages {
						t.Fatalf("package.list_installed: %d packages, want at least %d", len(inv.Packages), minInstalledPackages)
					}
					if !slices.ContainsFunc(inv.Packages, func(p osdebian.InstalledPackage) bool { return p.Name == "base-files" }) {
						t.Errorf("package.list_installed: base-files missing from %d packages", len(inv.Packages))
					}
					k := inv.RunningKernel
					t.Logf("%s %s: package.list_installed %d packages (%d bytes, limit %d), running kernel %s state %v %s %s",
						tg.name, mode, len(inv.Packages), len(r.Result), hostrun.MaxResult, k.Release, k.State, k.Source, k.Version)
				case "package.list_updates":
					u, err := osdebian.ParseUpdates(r.Result)
					if err != nil {
						t.Fatalf("package.list_updates unreadable: %v", err)
					}
					t.Logf("%s %s: package.list_updates %d updates (%d security, %d kernel), reboot required %v",
						tg.name, mode, len(u.Packages), u.Security, u.Kernel, u.RebootRequired)
				}
			}
		})
	}
}
