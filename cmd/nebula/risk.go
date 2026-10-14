// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Executor-held risk data (H01). The executor rejects proposals whose
// risk_class is below what it derives from these entries; see
// internal/riskpolicy.

func artifactCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nebula artifact trust|untrust|list")
	}
	switch args[0] {
	case "trust":
		return artifactTrust(ctx, c, args[1:], os.Stdin)
	case "untrust":
		return artifactUntrust(ctx, c, args[1:])
	case "list":
		return artifactList(ctx, c, os.Stdout)
	default:
		return fmt.Errorf("unknown artifact command %q", args[0])
	}
}

func artifactTrust(ctx context.Context, c pb.ExecutorServiceClient, args []string, stdin io.Reader) error {
	fs := flag.NewFlagSet("artifact trust", flag.ContinueOnError)
	action := fs.String("action", "", "action_id, e.g. patching.install_security")
	version := fs.String("version", "", "module_version, e.g. 1.0.0")
	risk := fs.String("risk", "", "declared risk: LOW, MEDIUM, HIGH or CRITICAL")
	label := fs.String("label", "", "free text shown by `nebula artifact list`")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *action == "" || *version == "" || *risk == "" {
		return errors.New("usage: nebula artifact trust --action ID --version X.Y.Z --risk LEVEL [--label TEXT] FILE")
	}
	rc, err := parseRisk(*risk)
	if err != nil {
		return err
	}
	b, err := readArtifact(fs.Arg(0))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	sumHex := hex.EncodeToString(sum[:])
	existing, err := c.ListTrustedArtifacts(ctx, &pb.ListTrustedArtifactsRequest{})
	if err != nil {
		return err
	}

	fmt.Println("Trust this artifact on the executor?")
	fmt.Printf("  file           %s (%d bytes)\n", fs.Arg(0), len(b))
	fmt.Printf("  sha256         %s\n", sumHex)
	fmt.Printf("  action         %s @ %s\n", *action, *version)
	fmt.Printf("  declared risk  %s\n", shortRisk(rc))
	for _, a := range existing.GetArtifacts() {
		if a.GetArtifactSha256() == sumHex && (a.GetActionId() != *action || a.GetModuleVersion() != *version) {
			fmt.Printf("  NOTE: the same bytes are already trusted as %s for %s@%s;\n", shortRisk(a.GetRiskClass()),
				displaySafe([]byte(a.GetActionId()), 129), displaySafe([]byte(a.GetModuleVersion()), 20))
			fmt.Println("        the executor uses the highest level of these bytes for every action.")
		}
	}
	if rc == pb.RiskClass_RISK_CLASS_LOW {
		fmt.Println("  LOW: inside a privileged session permits are issued without a WebAuthn tap on")
		fmt.Println("  hosts recorded LOW to HIGH. The server chooses the parameters. Use LOW only for")
		fmt.Println("  scripts that are read-only and harmless for ANY parameter values.")
	}
	fmt.Print("Type 'yes' to trust: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("not trusted")
	}
	// The executor hashes the bytes itself and stores nothing if its hash
	// differs from the one shown here.
	resp, err := c.TrustArtifact(ctx, &pb.TrustArtifactRequest{
		ActionId: *action, ModuleVersion: *version, RiskClass: rc, Artifact: b, Label: *label, ExpectedSha256: sumHex,
	})
	if err != nil {
		return err
	}
	if resp.GetArtifactSha256() != sumHex {
		return fmt.Errorf("executor reported sha256 %q, expected %s", resp.GetArtifactSha256(), sumHex)
	}
	fmt.Printf("trusted: %s %s@%s as %s\n", resp.GetArtifactSha256(), *action, *version, shortRisk(rc))
	return nil
}

func readArtifact(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, permit.MaxArtifactSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > permit.MaxArtifactSize {
		return nil, fmt.Errorf("artifact size must be 1..%d bytes", permit.MaxArtifactSize)
	}
	return b, nil
}

func artifactUntrust(ctx context.Context, c pb.ExecutorServiceClient, args []string) error {
	fs := flag.NewFlagSet("artifact untrust", flag.ContinueOnError)
	action := fs.String("action", "", "action_id")
	version := fs.String("version", "", "module_version")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *action == "" || *version == "" {
		return errors.New("usage: nebula artifact untrust --action ID --version X.Y.Z SHA256")
	}
	resp, err := c.UntrustArtifact(ctx, &pb.UntrustArtifactRequest{ArtifactSha256: fs.Arg(0), ActionId: *action, ModuleVersion: *version})
	if err != nil {
		return err
	}
	if !resp.GetRemoved() {
		return errors.New("no such trusted artifact")
	}
	fmt.Println("untrusted; proposals with this artifact need at least HIGH again")
	return nil
}

func artifactList(ctx context.Context, c pb.ExecutorServiceClient, w io.Writer) error {
	resp, err := c.ListTrustedArtifacts(ctx, &pb.ListTrustedArtifactsRequest{})
	if err != nil {
		return err
	}
	if len(resp.GetArtifacts()) == 0 {
		fmt.Fprintln(w, "no trusted artifacts: every proposal needs at least HIGH")
		return nil
	}
	for _, a := range resp.GetArtifacts() {
		fmt.Fprintf(w, "%s  %-8s %s@%s  %s  by %s  %s\n",
			displaySafe([]byte(a.GetArtifactSha256()), 64), shortRisk(a.GetRiskClass()),
			displaySafe([]byte(a.GetActionId()), 129), displaySafe([]byte(a.GetModuleVersion()), 20),
			time.Unix(a.GetTrustedAtUnix(), 0).Format("2006-01-02"),
			displaySafe([]byte(a.GetTrustedBy()), 64), displaySafe([]byte(a.GetLabel()), 200))
	}
	return nil
}

func hostCmd(ctx context.Context, c pb.ExecutorServiceClient, args []string) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		return hostList(ctx, c, os.Stdout)
	case (len(args) == 3 || len(args) == 4) && args[0] == "criticality":
		// HOST LEVEL binds to the pinned key; HOST FINGERPRINT LEVEL for a
		// host that is not pinned yet (or to check the pin).
		fp := ""
		if len(args) == 4 {
			fp = args[2]
		}
		rc, err := parseRisk(args[len(args)-1])
		if err != nil {
			return err
		}
		resp, err := c.SetHostCriticality(ctx, &pb.SetHostCriticalityRequest{
			HostId: args[1], HostKeyFingerprint: fp, Criticality: rc,
		})
		if err != nil {
			return err
		}
		fmt.Printf("%s (%s): criticality %s\n", args[1], displaySafe([]byte(resp.GetHostKeyFingerprint()), 60), shortRisk(rc))
		return nil
	case len(args) >= 1 && args[0] == "probe":
		return hostProbe(ctx, c, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "pin":
		return hostPin(ctx, c, args[1:], os.Stdin, os.Stdout)
	case len(args) >= 1 && args[0] == "unpin":
		return hostUnpin(ctx, c, args[1:], os.Stdin, os.Stdout)
	case len(args) == 1 && args[0] == "keys":
		return hostKeys(ctx, c, os.Stdout)
	case len(args) >= 1 && args[0] == "test":
		return hostTest(ctx, c, args[1:], os.Stdout)
	case len(args) >= 1 && args[0] == "enroll-script":
		return hostEnrollScript(ctx, c, args[1:], os.Stdout)
	case len(args) == 2 && args[0] == "clear":
		resp, err := c.SetHostCriticality(ctx, &pb.SetHostCriticalityRequest{HostId: args[1], Clear: true})
		if err != nil {
			return err
		}
		if resp.GetChanged() {
			fmt.Printf("%s: record removed; the host counts as unrecorded (HIGH)\n", args[1])
		} else {
			fmt.Printf("%s: no record\n", args[1])
		}
		return nil
	default:
		return errors.New(hostUsage)
	}
}

const hostUsage = `usage: nebula host criticality HOST [SHA256:FINGERPRINT] LOW|MEDIUM|HIGH|CRITICAL
       nebula host clear HOST
       nebula host list
For a pinned host (nebula host keys) the record binds to the pinned key and the
fingerprint can be left out. Otherwise FINGERPRINT is the host's key: check it on
the host itself with ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
(not with ssh-keyscan).

` + hostKeysUsage

func hostList(ctx context.Context, c pb.ExecutorServiceClient, w io.Writer) error {
	resp, err := c.ListHostCriticality(ctx, &pb.ListHostCriticalityRequest{})
	if err != nil {
		return err
	}
	if len(resp.GetHosts()) == 0 {
		fmt.Fprintln(w, "no host records: every host counts as unrecorded (HIGH for actions above LOW)")
		return nil
	}
	for _, h := range resp.GetHosts() {
		fmt.Fprintf(w, "%-32s %-50s %-8s %s  by %s\n", displaySafe([]byte(h.GetHostId()), 63),
			displaySafe([]byte(h.GetHostKeyFingerprint()), 50), shortRisk(h.GetCriticality()),
			time.Unix(h.GetUpdatedAtUnix(), 0).Format("2006-01-02"), displaySafe([]byte(h.GetUpdatedBy()), 64))
	}
	return nil
}

func parseRisk(s string) (pb.RiskClass, error) {
	switch strings.ToUpper(s) {
	case "LOW":
		return pb.RiskClass_RISK_CLASS_LOW, nil
	case "MEDIUM":
		return pb.RiskClass_RISK_CLASS_MEDIUM, nil
	case "HIGH":
		return pb.RiskClass_RISK_CLASS_HIGH, nil
	case "CRITICAL":
		return pb.RiskClass_RISK_CLASS_CRITICAL, nil
	default:
		return 0, fmt.Errorf("unknown risk %q (LOW, MEDIUM, HIGH, CRITICAL)", s)
	}
}
