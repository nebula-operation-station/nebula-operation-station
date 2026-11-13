# Security tests (M10-3)

Every acceptance criterion of spec 16 and every "Protected" line of the
threat model, with the tests that hold it and where they run. A criterion
without an automated test says so and names the lab check.

Where: **unit** and **acceptance** run in `make test` (CI, every PR);
**deploy** (the shell and Python tests under `deploy/`) in `make test-deploy`
(CI, every PR; `make check` runs it too); **privileged** in
`make test-privileged` (root, CI); **browser** in `make test-browser`;
**integration** in `make test-integration` against the OpenSSH test VMs (not
in CI; its only test is `TestRealOpenSSH`); **fuzz** in `make fuzz` (13
targets, not in CI; the seed corpora of all `Fuzz*` functions run in
`make test`, see [Fuzz targets](#fuzz-targets)); **lab** is the reference lab
before a release.

## Spec 16 acceptance criteria

| Milestone | Criterion | Tests | Where |
| --- | --- | --- | --- |
| 0 | The server user cannot read executor files | `TestM0Privileged_ServerUserCannotReadExecutorFiles`, `TestH02Privileged_ExecutorDBIsPrivateToTheExecutor`, `TestH02_DatabaseFileIsPrivate` | privileged, acceptance |
| 0 | An unknown UID is rejected | `TestM0_UnknownUIDIsRejected`, `TestM0Privileged_UnknownUIDIsRejectedAcrossProcesses` | acceptance, privileged |
| 0 | A script, host list or parameter swapped after approval is rejected | `TestM0_SubstitutionAfterApprovalIsRejected`, `TestM0_ChangedRequestNeedsNewApproval`, `TestM0_ParametersAreBoundAtProposal`, `TestM0_ExecutorComputesTheDigestItself` | acceptance |
| 0 | A replayed assertion is rejected | `TestM0_ReplayedAssertionIsRejected`, `TestH02_SignCountersSurviveRestart`, `TestH02_SpentExecutionIDsSurviveRestart` | acceptance |
| 1 | A clean install from the tarball starts all services locked | No automated test of a full install. `deploy/install_test.sh` (run by `make test-deploy`, which `make check` runs; CI job `test`, step `make test-deploy`, as root; previously: not run by CI) runs `install.sh` in dry-run mode for argument parsing and validation, admin users in `/etc/passwd`, and "dry run changes nothing"; it runs the unit refresh block in a temporary directory and checks the live-handoff spool and the server drop-in statically. Its root-only cases are skipped with a message unless root and a running systemd (`/run/systemd/system`) are present. The unit-recovery and `server.json` cases on install also need the release-tarball layout (`nebula-executor` next to `deploy/`), which a CI checkout does not have, so they are always skipped in CI. The uninstall drop-in cases need only root and systemd: CI runs them as root on the self-hosted `nos` runner if that host runs systemd (not verifiable from the repository); when they run, they execute `uninstall.sh` on the CI host, which removes the units and binaries. `TestH02_RestartRevokesPermitsAndStartsLocked` covers the locked start after a restart | lab: full install from the tarball on Debian 12, every service starts locked |
| 2 | After a reboot nothing executes until `nebula unlock` | `TestM0_LockedExecutorAuthorizesNothing`, `TestH02_RestartRevokesPermitsAndStartsLocked`, `TestH05_LockedKeyringConnectsNowhere` | acceptance |
| 2 | A recovery forces a new WebAuthn registration | `TestM2Recovery_ForcesNewRegistration`, `TestM2Recovery_CodeOnlyKeyNeedsConfirmationOnTheExecutorHost` | acceptance |
| 3 | A host with LAN and VPN endpoints falls back on TCP failure | `TestH05_PinnedHostFallsBackOnTCPFailure`, `TestH05_AuthFailureTriesNoOtherEndpoint`; integration: `TestRealOpenSSH` puts a closed local endpoint in front of the VM endpoints and checks the fallback against real OpenSSH (only with `NEBULA_IT_TARGETS` and `NEBULA_IT_KEY` set; not in CI) | acceptance, integration |
| 3 | A changed host key stops it and notifies | `TestH05_ChangedHostKeyStopsAndBlocksTheHost`, `TestH05_BlockSurvivesRestart`, `TestHostKeyWatcherNotifiesOncePerBlock` | acceptance, unit |
| 4 | Killing Nebula during a durable job and restarting reconciles without a re-run | `TestM4_DurableJobSurvivesAnExecutorRestart`, `TestM4_DurableJobStartsOncePerHost`, `TestM4_DurableJobThatDiesIsInterruptedNotRerun` | acceptance; integration: `TestRealOpenSSH` with `NEBULA_IT_DURABLE=1` runs one harmless durable job on the OpenSSH VMs (the restart cases are acceptance only) |
| 5 | Security updates on Debian 12 and Ubuntu 24.04 as a durable job; reboot waits and reports `host_not_returned` | `TestM5_InstallSecurityRunsAsDurableJob`, `TestM5_RebootWaitsForANewBoot`, the `internal/executions/osdebian` parser tests | acceptance, lab (real hosts) |
| 5 | A held dpkg lock ends as `precheck_failed`; Proxmox gets `full-upgrade` | No automated test (the host scripts are not executed by any test) | lab: hold `flock /var/lib/dpkg/lock-frontend sleep 600` on a Debian 12 VM and install updates; enroll a Proxmox host and check that the planned command is `apt-get full-upgrade` |
| 6 | A failing canary stops the rollout | `TestM6_FailingCanaryStopsTheRollout`, `TestM6_AbortStopsTheRollout` | acceptance |
| 6 | A HIGH gate demands a fresh assertion | `TestM6_HighGateDemandsAFreshAssertion`, `TestM6_StagePlanIsPartOfTheApproval` | acceptance |
| 7 | An unverified root script is at least HIGH | `TestM7_UnverifiedRootScriptIsAtLeastHigh`, `TestH01_UntrustedArtifactIsAtLeastHigh`, `TestM7_SignedModules` | acceptance |
| 7 | A module UI cannot inject script | `TestModuleUICannotInjectScript` (internal/web/ui), `FuzzParse` (modulelock) | unit, fuzz |
| 8 | (no criterion) Docker results are untrusted | `FuzzParsers` (dockerhost), the dockerhost tests | unit, fuzz |
| 9 | (no criterion) scan results are untrusted; discovery runs only fixed Nmap arguments for known networks | `TestValidateRefuses`, `FuzzJobArgs`, `FuzzParseNmapXML`, `TestSpool` (discoveryjob); `TestSubmitChecksTargets`, `TestPollClassifyImport` (discovery); `TestDiscoveryFlow` | unit, fuzz, browser |
| 10 | Executor events are signed; a changed, reordered or dropped event fails | `TestExecutorEventsAreSignedAndChained`, `TestChainVerifies`, `TestEventKeyHistory`, `TestEventsVerifyAndList` | acceptance, unit |
| 10 | A backup never holds a secret in plaintext; restore is checked and CRITICAL | `TestBackupExecutorPart`, `TestRoundTrip`, `TestReadRefusesTampering`, `TestRestore`, `TestBackupAndRestoreFiles`, `FuzzRead` | acceptance, unit, fuzz |

## Threat model, "Protected"

| Threat | Tests |
| --- | --- |
| Compromised web process | `TestM0_ServerRoleCannotUseAdminMethods`, `TestH01_ServerRoleCannotChangeRiskData`, `TestM2_NoRPCReturnsSecretValues`, `TestM2_VaultIsAdminOnly`, `TestM7_SignerAdministrationIsAdminOnly`, `TestBackupExecutorPart` (server role refused) |
| Script, host list or parameters swapped after approval | see milestone 0 above |
| Replayed WebAuthn assertion | see milestone 0 above |
| Risk mislabelling by a compromised server | `TestH01_HighActionProposedAsLowIsRejected`, `TestH01_RelabelledCriticalHostIsNotLow`, `TestH01_HostCriticalityRaisesTheFloor`, `TestM7_UnverifiedRootScriptIsAtLeastHigh`, the scanner tests (`TestLongLineCountsHigh`, `FuzzScan`) |
| Unauthenticated or replayed WebAuthn registration | the `TestH03_*` tests |
| Another local user talking to the executor | `TestM0_UnknownUIDIsRejected`, `TestM0Privileged_UnknownUIDIsRejectedAcrossProcesses` |
| Malicious managed host | `FuzzParsers` (dockerhost, osdebian), `FuzzOneJSONDocument`, `TestOneJSONDocumentRefusesDuplicateMembers`, `TestUpdatesAreShownAsText` |
| Silent host-key change, man in the middle | `TestH05_ChangedHostKeyStopsAndBlocksTheHost`, `TestH05_TargetFingerprintMustMatchThePin`, `TestH05_NoConnectionBeforePin` |
| Key spraying across endpoints, fail2ban lockout | `TestH05_AuthFailureTriesNoOtherEndpoint` |
| Secrets reaching anything but the host | `TestM7_SecretsReachOnlyTheHost`, `TestM2_NoRPCReturnsSecretValues` |
| Forged or rewritten history | `TestExecutorEventsAreSignedAndChained`, `TestEventsAreAppendOnly`, `TestAuditLog` |
| A module or update from an untrusted author | `TestM7_SignedModules`, `TestConfirmSignerNeedsTheTypedFingerprint`, `TestReservedMustBeEmpty`, `TestParseRefusesNonCanonicalBytes` |
| A module UI injecting script | `TestModuleUICannotInjectScript` |
| A compromised server misusing discovery | `TestValidateRefuses`, `FuzzJobArgs`, `TestSpool`, `TestRunWritesResults`, `TestSubmitChecksTargets` |
| Hostile scan results | `FuzzParseNmapXML`, `TestParseNmapXML`, `TestPollClassifyImport`, `TestDiscoveryFlow` |
| A backup leaking secrets, or a tampered restore | `TestBackupExecutorPart`, `TestRoundTrip`, `TestReadRefusesTampering`, `TestRestore` |

## Fuzz targets

`make fuzz` (`Makefile`, target `fuzz`) runs 13 fuzz functions for 20
seconds each. It is not run by CI. The table lists every `Fuzz*` function
in the repository (117, previously: 111, from `grep -rn '^func Fuzz' --include=*_test.go .`)
with its package and whether `make fuzz` runs it. Functions marked "no"
are not run by `make fuzz`; their seed corpora still run in `make test`
like every other test.

| Package | Fuzz functions | In `make fuzz` |
| --- | --- | --- |
| `internal/backup` | `FuzzRead` | yes |
| `internal/canonical` | `FuzzHashParameters`, `FuzzParseBatch`, `FuzzBatchGraphAndLimits` | yes: `FuzzHashParameters`; no: `FuzzParseBatch`, `FuzzBatchGraphAndLimits` |
| `internal/cbscli` | `FuzzParsePrompt`, `FuzzLooksInteractive` | no |
| `internal/cbsparse` | `FuzzParseVLANs`, `FuzzParseLLDPNeighbors`, `FuzzParseLLDPNeighborDetail`, `FuzzParseMACTable`, `FuzzParseInterfaces`, `FuzzParseVersion` | no |
| `internal/discoveryjob` | `FuzzParseNmapXML`, `FuzzJobArgs` | yes |
| `internal/executions/actions/netfacts` | `FuzzStrictKeysMatchJSON`, `FuzzDecode` | no |
| `internal/executions/dockerhost` | `FuzzParsers`, `FuzzParseImagePackages`, `FuzzParseUpdatePreview`, `FuzzParseUpdatePrepare`, `FuzzParseListBounds`, `FuzzParseLogsBounds`, `FuzzParseInspectBounds`, `FuzzParseControlBounds`, `FuzzParseComposeUpdateBounds`, `FuzzParseImageUpdatesBounds`, `FuzzParseStats`, `FuzzParseImageVulns` | yes: `FuzzParsers`; no: the other 11 |
| `internal/executions/gpuhost` | `FuzzParsePCIInventory`, `FuzzParseGPUStatus`, `FuzzParseGPUStatusUnavailable` | no |
| `internal/executions/hostmetrics` | `FuzzParseMetrics`, `FuzzParseFilesystems`, `FuzzParseMetricsRoundTrip`, `FuzzParseMetricsBounds`, `FuzzParseFilesystemsBounds` | no |
| `internal/executions/osdebian` | `FuzzParsers`, `FuzzParseInstalled` | yes: `FuzzParsers`; no: `FuzzParseInstalled` |
| `internal/fimbaseline` | `FuzzDiff` | no |
| `internal/fimscan` | `FuzzParse` | no |
| `internal/helpdocs` | `FuzzBuild` | no |
| `internal/hostrun` | `FuzzOneJSONDocument` | yes |
| `internal/iconstore` | `FuzzSanitize` | no |
| `internal/inventory/csvimport` | `FuzzParse` | yes |
| `internal/modules` | `FuzzUnpack` | yes |
| `internal/modulelock` | `FuzzParse` | yes |
| `internal/netadvisor` | `FuzzRuleInputs` | no |
| `internal/netdevcontract` | `FuzzDecodeDevice`, `FuzzDecodeObservation`, `FuzzCheckXML`, `FuzzCheckLines` | no |
| `internal/netfacts` | `FuzzParseSockets`, `FuzzParseNeighBounds`, `FuzzParseRoutesBounds`, `FuzzParseAddrsBounds`, `FuzzParseLinksBounds`, `FuzzParseBridgeVLANBounds` | no |
| `internal/netreach` | `FuzzEvaluate`, `FuzzParseLiterals`, `FuzzPlace` | no |
| `internal/pairing` | `FuzzParse` | no |
| `internal/panapi` | `FuzzParseNATRules`, `FuzzParseSecurityRules`, `FuzzParseJob`, `FuzzParseObjects`, `FuzzParseRuleHitCounts`, `FuzzParseZones` | no |
| `internal/pveapi` | `FuzzListQemu`, `FuzzListLxc`, `FuzzListNodes`, `FuzzGetQemuConfig`, `FuzzGetLxcConfig`, `FuzzClusterStatus`, `FuzzHAStatus`, `FuzzListSnapshots`, `FuzzReadBackups`, `FuzzAgentOSInfo`, `FuzzAgentNetworkInterfaces`, `FuzzAgentFSInfo`, `FuzzNodeTasks`, `FuzzListStorages`, `FuzzNodeStatus`, `FuzzGuestStatus`, `FuzzNodeRRDData`, `FuzzGuestRRDData` | no |
| `internal/pvecontract` | `FuzzDecodeRemote`, `FuzzDecodeObservation` | no |
| `internal/registrymeta` | `FuzzLatestStable` | no |
| `internal/release` | `FuzzParseInstalledFiles`, `FuzzVerifyInstalledFiles`, `FuzzReadUstar`, `FuzzParseManifest` | no |
| `internal/scanner` | `FuzzScan` | yes |
| `internal/softwarecat` | `FuzzNormalizers` | no |
| `internal/sshsig` | `FuzzParse` | yes |
| `internal/stageplan` | `FuzzParse` | no |
| `internal/textdiff` | `FuzzDiff` | no |
| `internal/vulnfeed` | `FuzzParseEPSS`, `FuzzParseOSV`, `FuzzParseOSVArchive`, `FuzzParseDebianTracker`, `FuzzParseDebianAdvisoryList`, `FuzzParseKEV`, `FuzzParseNVD` | no |
| `internal/vulnfeed/reputation` | `FuzzParseEntry`, `FuzzForEachRecord` | no |
| `internal/vulnfinding` | `FuzzParseRecord` | no |
| `internal/vulnmatch` | `FuzzMatchVersions` | no |
| `internal/vulnprio` | `FuzzCompute` | no |
| `internal/vulnver` | `FuzzCompareDpkg`, `FuzzCompareAPK`, `FuzzOSVAffected`, `FuzzSchemeForEcosystem`, `FuzzRunningKernel`, `FuzzSourceVersionBasis` | no |
| `internal/web/api/trafficmap` | `FuzzCleanText` | no |
| `internal/webauthnverify` | `FuzzVerifyNeverPanics` | yes |

`internal/webauthnreg` (registration and login JSON from the browser) has
no fuzz target of its own: the parsing is the webauthn library's, and the
package is a protected path.

Before a release, run each `make fuzz` target for at least an hour
(`go test -run='^$' -fuzz=NAME -fuzztime=1h ./PKG`).

**Open:** 104 fuzz functions (the "no" rows; previously: 98) are not run by `make fuzz`,
and CI runs no fuzz target at all, although the M10-3 plan in
`docs/implementation/m10-plan.md` expects CI to run them briefly. Proposal
for a separate ticket on the protected `Makefile` (not done here): add the
parsers of untrusted managed-host and device input first (`internal/pveapi`,
`internal/panapi`, `internal/netdevcontract`, `internal/netfacts`,
`internal/cbsparse`, `internal/cbscli`, `internal/executions/*` except the
`FuzzParsers` ones, `internal/vulnfeed`, `internal/vulnfeed/reputation`,
`internal/release`), then decide with the maintainer
whether `make fuzz` should list them all or a nightly CI job should run
them, since the protected paths include `.github/`.
