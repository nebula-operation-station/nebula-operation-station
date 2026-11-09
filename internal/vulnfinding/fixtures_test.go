// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

// Reference records. Host and device IDs are synthetic; no lab names.

const validHostJSON = `{
  "subject_kind": "host",
  "subject_ref": {"id": "web01"},
  "ecosystem": "debian:bookworm",
  "component": {
    "source_package": "openssl",
    "source_version": "3.0.15-1~deb12u1",
    "binaries": [
      {"name": "libssl3", "version": "3.0.15-1~deb12u1"},
      {"name": "openssl", "version": "3.0.15-1~deb12u1"}
    ]
  },
  "vuln": {"id": "CVE-2024-12345", "aliases": ["DSA-5000-1", "DLA-4000-1"]},
  "fix": {"state": "fixed", "version": "3.0.16-1~deb12u1"},
  "tracker_state": "fixed",
  "match_basis": "distro_tracker",
  "scores": {
    "cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8, "source": "nvd"},
    "kev": {"date_added": "2025-01-15"},
    "epss": {"probability": 0.42, "percentile": 0.97, "date": "2025-02-01"}
  },
  "evidence": {
    "basis_sources": [
      {"source_id": "debian-tracker", "snapshot_id": "sha256-0a1b2c", "integrity": "none"},
      {"source_id": "kev", "snapshot_id": "kev-2025-02-01", "integrity": "none"}
    ],
    "matcher_version": "1.4.0"
  },
  "assessment": {
    "text": "Backport present in deb12u1? Check changelog.\nLikely reachable.",
    "backport_checked": true,
    "likely_false_positive": false,
    "exploit_public": true
  }
}`

// validHostJSONReordered is validHostJSON with other key order and spacing.
const validHostJSONReordered = `{"vuln":{"aliases":["DSA-5000-1","DLA-4000-1"],"id":"CVE-2024-12345"},
"ecosystem":"debian:bookworm","subject_ref":{"id":"web01"},"subject_kind":"host",
"match_basis":"distro_tracker","tracker_state":"fixed","fix":{"version":"3.0.16-1~deb12u1","state":"fixed"},
"component":{"source_version":"3.0.15-1~deb12u1","source_package":"openssl"},
"evidence":{"matcher_version":"1.4.0","basis_sources":[{"integrity":"none","snapshot_id":"x","source_id":"debian-tracker"}]}}`

const validImageJSON = `{
  "subject_kind": "image",
  "subject_ref": {"id": "dock01", "image_digest": "sha256:abababababababababababababababababababababababababababababababab"},
  "ecosystem": "alpine:3.20",
  "component": {"source_package": "musl", "source_version": "1.2.5-r0"},
  "vuln": {"id": "CVE-2025-1111"},
  "fix": {"state": "no_fix_yet"},
  "match_basis": "osv_range",
  "evidence": {
    "basis_sources": [{"source_id": "osv", "snapshot_id": "osv-20250201", "integrity": "none"}],
    "matcher_version": "1.4.0"
  }
}`

const validDeviceJSON = `{
  "subject_kind": "device",
  "subject_ref": {"id": "fw-edge"},
  "ecosystem": "vendor:paloalto:panos",
  "component": {"model": "PA-440", "firmware": "11.1.2-h3"},
  "vuln": {"id": "CVE-2024-3400", "aliases": ["PAN-SA-2024-0004"]},
  "fix": {"state": "fixed", "version": "11.1.2-h4"},
  "match_basis": "vendor_advisory",
  "scores": {"cvss": {"version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "base_score": 10, "source": "vendor"}},
  "evidence": {
    "basis_sources": [{"source_id": "paloalto-csaf", "snapshot_id": "csaf-7", "integrity": "signed"}],
    "matcher_version": "1.4.0"
  }
}`
