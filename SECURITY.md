# Security policy

Nebula Operation Station holds credentials with root access to managed hosts. We treat security reports as the highest priority.

## Reporting a vulnerability

Please report privately through **GitHub Security Advisories** ("Report a vulnerability" on the repository's Security tab). Do not open a public issue.

Include what you found, how to reproduce it, the affected version or commit, and the impact you expect. We confirm receipt within 7 days and agree on a disclosure date with you.

## Supported versions

Before 1.0 only the latest release and `main` receive security fixes.

## Scope

In scope: the executor trust boundary, permit binding, WebAuthn verification, credential handling, host-input parsing, the module trust model, release signing.

Out of scope, as documented in `docs/threat-model.md`: root compromise of the Nebula machine, malicious administrators, compromised authenticators.
