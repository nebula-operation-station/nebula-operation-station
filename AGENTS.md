# AGENTS.md

Instructions for AI coding agents (and humans) working in this repository. Read this file completely before every task.

## What this project is

Nebula Operation Station is an open-source operations control plane for Linux homelabs. It holds SSH keys that give root on every managed host. **A bug here can compromise a whole lab.** Correctness and security come before speed.

- Specification: `docs/spec/` (frozen; index in `docs/spec/00-index.md`). Read only the files your task references.
- Current state and known gaps: `docs/implementation/m0.md`.
- Language: Go. Module requires Go 1.26; development uses Go 1.27.

## Your workflow for every task

1. Read the issue. It names the spec sections, the files you may change and the acceptance criteria.
2. Read the referenced spec files and the existing code you will touch. Do not read the whole repository.
3. Write or extend tests first, in files you are allowed to change. Each acceptance criterion becomes at least one test.
4. Implement the smallest change that makes the tests pass.
5. Run `make check`. It must pass completely. Fix failures; never work around them.
6. Commit on a branch named `agent/<issue-number>-<short-slug>`, one logical change per commit, message format below.
7. Finish with a short summary: what changed, how it was tested, open questions. **Never push.** A human reviews and pushes.

If the task is unclear, contradicts the spec, or seems to need a change in a protected path: stop, do not guess, and write the question into your summary.

## Hard rules

1. **Never modify protected paths** (list below). The pre-commit hook and CI reject it. If your task needs such a change, stop and explain why in your summary.
2. **Never weaken, skip or delete a test** to make the build green. No `t.Skip`, no loosened assertions, no changed golden values, no commented-out tests.
3. **No new dependencies** unless the issue explicitly allows the named module. Never edit `go.mod` or `go.sum` otherwise.
4. **No self-written cryptography.** Use `crypto/*`, `golang.org/x/crypto`, and the libraries listed in `docs/adr/0002-m0-libraries.md`.
5. **Never call the `ssh` binary** or any shell from Go production code. SSH uses `golang.org/x/crypto/ssh` only. No CGO.
6. **Everything from a managed host is untrusted input.** Validate with explicit size limits, UTF-8 checks and schemas. Render it as text only.
7. **Secrets never appear** in logs, errors, results, test fixtures or commit messages.
8. **No network access in tests** other than loopback and Unix sockets in temporary directories.
9. **No panics in library code.** Return wrapped errors with context: `fmt.Errorf("load host %s: %w", id, err)`.
10. **Do not change generated code by hand.** Edit `proto/` (protected) and run `make generate`.

## Protected paths

Changes here need a human. The authoritative list is `.github/protected-paths.txt`:

- `AGENTS.md`, `.github/`, `.githooks/`, `Makefile`, `go.mod`, `go.sum`
- `docs/spec/`, `docs/adr/`, `docs/threat-model.md`
- `proto/`
- `internal/canonical/`, `internal/permit/`, `internal/peercred/`, `internal/keyring/`, `internal/webauthnverify/`, `internal/fsguard/`, `internal/executor/roles.go`
- `test/security/`
- `deploy/systemd/`

## Definition of done

`make check` passes. It runs:

- `gofmt` (no diff)
- `go vet ./...`
- `go test -race ./...`
- `staticcheck` (under Go 1.26.9, see `docs/implementation/m0.md`)
- `buf lint` and a check that generated code is up to date
- `govulncheck ./...`

New code also needs:

- an SPDX header `// SPDX-License-Identifier: AGPL-3.0-or-later` as the first line of every new Go file,
- doc comments on all exported identifiers,
- tests for every error path that matters for security (rejections, limits, malformed input).

## Code conventions

- Standard library first. `log/slog` for logging (JSON in services). `context.Context` is the first parameter of anything that does I/O.
- Packages under `internal/` only. One package, one responsibility. No `utils` or `common` packages.
- Errors: sentinel errors for conditions callers branch on, `errors.Is`/`errors.As` to check them.
- Limits are named constants next to the code that enforces them.
- Table-driven tests; name tests after the behaviour: `TestHostKeyMismatchStopsRun`.
- Time is injected (`Now func() time.Time`) wherever behaviour depends on it.

## Commit messages

```
<area>: <imperative summary, max 72 chars>

Why the change is needed, in one or two sentences.
Spec: docs/spec/<file>.md
Issue: #<number>
Tests: <what you ran>
```

Example: `inventory: add host CRUD with endpoint ordering`.

## Environment notes

- Agent commits are authored as `nos-coder (local AI) <nos-coder@localhost>`; this identity is what the protected-path checks look for.
- `make test-privileged` needs root; do not run it. CI runs it.
- If `make check` fails on something outside your task, report it; do not fix unrelated code in the same branch.
