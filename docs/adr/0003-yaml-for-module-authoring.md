# ADR 0003: YAML only for module authoring

Status: accepted, 2026-10-19

Spec 10 names `module.yaml` as the module manifest. Parsing YAML in the
executor would add a large parser to the security core, so the executor
never reads YAML: `nebula module pack` turns `module.yaml` into the
canonical JSON lock (`internal/modulelock`), the author signs the lock, and
the executor verifies and reads only the lock.

| Need | Library | License | Where |
| --- | --- | --- | --- |
| Reading `module.yaml` | `gopkg.in/yaml.v3` v3.0.1 | MIT and Apache-2.0 | `cmd/nebula` (`module pack`) only |

The rule of ADR 0002 stands: no new dependency in the security core
packages. `internal/modulelock`, `internal/sshsig` and `internal/prelude`
use the standard library, `golang.org/x/crypto/ssh` and the existing
canonicalization only.
