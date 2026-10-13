# Vendored static assets

Third-party files in this directory are pinned. To update one: download it
from the official upstream release only, verify the bytes, and update this
table in the same commit. Hashes are computed with `sha256sum`; never copy
a hash from a third party.

| File | Upstream | Version | Source URL | SHA-256 |
| --- | --- | --- | --- | --- |
| `htmx.min.js` | [bigskysoftware/htmx](https://github.com/bigskysoftware/htmx) | 4.0.0 | https://github.com/bigskysoftware/htmx/releases/download/v4.0.0/htmx-4.0.0-dist.zip (entry `dist/htmx.min.js`) | `e484d9171a9db30a39c8f16e3d709d4137f3211c659f8e6125816635033d593f` |

Cross-check: the same bytes were fetched from
https://unpkg.com/htmx.org@4.0.0/dist/htmx.min.js and are identical
(same SHA-256).
