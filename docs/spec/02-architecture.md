<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Architecture and trust boundary

```
            Browser (WebAuthn)                    nebula CLI (admin UID)
                  |  HTTPS                          unlock / approve / lock
                  v                                         |
          Reverse proxy (TLS, fixed hostname)               |
                  |  localhost                              |
+-----------------v-----------------------------------------v---------------+
| Nebula machine - one OS user per role                                     |
|                                                                           |
|  nebula-server  ---- gRPC over Unix socket ---->  nebula-executor         |
|  web UI, inventory,   (SO_PEERCRED decides)       keyring, vault, permits,|
|  planning, read API                               WebAuthn + hash checks  |
|  holds no keys                                    no network listener     |
|                                                                           |
|  nebula-discovery: one-shot Nmap, CAP_NET_RAW only, results to staging    |
+------|------------------------------------|------------------|------------+
       | outbound                           | SSH with permit  | scan
       v                                    v                  v
  Notifications                       Managed hosts         Network
  (ntfy, webhook, Telegram)           (untrusted input)     (reviewed import)
```

<a id="v23-02-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-02-01 -->
The server faces the browser and plans work; the executor holds every managed-host/provider credential, verifies each request independently and is the only process that talks SSH to hosts or HTTPS to PVE. The server and collector can trigger reads only inside executor-approved grants. Only the admin CLI may unlock or give hardened approval, enforced by the caller's UID on the socket.

<a id="v23-02-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-02-02 -->
**Provider read path.** In addition to the SSH path in the diagram, `nebula-server` writes typed poll/visible-target requests to a request spool; `nebula-pve-collector` (peercred role `pve-collector`) schedules typed metadata/read RPCs; the executor alone dials admin-approved PVE HTTPS origins, checks TLS and read authority, and returns sanitized fields. The collector alone writes result spool files; the server revalidates and imports them. The collector has no network access, listener, capabilities, credentials or database access. Neither spool direction accepts URLs, raw API paths or generic commands. PVE is a built-in typed provider, never a server-side module plugin.

<a id="v23-02-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-02-03 -->
**Registry egress boundary.** The server may additionally fetch anonymous public registry metadata within administrator-approved HTTPS registry/auth origins and the limits in [11-operations.md](11-operations.md). This permission does not include PVE API access, private registry credentials or image-layer pulls. Private registry metadata is executor-only under typed repository/tag read grants and vault custody. The unresolved approval lifecycle of public-origin configuration and private auth/pull profiles is recorded in [17-frozen-decisions.md](17-frozen-decisions.md); it must not be inferred from host-supplied image references.

<a id="v25-02-01"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-02-01 -->
**One-step enrollment boundary (ADR 0013 D1, D2, D7).** One-step enrollment adds the first **unauthenticated endpoint that returns executor-generated content**: `GET /enroll/<offer-id>` on `nebula-server`, served through the reverse proxy outside the authenticated UI chain ([03-processes-and-data.md](03-processes-and-data.md#v25-03-05)). It returns only the script of an open enrollment offer, at most once, and the script is public content except for the optional NetBird setup key. The authority stays where it was: the **executor** creates and holds the offer (ID hash, salt, state), renders the script on demand, decides whether a pairing code matches, builds the paired enrollment permit and pins; the **server** only validates the ID syntax, determines the client address, rate-limits, calls the executor (`FetchEnrollScript`) and streams the bytes, and for the authenticated steps forwards operator input. No component on the host calls back to NOS: the only channel host → NOS is the operator, who carries the pairing code from the host's terminal into the web UI ([08-ssh-transport.md](08-ssh-transport.md#v25-08-01)). The reverse proxy is part of this boundary: it must run `/enroll/` (and the UI's "Show script" and "Download in browser" routes) without buffering to disk, without cache and without access log, and it is the only address whose `X-Forwarded-For` the server may honour, and only when configured as a trusted proxy ([03-processes-and-data.md](03-processes-and-data.md#v25-03-06)).

<a id="v25-02-02"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-02-02 -->
**Executor NetBird egress (ADR 0013 D6; Q3, decided 2026-11-11).** In addition to SSH to hosts and HTTPS to PVE ([v23-02-01](#v23-02-01)), the executor may dial exactly one more destination: the **NetBird management API** at the management URL and with the TLS trust from executor-local configuration (public CA for NetBird Cloud; pinned CA or leaf for self-hosted management; never accept-any), never from the server or the browser. It uses only typed calls (create and revoke a setup key, get a setup key by key ID, list setup keys without a name filter, which reconcile filters locally ([06-credentials.md](06-credentials.md#v25-06-02) steps 3 and 5; previously: create, revoke and list setup keys by name), read with one request per pass because the endpoint is not paginated, within the key and byte limits of [03-processes-and-data.md](03-processes-and-data.md#v25-03-04); only a list that is complete as defined in [06-credentials.md](06-credentials.md#v25-06-02) step 5 is matched, any other result counts as truncated, matches nothing, revokes nothing and raises the unresolved alert instead of "no candidate" (previously: read page by page with an unnamed last-page indication; before that: no limit stated); list peers, get a peer, read the NOS peer; delete a peer after operator confirmation; read policies) with a token of a dedicated NetBird service user held in the executor vault ([06-credentials.md](06-credentials.md#v25-06-01)); there is no generic HTTP proxy, and NOS never creates or changes NetBird policies or groups. Without a configured token there is no NetBird egress and the NetBird option is hidden. The server, collector and discovery processes gain no NetBird access. Whether the reference lab uses self-hosted management or NetBird Cloud is established in the lab test before EN-12; both trust settings are supported.
