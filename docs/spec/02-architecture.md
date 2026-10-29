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
