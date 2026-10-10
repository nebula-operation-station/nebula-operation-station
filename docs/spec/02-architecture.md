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

The server faces the browser and plans work but cannot execute anything; the executor holds every credential, verifies each request on its own and is the only process that talks SSH to hosts. Only the admin CLI may unlock or give hardened approval, enforced by the caller's UID on the socket.
