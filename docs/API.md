# Cadabra local control API

Cadabra listens on `<store-root>/cadabra.sock`. The socket is Unix-domain only
and is created with mode `0600`. A client sends one UTF-8 JSON object followed by
a newline and receives one JSON object followed by a newline. Connections may be
reused. Requests have an `op`; successful responses are
`{"ok":true,"result":...}` and failures are `{"ok":false,"error":"..."}`.

The store root and every store directory are owner-only (`0700`). Cadabra
refuses an existing root that is group- or world-accessible. The listener checks
kernel peer credentials and accepts only the daemon uid. A control line is at
most 1 MiB and an idle connection is closed after 30 seconds. The socket carries
full device authority: any process able to connect can pair peers, mint scoped
tokens, enqueue private data, and materialize received data. Treat access to it
exactly like access to the device key.

Operations and request fields:

| Operation | Fields | Result |
|---|---|---|
| `status` | — | identity, root and queue summary |
| `pair-ticket` | `name?` | encoded signed ticket |
| `pair-add` | `ticket` | paired peer id |
| `pending-pairs` | — | requests awaiting confirmation |
| `pair-confirm` | `id` | confirmation result |
| `peers` | — | trusted peer records |
| `capsule-create` | `path` | capsule id |
| `snapshot` | `path`, `label?` | capsule and snapshot ids |
| `native-attach` | `capsule`, `fingerprint`, `artifacts[{role,path}]` | signed child snapshot and native refs (adapter API) |
| `send` | `peer` and one of `snapshot_id`, `path`, or `link`; `title?`, `note?` | durable outbox id |
| `inbox` | — | partial floor cards and read state |
| `accept` | `id`, `to` | materializes files, if any, and marks inbox items read |
| `log` | `capsule?` | capsule snapshot history |
| `enroll-mint` | `capsules`, `kinds`, `ttl_ms`, `send`, `receive` | encoded enrollment token |
| `enroll-join` | `token` | persisted guest role and effective scopes |
| `revoke` | `token_id` | revocation confirmation |
| `policy-grant` | `peer`, `kind`, `auto_accept`, `auto_run_recipes`, `to?` | persisted receive grant; auto-run returns unimplemented |
| `policy-list` / `policy-revoke` | `id?` | list or revoke generic grants |
| `control` | `peer`, `capsule`, `control_op`, `text?` | signed live control acknowledgement |
| `events` / `watch` | — | retained events / long-lived NDJSON event stream |
| `lease-status` / `lease-take` | `capsule` | lease state / signed takeover |
| `ps` / `stop-recipes` | `capsule?` | legacy records / explicit disabled error |
| `outbox` | — | entries including protocol state and retry metadata |
| `cancel` | `id` | cancelled outbox id |

Paths sent to `capsule-create`, `snapshot`, and `accept` must be absolute. The
CLI resolves them in the caller's working directory before making the request;
`capsule-create` creates a missing directory.

`pair-confirm` and `pending-pairs` are the stable interactive API. The issuer
keeps the bootstrap connection open until confirmation or ticket timeout;
confirmation completes that connection without retrying the ticket. A daemon
run with `--yes` confirms pairing requests automatically for automation.

`--json` writes exactly one JSON value: the operation's `result` object. In
human mode, `pair ticket` writes only the copyable `abra-pair/1/...` token.
`enroll` writes the bare token first and `abra://join/<token>` second. Capsule
and kind scopes are mandatory; no wildcard is silently introduced. Recipes are
transported and materialized as data but never executed by Abra. Control
messages are surfaced through `events`/`watch`; acting on them belongs to the
receiving application. Guest enrollment and revocation are issuer-device-local
in v1.
