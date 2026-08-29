# Cadabra local control API

Cadabra listens on `<store-root>/cadabra.sock`. The socket is Unix-domain only
and is created with mode `0600`. A client sends one UTF-8 JSON object followed by
a newline and receives one JSON object followed by a newline. Connections may be
reused. Requests have an `op`; successful responses are
`{"ok":true,"result":...}` and failures are `{"ok":false,"error":"..."}`.

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
| `send` | `peer` and one of `snapshot_id`, `path`, or `link`; `title?`, `note?` | durable outbox id |
| `inbox` | — | partial floor cards and read state |
| `accept` | `id`, `to` | materializes files, if any, and marks inbox items read |
| `log` | `capsule?` | capsule snapshot history |
| `enroll-mint` | `capsules`, `kinds`, `ttl_ms`, `send`, `receive` | encoded enrollment token |
| `outbox` | — | entries including protocol state and retry metadata |
| `cancel` | `id` | cancelled outbox id |

`pair-confirm` and `pending-pairs` are the stable interactive API. A daemon run
with `--yes` confirms pairing requests automatically for automation.

