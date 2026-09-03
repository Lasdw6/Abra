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

The daemon accepts `--iroh-relay n0|none|<https-url>`, `--skip-native`, and
`--offer-budget <bytes>`. Cadabra stores explicitly supplied values as
`iroh_relay`, `skip_native`, and `offer_budget` in
`<store-root>/config/daemon.json`; later starts reuse them. The default relay
mode is `n0`. `n0` enables iroh's public relay plus
DNS/pkarr discovery, `none` is direct-address-only, and a custom URL keeps
discovery enabled while replacing the relay set.
Daemon health only means the local endpoint started. In `n0` and custom modes,
`pair-ticket` and `enroll-mint` wait briefly for the configured relay to appear
in the local endpoint address; if it does not, they still mint a direct-address
credential and print a warning that it will not cross NATs.

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
| `native-attach` | `capsule`, `parent_snapshot`, `snapshot_type:"Full"`, `fingerprint`, `artifact_root`, `artifacts[{role,path}]` | signed child snapshot and exactly `vmstate,memory,disk` refs; paths must remain under `artifact_root` (adapter API) |

| `send` | `peer` and one of `snapshot_id`, `path`, `link`, or adapter `kind` + `source`; `options?`; `title?`, `note?` | durable outbox id |
| `adapters-list` / `adapters-add` / `adapters-remove` | `dir?`, `name?` | list returns `{adapters:[...],errors:[...]}`; add/remove return the registration change |
| `inbox` | — | partial floor cards and read state |
| `accept` | `id`, `to`, `into?`, `destination?`, `options?` | materializes files, invokes an importer if registered, and marks inbox items read |
| `log` | `capsule?` | capsule snapshot history |
| `capsules` | — | capsule ids, kinds, titles, and current main/fork heads |
| `mesh-profile` | `profile?` (`personal` or `fleet`) | read or update authorization profile |
| `enroll-mint` | `capsules`, `kinds`, `ttl_ms`, `send`, `receive` | encoded enrollment token |
| `enroll-join` | `token` | persisted guest role and effective scopes |
| `revoke` | `token_id` | signs and persists a guest revocation, drops local trust, and propagates it to full peers on later offers and handshakes; peers with no later contact keep trust until certificate expiry |
| `policy-grant` | `peer`, `kind`, `capsule?`, `auto_accept`, `auto_run_recipes`, `to?` | persisted receive grant; auto-run returns unimplemented |
| `policy-list` / `policy-revoke` | `id?` | list or revoke generic grants |
| `control` | `peer`, `capsule`, `control_op`, `text?` | signed live control acknowledgement |
| `events` / `watch` | — | retained events / long-lived NDJSON event stream |
| `lease-status` / `lease-take` | `capsule` | lease state / signed takeover |
| `ps` / `stop-recipes` | `capsule?` | legacy records / explicit disabled error |
| `outbox` | — | entries including protocol state and retry metadata |
| `cancel` | `id` | cancelled outbox id |
| `relay-list` | — | configured relay endpoints |
| `relay-add` | `url`, `secret?`, `relay_after_attempts?`, `poll_seconds?` (minimum 5) | persisted relay configuration |
| `relay-remove` | `url` | removal result |

Paths sent to `capsule-create`, `snapshot`, and `accept` must be absolute. The
CLI resolves them in the caller's working directory before making the request;
`capsule-create` creates a missing directory.

Adapter `source` and `destination` values parse as JSON only when they are JSON
objects; all other values stay strings. Adapter options are string maps. `to`
always names the materialization directory. `accept --into` replaces the files
in an existing workspace only when `.abra/capsule_id` matches; it preserves
`.abra` and overwrites local file changes.

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
receiving application.

Cadabra retains each enrollment bind certificate. When a full peer forwards a
guest-authored snapshot, its direct offer includes that certificate and issuer
id only if the receiver advertised `bind-cert`. Relay envelopes have no feature
handshake and omit it. A receiver installs the guest with the certified
name, key, scopes, token id, and expiry only when the issuer is already a trusted
full peer, the signature and expiry verify, and the certificate subject matches
the manifest origin. The installed row has no dialing addresses. Guest-issued,
expired, mismatched, and invalid certificates leave the origin untrusted. Offer
rejections preserve a bounded receiver reason in the sender's outbox
`last_error`.

`accept` runs a matching adapter before it marks the inbox entry read. If the
adapter starts and then fails, Abra keeps the entry unread and returns an error
with `files_materialized_at=<path>`, where `<path>` is the `--to` directory. The
files remain there so the user can inspect or recover the partial import.

`abra policy clear` empties `policy/grant-errors.json`, removing saved
auto-accept errors.

Direct delivery streams CAS objects above 8 MiB in 1 MiB chunks. Smaller objects
keep the single-stream path. Ordinary blobs and trees are limited to 256 MiB
each; blobs referenced by `manifest.native` are limited to 8 GiB each. Receivers
default to a 16 GiB total offer budget and also require enough free disk space.
Use `daemon --offer-budget <bytes>` to change the total limit. Use
`daemon --skip-native` when the local runtime cannot use the offered fingerprint;
the receiver then accepts the portable snapshot without downloading native blobs
that are not also part of the portable tree.

`log` results are guaranteed to be topologically ordered: every locally known
parent appears before its children, with deterministic snapshot-id sibling order.

Relay configuration is stored at `<store-root>/config/relays.json`. The CLI forms
are `abra relay add <url> [--secret <deploy-secret>] [--relay-after-attempts N]
[--poll-seconds N]`, `abra relay list`, and `abra relay remove <url>`. Deposit
defaults to three failed direct attempts and polling defaults to every 60 seconds;
`inbox` and `watch` also trigger an immediate poll.

Native refs are an optional cache. Receivers compare every fingerprint field
against a live probe and fall back to the portable file tree and recipe data
after any mismatch or native load/readiness failure. `native-attach` is local
device authority and its socket must remain `0600` inside a `0700` directory.
