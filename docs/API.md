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

`abra config get|set|unset` edits `iroh_relay`, `skip_native`, and
`offer_budget` in `<store-root>/config/daemon.json`, plus
`relay_after_attempts` and `relay_poll_seconds` in `config/relays.json`. It
writes the files directly, so it works before the first daemon start. The daemon
reads `daemon.json` at startup only, so those three keys apply on the next start;
relay tuning is reread while it runs. The default relay
mode is `n0`. `n0` enables iroh's public relay plus
DNS/pkarr discovery, `none` is direct-address-only, and a custom URL keeps
discovery enabled while replacing the relay set.
Daemon health only means the local endpoint started. In `n0` and custom modes,
`pair-ticket` and `enroll-mint` briefly wait for the configured relay.
If it does not appear, they mint a direct-address credential. They also warn
that it will not cross NATs.

Operations and request fields:

| Operation | Fields | Result |
|---|---|---|
| `status` | none | identity, root and queue summary |
| `pair-ticket` | `name?` | encoded signed ticket |
| `pair-add` | `ticket` | paired peer id |
| `pending-pairs` | none | requests awaiting confirmation |
| `pair-confirm` | `id` | confirmation result |
| `peers` | none | trusted peer records |
| `capsule-create` | `path` | capsule id |
| `snapshot` | `path`, `label?`, `no_lease?` | capsule and snapshot ids |
| `native-attach` | `capsule`, `parent_snapshot`, `snapshot_type:"Full"`, `fingerprint`, `artifact_root`, `artifacts[{role,path}]` | signed child snapshot and exactly `vmstate,memory,disk` refs; paths must remain under `artifact_root` (adapter API) |
| `send` | `peer`; one payload: `snapshot_id`, `path`, `link`, or `kind` + `source`; optional send fields | ids; linked workspace fields; inspect fields; wait entries |
| `adapters-list` / `adapters-add` / `adapters-remove` | `dir?`, `name?` | list returns `{adapters:[...],errors:[...]}`; add/remove return the registration change |
| `inspect` | `kind`, `source`, `options?` | `{summary?,warnings:[...],blocked:[...]}` from the adapter |
| `inbox` | `kind?`, `from?`, `wait?`, `timeout_ms?` | partial floor cards, read state, and `provenance` |
| `accept` | `to`; `id` or `latest:true` + `kind`; optional `from`, `replace`, `workspace`, `timeout_ms`, `no_lease`, `discard_local`, `allow_divergence`, `no_import`, `destination`, `options`; legacy `into` aliases `replace` | materializes, imports, marks read, and returns `replace` plus `import` (`{result, deep_link?}`) when an adapter ran; `no_import:true` skips the importer |
| `handoffs` | `kind?`, `peer?` | rows shaped `{kind,last_acked_send,last_pending_send,last_unread_receive,last_read_receive,capsule}`; missing values are `null` |
| `log` | `capsule?` | capsule snapshot history |
| `capsules` | none | capsule ids, kinds, titles, and current main/fork heads |
| `enroll-mint` | `capsules`, `kinds`, `ttl_ms`, `send`, `receive`, `lease_acquire?`, `lease_takeover?` | encoded enrollment token; the lease flags let the guest run `lease take` |
| `enroll-join` | `token` | persisted guest role and effective scopes |
| `revoke` | `token_id` | saves a guest revocation, drops local trust, and later sends it to full peers |
| `policy-grant` | `peer`, `kind`, `capsule?`, `auto_accept`, `to?`, `forward?` | persisted receive grant |
| `policy-list` | none | all receive grants |
| `policy-clear` | none | clears saved auto-accept errors |
| `policy-revoke` | `id` | revoked grant id |
| `control` | `peer`, `capsule`, `control_op`, `text?` | full `{type:"control-ack",nonce,ok,error?,result?}` ack; `ok` may be false |
| `events` | none | retained event array |
| `lease-status` / `lease-take` | `capsule` | lease state / signed takeover |
| `outbox` | none | entries including protocol state and retry metadata |
| `cancel` | `id` | cancelled outbox id |
| `relay-list` | none | configured relay endpoints |
| `relay-add` | `url`, `secret?` | persisted relay configuration |
| `relay-remove` | `url` | removal result |

`adapters-list` rows contain `{manifest,directory,executable,source}`. `source`
is `root` for `<root>/adapters/*`, `registry`
for the persisted `adapters add` list, and `flag` or `env` for directories a
daemon was started with. `adapters remove` refuses a `flag`/`env` registration
because there is nothing persisted to remove.

Paths sent to `capsule-create`, `snapshot`, and `accept` must be absolute. The
CLI resolves them in the caller's working directory before making the request;
`capsule-create` creates a missing directory.

For a workspace snapshot, the daemon reads `.abra/observed.json` first. It puts
derived recipes in `manifest.recipes` and the remaining ledger in
`extensions["dev.abra.observed"]`. If `observed.json` is absent, it reads
`.abra/recipes.json` as a manual fallback. On materialization it writes received
recipes to `.abra/recipes.json` and the received ledger to
`.abra/received-observed.json`. These files are data only. A ledger with no complete recipes clears the received
recipe file instead of retaining earlier suggestions.

For a pinned capture, `snapshot` accepts `observation_barrier` and optional
`observation_host`. The CLI flags are `--observation-barrier <id>` and
`--observation-host '<JSON object>'`. The daemon strictly reads
`.abra/observed-<id>.json`, checks schema, mode, barrier and capture times, and
returns `observation_barrier`. It never falls back to live data for this request.
Host facts require a barrier and are limited to 16 KiB. See the
[observation contract](OBSERVATION.md) for fields, limits and consistency.

Adapter `source` and `destination` values parse as JSON only when they are JSON
objects; all other values stay strings. Adapter options are string maps. `to`
always names the materialization directory. The CLI form is
`abra accept <id> <path> [--replace] [--discard-local] [--allow-divergence] [--no-import]`,
where `--replace` sets `replace` and replaces the files in an existing
workspace only when `.abra/capsule_id` matches; it preserves `.abra`. Local
files that differ from the recorded `.abra/snapshot_id` are refused unless
`--discard-local` is set. An incoming snapshot that does not descend from that
recorded snapshot is refused unless `--allow-divergence` is set. `<id>` is
optional when `--latest --kind <k>` is given. When the inbox has no unread
match of that kind, `--latest` falls back to a capsule `main` head of that
kind authored by another peer.

## Waiting, linking, and leases

`send` with `wait:true` returns only once every entry it enqueued reaches
`acked`. The daemon watches durable outbox state on a 100 ms interval through the
same reload path every other op uses, so the node mutex is never held across the
wait. The result gains `entry` (the primary delivery) and `entries` (every
delivery, in enqueue order), each with `id` (the outbox id), `peer_id`,
`snapshot_id`, `state`, `attempts`, `created_at`, `updated_at`, `acked_at`,
`ack_sig`, and `last_error`. An entry that ends `failed`, `cancelled`, or
`expired`, or a `timeout_ms` that passes, is an error naming the state and
`last_error`. `timeout_ms` defaults to 120000. The CLI forms are `--wait` and
`--timeout <dur>`.

`send --path <dir>` where `<dir>` holds `.abra/capsule_id` snapshots the
workspace and sends that full capsule snapshot instead of a partial bundle. The
result carries `capsule_id` and `workspace_detected:true`; in human mode the CLI
writes `workspace detected: sent capsule snapshot <id>` to stderr. A plain folder
or a file keeps the partial bundle behaviour.

`send --kind <k> --source <s> --workspace <dir>` is one linked handoff. The
daemon runs `init` on `<dir>` when it has no `.abra/capsule_id`, snapshots it,
enqueues that full snapshot first, then exports the adapter partial with its
manifest `provenance` set to that capsule and snapshot and enqueues it second.
The result adds `workspace_outbox_id`, `workspace_snapshot_id`, and
`capsule_id`; `--wait` waits for both acks. The same manifest field can instead
come from `--provenance <snapshot-id>`, naming a snapshot already in the local
store, or from a `provenance:{capsule_id,snapshot_id}` object in an adapter's
`export` result. `--workspace` and `--provenance` are mutually exclusive, and
provenance applies only to a partial the daemon authors.

`--provenance <snapshot-id>` and a `provenance` object returned by an
adapter's `export` follow the same rule. The snapshot must exist on the sending
device, its full snapshot is enqueued before the partial, and the `send` result
carries `provenance_outbox_id` and `provenance_snapshot_id`.

`accept <id> <path> --workspace <dir>` completes the other half. The manifest
must carry `provenance` or it is an error. The daemon waits (`--timeout`,
default 120s) for the referenced snapshot to reach the local capsule store,
because the two deliveries are independent. It materializes the snapshot into
`<dir>`, either as a fresh directory or by using `--replace` on an existing
directory whose `.abra/capsule_id` matches. The same dirty and ancestry guards
as `accept --replace` apply (`--discard-local`, `--allow-divergence`). It writes `.abra` metadata, then
takes the lease. It runs the partial's adapter import last. When `--destination` is a JSON
object, the daemon inserts `workspace:<dir>` into it so the adapter can find the
restored tree. Any failure after the workspace was replaced restores the
previous contents, and the inbox entry stays unread. The accept result includes
the adapter's `{result, deep_link?}` under `import` when one ran.

`snapshot`, `accept --replace`, and linked accept take the capsule lease on a
full peer unless `--no-lease` is set. Linked accept takes it after materialization
and metadata writes. Auto-accepted full heads do not take it. The mirror leaves
the lease with the driving peer. A guest takes it only when its token grants
`lease_takeover` or `lease_acquire`. Otherwise it keeps the forking behaviour.
The takeover is the same
`Takeover` record and the same `lease-change` event that `lease take` writes.
`--no-lease` on `snapshot` and `accept` opts out. `lease take` remains for
explicit use.

`inbox` filters on `kind` and `from`. With `wait:true` it blocks, polling relays
as it goes, until at least one unread matching entry exists, and errors on
`timeout_ms`. `accept` with `latest:true` and a `kind` selects one unread inbox
partial of that kind. If none exists, it selects a matching capsule `main` head
authored by another peer. Zero or several matches are errors. The latter lists
the ids.

`handoffs` returns a plain JSON array, one row per kind rather than per
kind+peer; every sub-record names its own peer. `last_acked_send` and
`last_pending_send` are the most recent outbox entries of that kind by
`updated_at`. They use the shape returned by `send --wait`.
`last_pending_send` holds any entry that is not `acked`, including a failed
entry. Its `state`, `attempts`, and `last_error` explain why. `last_unread_receive` and
`last_read_receive` are the most recent inbox entries by `received_at`. A full
capsule snapshot lands in neither queue. `capsule` reports the current `main`
head of the latest received capsule of that kind. Its fields are
`{capsule_id, snapshot_id, origin, received_at, lease_holder, driving, path}`.
`driving` means the local device holds the lease. Lease knowledge is per-device
and travels with snapshots, so two devices can each believe they are driving
until the next delivery. `kind` and `peer` filter; `peer` matches the outbox
peer, the inbox sender, and a capsule's head origin or lease holder.

## Background daemon

`abra daemon --background` re-executes the same binary without `--background`,
detached in its own session, with stdout and stderr appended to
`<root>/daemon.log` (0600). It writes `<root>/daemon.pid` (0600) holding the
pid, the `ps lstart` string, the binary path, and the root. It polls `status`
until the child answers or exits, then prints the peer id. `abra stop` verifies
the live process against the saved start time, binary, command, and root.
It then sends `SIGTERM`, waits up to ten seconds, and removes the file.
A daemon removes a stale pid file it finds at startup, and
a clean foreground shutdown removes its own. `abra daemon` without the flag is
unchanged and writes no pid file. The launcher holds `<root>/daemon.launch.lock` from the first
status probe until the pid file is written, so two concurrent `--background`
starts cannot overwrite each other's pid file.

`abra daemon --adapters <dir>` (repeatable) and the colon-separated
`ABRA_ADAPTERS` add adapter directories for that daemon process only. Each entry
is either an adapter directory (it holds `abra-adapter.json`) or a parent whose
immediate children are adapter directories. They join `<root>/adapters/*` and
the persisted `adapters add` list; nothing is written to disk.

## Events

`events` returns the retained array. `watch` streams the same NDJSON records.
`watch` ignores `--json`; it always streams NDJSON.

Every event record has `event` and `at`.

| Name | Fields after the name |
|---|---|
| `capsule-sync` | `snapshot_id`, `from`; direct delivery also has `capsule_id` and `scope:"full"`, relay delivery has `via:"relay"` |
| `inbox-arrival` | `snapshot_id`, `from`; direct delivery also has `scope:"partial"`, relay delivery has `via:"relay"` |
| `lease-change` | `capsule_id`, `lease` |
| `control` | `from`, `message` |
| `control-handled` | `capsule_id`, `op`, `ok`, `adapter`, `peer` |
| `adapter-inspect` | `kind`, warning count in `warnings`, blocked count in `blocked` |
| `send-acked` | `outbox_id`, `snapshot_id`, `peer` |
| `linked-accept` | `snapshot_id`, `capsule_id`, `workspace`, `peer` |
| `auto-accepted` | `snapshot_id`, `kind`, `to`, `peer`; full snapshots also have `capsule_id`; an adapter import adds `import` |
| `auto-forwarded` | `capsule_id`, `snapshot_id`, `peer`, `outbox_id` |
| `auto-forward-skipped` | `snapshot_id`, `peer`, `reason`; the target was the delivering peer or origin, or that snapshot was already forwarded there |
| `auto-accepted-full` | `capsule_id`, `snapshot_id`, `to`, `peer` |

On receipt of a verified control message, an adapter whose manifest claims the
capsule kind in `controls` runs its `control` verb. The adapter value becomes
the acknowledgement `result`. Pause and stop fall back to `{recorded:true}`
when no adapter claims the kind. Instruct fails without a matching adapter.

`pair-confirm` and `pending-pairs` are the stable interactive API. The issuer
keeps the bootstrap connection open until confirmation or ticket timeout (600
seconds). Pairing and enrollment reads wait 630 seconds. Confirmation completes
the connection without retrying the ticket. A daemon run with `--yes` confirms
pairing requests automatically, so `pair add`
returns in one step. Otherwise `pair add` blocks for the same window and, in
human mode, prints the issuer short id and the `abra pair confirm <peer-id>`
line to run there after 1.5 seconds.

The receiver limits a control handler to 660 seconds. The sender waits 690
seconds for its acknowledgement.

Limits:

- 10,000 inbox entries.
- 128 pending pairing requests.
- An 8 MiB event log. Abra truncates it when full.
- 64 local control clients.
- 32 inbound sessions.
- 8 watchers.

`--json` writes exactly one JSON value: the operation's `result` object. In
human mode, `pair ticket` writes only the copyable `abra-pair/1/...` token.
`enroll` writes the bare token; `join` also accepts the `abra://join/<token>` form. Capsule
and kind scopes are mandatory; no wildcard is silently introduced. Recipes are
transported and materialized as data but never executed by Abra.

`abra join <token>` redeems a token through a running daemon. A new guest can
instead start with `abra daemon --token <token>`. The hidden
`daemon --transport tcp` mode is for loopback tests. It is authenticated but not
encrypted. Iroh is the inter-device transport and saves full peer addresses,
including relay URLs, across restarts.

Cadabra retains each enrollment bind certificate. When a full peer forwards a
guest-authored snapshot, its direct offer includes that certificate and issuer
id only if the receiver advertised `bind-cert`. Relay envelopes have no feature
handshake and omit it. A receiver checks the issuer, signature, expiry, and
certificate subject before installing the guest. The issuer must be a trusted
full peer. The subject must match the manifest origin. The installed row has no
dialing addresses. Guest-issued,
expired, mismatched, and invalid certificates leave the origin untrusted. Offer
rejections preserve a bounded receiver reason in the sender's outbox
`last_error`.

`accept` runs a matching adapter before it marks the inbox entry read. The
result includes the adapter's `{result, deep_link?}` under `import` when one
ran. If the adapter starts and then fails, Abra keeps the entry unread and
returns an error with `files_materialized_at=<path>`, where `<path>` is the
accept path. The files remain there so the user can inspect or recover the
partial import.

A partial can also be materialized without its importer. When no registered
adapter supports `import` for the kind, `accept` writes the files and marks the
entry read. `accept --no-import` (`no_import:true`) does the same even when an
adapter is registered, so another tool can consume the files; the sandbox
coordinator uses it to accept a browser bundle it will push into a remote
browser itself. The files keep ordinary modes and the result has no `import`.

`abra policy clear` empties `policy/grant-errors.json`, removing saved
auto-accept errors.

`policy-grant` with `auto_accept:true` requires `to`. It materializes a matching
partial and runs its importer before marking it read. It also materializes full
snapshots below `to`. A matching `.abra/capsule_id` is replaced only when the
tree still matches the recorded snapshot and the incoming snapshot descends from
it; otherwise the grant records an error and leaves the files alone. With
`forward`, the daemon then enqueues the same signed snapshot to that peer and
records `auto-forwarded`.

Direct delivery streams CAS objects above 8 MiB in 1 MiB chunks. Smaller objects
keep the single-stream path. Ordinary blobs and trees are limited to 256 MiB
each; blobs referenced by `manifest.native` are limited to 8 GiB each. Receivers
default to a 16 GiB total offer budget and also require enough free disk space.
Use `config set offer_budget <bytes>` to change the total limit. Use
`config set skip_native true` when the local runtime cannot use the offered
fingerprint; the receiver then accepts the portable snapshot without downloading
native blobs that are not also part of the portable tree.

`log` results are guaranteed to be topologically ordered: every locally known
parent appears before its children, with deterministic snapshot-id sibling order.

Relay configuration is stored at `<store-root>/config/relays.json`. The CLI forms
are `abra relay add <url> [--secret <deploy-secret>]`, `abra relay list`, and
`abra relay remove <url>`; `abra config set relay_after_attempts N` and
`abra config set relay_poll_seconds N` (minimum 5) tune deposit and polling.
Deposit defaults to three failed direct attempts and polling defaults to every 60
seconds; `inbox` and `watch` also trigger an immediate poll.

The iroh relay handles NAT traversal. It can see device IP addresses and iroh
node ids, but QUIC/TLS keeps Abra payloads encrypted between devices. The n0 and
custom modes publish endpoint ids through DNS/pkarr discovery. `none` disables
that discovery and relay traffic.

`abra-relay` is a separate sealed, offline store-and-forward service. Start it
with `ABRA_RELAY_SECRET=<secret> abra-relay --listen <address>`, then register
its HTTP URL on each device with `abra relay add <url> --secret <secret>`. Put
it behind TLS on the Internet. It sees rotating tags, expiry metadata, and
recipient-sealed ciphertext. A deposit leaves the outbox in `awaiting_ack` until
the receiver returns a verified acknowledgement.

## Capability links

`abra link mint <snapshot> --ttl <duration> --out <dir>` writes sealed link
data. `--full` includes full snapshot data. `--url` records the public
ciphertext URL. `--viewer <origin>` produces the static viewer form.
`--upload-command` receives `{file}`, `{hash}`, and `{url}` placeholders. A
remote upload also requires `--revoke-command` with the same placeholders.
Neither hook receives the bearer key. `link list` stores fragment-free URLs,
and `link revoke <id>` tombstones local ciphertext and runs the remote revoke
hook. `abra link open <url> --to <dir>` opens a link. For local hosting, use
`abra link serve <dir> --listen 127.0.0.1:8080`; production object hosting must
use HTTPS and CORS. Sealed links are limited to 64 MiB total and 32 MiB per
object.

Native refs are an optional cache. Receivers compare every fingerprint field
against a live probe and fall back to the portable file tree and recipe data
after any mismatch or native load/readiness failure. `native-attach` is local
device authority and its socket must remain `0600` inside a `0700` directory.
