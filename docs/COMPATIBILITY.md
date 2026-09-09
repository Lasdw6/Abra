# Compatibility and recovery

Abra is a developer alpha. Pin the release used by both devices and application
adapters. The source of truth for signed and wire formats is [SPEC.md](../SPEC.md).
The [local API](API.md) is a separate interface from those signed bytes.

## Version contract

| Interface | Current identifier | Reader behavior |
|---|---|---|
| Signed snapshot envelope | `abra/0.1` | Reject unsupported versions and unknown top-level fields; preserve accepted canonical bytes |
| iroh application protocol | `abra/1` ALPN | Connect only to the matching application protocol |
| Pairing ticket | `abra-pair/1` | Verify format, signature, expiry and single-use state |
| Adapter process protocol | `abra-adapter/1` | Require the advertised verbs and kinds |
| Observation ledger | `dev.abra.observed/3` | Consumers inspect the schema before deriving actions; other schemas remain opaque data |

Changes to the meaning of signed fields or their canonical representation require
a new format version. New application data belongs in namespaced kinds and
extensions. Additive local API responses may gain fields, so clients should read
the fields they need. Pin crate versions while the Rust API is pre-1.0.

Existing `abra/0.1` snapshots remain byte-authoritative. Loading or forwarding a
snapshot never rewrites it to the latest serializer. Device removal adds local
trust history without changing the snapshot format. Do not downgrade a store
after removing devices: older binaries do not implement the revocation history.
Back up the complete stopped store before changing versions.

## What completion means

- `snapshot` creates a signed file-tree snapshot and its local history. The
  observer's barrier pins a particular ledger; it does not freeze application
  writes, flush databases or checkpoint process memory.
- `send --wait` waits for the receiver's verified acknowledgement. This confirms
  delivery and storage under the transfer policy. It does not mean an adapter
  imported the snapshot or a process started. Receivers may intentionally skip
  native-only objects and retain the portable representation.
- Retries retain the snapshot identity and content hashes. Missing objects can
  be sent again; the receiver verifies the bytes and reuses valid local objects.
- `accept` materializes data and, unless `--no-import` is set, invokes the
  registered importer. A failed import leaves the inbox unread for retry and
  reports the materialized path. Each adapter defines its own import side effects.
- `restore-plan` verifies current local objects and reports native eligibility
  and portable-file availability. It does not change the store or establish that
  a workload can run with the receiver's dependencies.

Individual CAS and metadata writes use atomic replacement and filesystem syncs.
This is not a claim that every multi-file operation is one filesystem transaction.
After interruption, restart the daemon and inspect the durable outbox and inbox
before issuing another operation. Filesystems and underlying storage must honor
their durability operations.

## Recover a transfer or workspace

```sh
abra --json outbox
abra --json inbox
abra --json restore-plan <snapshot-id>
```

If portable objects are missing or corrupt, retain the error and snapshot id,
then have an authorized peer send the snapshot again. Do not edit signed manifests
or substitute different bytes under a content hash. If a complete copy no longer
exists, restore a backup. Native state can be omitted when the portable
representation and required application checkpoints are sufficient.

Replacing a workspace requires its capsule to match. Abra refuses local edits
and divergent ancestry by default. `--discard-local` and `--allow-divergence` are
explicit choices to override those checks; keep a separate copy of local work
before using them. Core materialization does not perform a source-code merge.

## Revoke access

```sh
abra pair remove <peer-id>
```

Removal persists the loss of trust, revokes guests delegated by that peer, and
prevents stale daemon state from restoring the peer. Outstanding tickets issued
by this device before removal are invalidated. Pairing again requires a fresh
ticket. Other paired devices keep their own trust decisions; remove the peer on
each device that should stop accepting it.

Revocation rejects subsequent authorized operations. It does not interrupt an
operation already authorized and in flight, erase data previously delivered,
stop remote applications or invalidate their website/database credentials.
Guests can also be revoked individually with `abra revoke <token-id>`.

## Back up a store

Stop the daemon and every application or adapter writing that store. Copy the
entire root, including `keys`, `objects`, `capsules`, `inbox`, `outbox`, `net` and
configuration. Preserve owner-only access and protect the backup like the device
key. Restore into a stopped instance, then inspect status, outbox and restore
plans before resuming work.

A store backup includes the device identity. Do not run two independent copies
of the same identity at once. To move snapshots to another device, create a new
identity there and transfer through Abra.

## Optional offline relay

The offline relay is separate from iroh's NAT-traversal relays. Keep its data
directory across restarts. It acknowledges enqueue only after writing the sealed
envelope durably and rejects new items when its storage cap is reached. Envelopes
still expire; it is a bounded delivery queue, not a permanent backup.

Use HTTPS for remote relay endpoints. HTTP is accepted only on loopback for local
development or a locally terminated secure tunnel. The client verifies TLS and
refuses redirects. Run the HTTP relay behind a TLS reverse proxy and keep its
queue on persistent storage. See [relay configuration](API.md#offline-relay)
for commands and settings.
