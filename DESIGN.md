# Abra — design

Status: settled. This document records the decisions the implementation encodes,
including the parts later phases build. Phase 1 implements the local primitives
(identity, CAS, snapshot, store, enroll, link); everything marked _later_ is
described here so it is designed for, not designed around.

### v1 transport implementation

The shipped binaries default to iroh 1.1 over QUIC/TLS. Abra's Ed25519 identity
bytes are supplied directly as the iroh `SecretKey`, so the Abra peer id and
iroh endpoint id cannot diverge. The workspace MSRV is Rust 1.91. Pairing
tickets and enrollment-token intro records carry the complete serialized iroh
`EndpointAddr`: endpoint id and direct UDP addresses.

The shipped `presets::Minimal` endpoint has no discovery, relay, port mapping,
or Abra relay configuration. It therefore needs directly usable addresses
(normally the same LAN or manual routing). Relay and configurable discovery
support are future work. The historical Stage-2 authenticated but unencrypted
TCP transport remains an explicit `--transport tcp` loopback-only test mode;
it is not an inter-device fallback.

## 1. What Abra is

Abra is infrastructure for teleportation. It moves files, workspaces, and app
state between **one user's** devices and their cloud agents.

Abra is transport plus policy-controlled materialization. It carries bytes,
structure, and descriptions of processes without interpreting payload meaning.
Recipes are carried and materialized as data. Abra never executes them; the
receiving app or user decides whether and how to act on them.

### Carry the data, don't prescribe the experience

A snapshot carries the maximal amount of structured, parsable data about what it
is. The receiver — or a developer building on the SDK — derives the rendering at
receive time: a card, a deep link, a resume button, an inbox row. The sender
authors nothing beyond what the observer already captured.

The practical consequence: **a snapshot must never be an opaque blob.** The
manifest is JSON, parsable by construction, and any device that has never heard
of a payload's `kind` can still render a useful card from the floor fields.

## 2. Nouns and verbs

- **Snapshot** — the noun. A typed, self-describing, content-addressed bundle:
  a JSON manifest plus the blobs and tree objects it references.
- **Teleport** — the verb. Moving a snapshot end-to-end encrypted within one
  user's device mesh.
- **Capsule** — a continuing thing (a workspace, a sandbox, an app's state) with
  a stable id and a history DAG of snapshots.
- **Lease** — who's driving a capsule. A lease names the peer currently allowed
  to author new versions. It is coordination, not enforcement; a device that
  ignores a lease produces a fork, and forks are representable (multiple
  children of one parent).

## 3. One envelope, a `scope` field

There is exactly one envelope format. A single `scope` field splits behaviour:

**`scope: "full"`** — a version of a continuing thing. The whole sandbox or
workspace: file tree, process recipes, optional native memory blobs. Always
carries `capsule_id` and `parents` (the parent snapshot hashes, forming the
history DAG) and participates in lease semantics. Receiving a `full` snapshot
means: sync it into the capsule store. Its offer also carries the sender's
signed `main` pointer and the signed winning lease ancestry that authorizes that
pointer. Receivers commit the immutable snapshot first, validate the lease chain
with the ordinary lease rules, and apply the pointer with the ordinary label-op
rules. The bounded lease suffix and pointer are bound to the manifest's single
capsule id and staged transactionally against a clone: both persist, or neither
does. The acknowledgment distinguishes a stored-and-adopted head from a stored
fork. Missing-ancestor pointer ops are retained in a bounded retry set so a
later offer can resolve them. An invalid or sideways pointer leaves the object
available under a locally signed fork label; receipt never infers a head or
silently merges histories.

**`scope: "partial"`** — a delivery. A browser session, a file, a folder, a
handoff link. No lineage, no capsule, no lease. Receiving a `partial` means: it
lands in an inbox.

A partial may carry a **provenance** back-reference: `{capsule_id,
snapshot_hash, label}`. It is optional and it is a reference, not a claim of
membership — "this handoff came out of that workspace at that version". It
never makes the partial part of the DAG.

Resisting a second envelope format is deliberate. Every device, adapter, and SDK
consumer parses one thing.

## 4. Floor fields

Every manifest must carry enough that **any** device can render a card without
understanding the payload:

- `kind` — payload type string, e.g. `dev.abra.workspace`, `dev.abra.handoff.v1`
- `title` — human string
- `origin` — sending peer id
- `created_at` — timestamp

And optionally, in the same flat namespace: `summary`, `link` (a URL),
`thumbnail` (blob hash), `files` (tree root hash), `recipes`, native blob refs.

An unknown `kind` degrades gracefully: title + summary + origin + timestamp is
still a card, and `link` is still clickable. Namespacing `kind` (`dev.abra.*`,
`com.vendor.*`) lets third parties define payload types without a registry.

## 5. Recipes

A recipe is **how to recreate a process**, derived by an observer, not declared
by a user:

```
{ argv, cwd (relative to workspace root), env (map), ports (list), started_at }
```

Two rules:

1. **Derived, not declared.** _Later:_ the sandbox runs an observer that watches
   what actually ran and writes recipes from observation. Nobody maintains a
   manifest by hand; nobody's `dev.sh` drifts.
2. **Data in core.** Core stores and transports recipes. Only the daemon's
   explicit receive-policy layer may execute them. `cwd` is
   relative to the workspace root precisely so the receiver stays in control of
   where that root lands.

## 6. Native blobs

Native blobs are opaque acceleration artifacts — the clearest example being
Firecracker's memory file plus VM state file, carried **unchanged**. Abra does
not parse, transform, or version them; it moves bytes.

Each ref is keyed by a **host fingerprint** string:

```
linux-kvm-x86_64/fc-snap-v11/cpu-template-none
```

Restoring from a native blob is only valid on a host whose fingerprint matches.
So native blobs are an **evictable cache, never the source of truth**. The file
tree plus recipes is always the portable representation; the native blob is the
fast path when the receiver happens to be a compatible host. A receiver that
can't use them deletes them and loses nothing but time.

## 7. Identity and authorization

A peer is an Ed25519 keypair. The peer id is the full 32-byte public key (64
hex chars) — the same bytes as the iroh NodeId, so transport identity and Abra
identity never diverge. A short id (first 8 hex of `blake3(pubkey)`) exists for
display only and is never verified against or used for authorization.

**Single-user mesh is an authorization policy, not a protocol constraint.** The
protocol is peer-to-peer between keypairs. "Only my devices" is a rule about
which keys are admitted. Loosening it later (a shared capsule, a second user)
is a policy change, not a redesign.

### Scoped enrollment

A device is admitted by an existing device, which signs an enrollment cert:

```
{ subject pubkey, scopes, expires_at, issuer sig }
```

Scopes are strings like `send:partial` or `capsule:<id>`. Expiry is mandatory.
This makes "let this cloud agent send me partials, but never touch my capsules"
expressible from day one, and it makes a compromised agent key a bounded
problem. _Phase 1 ships the struct plus sign/verify; enforcement arrives with
transport._

## 8. Secrets

v1 syncs **byte for byte**. No exclusion logic, no ignore files, no `.env`
filtering. A workspace that doesn't run without its secrets isn't a workspace
that teleported. Since the default iroh transport is E2E encrypted, the security argument for
stripping is weak and the correctness argument for not stripping is strong.

Deliberately not implemented: ignore files. Adding them later is additive;
having shipped a half-working ignore semantics would not be.

## 9. Content addressing

- **Blobs** are blake3-addressed and stored sharded on disk, git-style:
  `blobs/ab/cdef...`.
- **Trees** are git-like directory objects: entries of `(name, mode, hash)`
  where mode is file / exec / symlink / dir. A tree's own hash identifies a
  complete directory state.
- **Dedup is by content**, so an unchanged file across a hundred snapshots is
  stored once, and an incremental teleport only needs the hashes the receiver
  is missing.
- **The snapshot DAG**: a manifest references its parent snapshot hash(es), a
  label string (e.g. agent-turn labels like `turn 14: fix the flaky test`), and
  a timestamp. Merges and forks are expressible because `parents` is a list.

The snapshot hash is `blake3` of the canonical manifest bytes, which makes a
snapshot id self-verifying: fetch it, hash it, compare.

## 10. Capability links

A link is a bearer capability:

```
abra://s/<blob-hash>#<base64url key>
https://<host>/s/<blob-hash>#<base64url key>
```

The key lives in the **fragment**, which browsers never send to the server. The
payload behind the hash is the encrypted bundle: manifest plus referenced
blobs, sealed with a fresh symmetric key (XChaCha20-Poly1305). A host serving
these learns a hash and a ciphertext and nothing else — the same blind-relay
property the transport layer has.

_Phase 1 ships the model plus seal/open and mint/parse. No HTTP._

## 11. Later phases

Recorded here because phase 1's shapes are chosen to fit them.

### Delivery loop

**outbox → health-check → transfer → ack.** Every teleport is enqueued in a
durable outbox on the sender. The sender health-checks a route to the target
before pushing bytes, transfers, and waits for an ack that names the snapshot
hash. Un-acked entries stay in the outbox and are retried. Devices are asleep,
on planes, and behind NATs; the outbox is what makes "teleport" mean "it will
arrive" rather than "it worked when both were awake".

### Direct p2p in v1

Direct encrypted connections between the user's devices are the only shipped
iroh path. Configurable discovery and blind relays are future work.

### Adapters are separate executables

An adapter (browser session capture, editor state, a specific app's data) is a
**separate executable** speaking a **stdio JSON contract**. It reads a request
on stdin, writes a snapshot fragment on stdout. Consequences: adapters can be
written in any language, ship on their own schedule, crash without taking the
daemon down, and run under their own permissions. The core never links an
adapter's code.

### Observer-based recipe capture

Inside a sandbox, an observer process watches what actually runs and emits
recipes. See §5.

### Flat receiver model

There is **no privileged first-party app**. Any browser can receive via a
capability link; any app can receive via the SDK. The reference UI is one client
among equals and gets no special protocol access. This is what keeps "carry the
data, don't prescribe the experience" honest — if the first-party app had a
private channel, the data would quietly stop being self-describing.

### Firecracker

Firecracker snapshot files (memory file + VM state) are carried **unchanged** as
native blobs, fingerprinted per §6. Abra does not become a hypervisor; it moves
the artifacts a hypervisor produces.

## 12. Non-goals

- Executing anything. Not recipes, not payloads, not adapters' logic.
- Being a general multi-user file-sharing service. The mesh is one user's.
- Interpreting payload semantics in core. Payload types are strings; meaning
  lives in receivers.
- Ignore/exclusion logic in v1 (§8).
- A snapshot format that can be opaque (§1).
