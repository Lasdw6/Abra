# Browser-session bundle v1

Status: Track B implementation specification. Normative terms use RFC 2119.

## Purpose and envelope

`dev.abra.browser.session.v1` is a provider-neutral, human-inspectable browser-session payload: “the `storage_state` of the agent era.” The adapter also accepts the legacy outer and inner kind `dev.abra.browser-session.v1` so capsules from older builds remain importable. It is a strict semantic superset of Playwright `storage_state`, adding session storage, IndexedDB, tabs, policy, provenance, integrity, receipts, and revocation. It can be sent as an Abra `partial` snapshot. The core authors and signs the Abra envelope; this document specifies the payload files inside it.

A payload directory contains:

- `manifest.json`: summary, policy, provenance, hashes, and an Ed25519 signature from a persistent per-installation key. It MUST NOT contain cookie or storage values.
- `state.json`: full browser state. Treat this file as a credential.
- `storage_state.json`: the Playwright compatibility view.

The payload kind is `dev.abra.browser.session.v1`. `manifest.json` has `version: 1`. Unknown fields MUST be preserved by transforms where practical and ignored by readers. A reader MUST reject an unknown major version, an invalid manifest signature, or a state hash mismatch.

The manifest signature is over canonical key-sorted JSON with `signature` omitted, domain separated by `abra-browser-session-v1\0browser-session-manifest\0`. The private key is persistent and stored `0600` below the tool data directory; `inspect` displays its public-key fingerprint. It proves integrity and continuity with that key, not human identity. Abra's signed outer envelope remains authoritative. A foreign standalone import MUST require explicit trust of an out-of-band-verified fingerprint; it MUST NOT silently trust the embedded key.

## Compatibility

The compatibility view has exactly Playwright's shape:

```json
{"cookies":[],"origins":[{"origin":"https://example.test","localStorage":[]}]}
```

Importing a plain `storage_state` file and exporting it again MUST reproduce its bytes unchanged, including whitespace and field order. Its semantic content is also projected into `state.json`. Browser capture produces `storage_state.json` by projecting cookies and local storage; fields not representable by Playwright remain in `state.json`.

## Manifest

The signed, human-readable manifest contains:

- `kind`, `version`, `capture_time`, and `source_browser`;
- `source` and `provenance`, including whether the capture path permits re-export;
- sender `policy.include_domains` and `policy.exclude_domains`;
- `domains`: domain, cookie count, HttpOnly count, and Secure count;
- `origins`: origin plus booleans for localStorage, sessionStorage, and IndexedDB presence;
- open `tabs` as URL and title only;
- `total_size`, `state_sha256`, and `storage_state_sha256`;
- `cookie_flags_preserved`, explicitly including HttpOnly and Secure;
- `non_teleportable`, with domain, reasons, and `heuristic: true`;
- `signature` (`algorithm`, `domain`, `public_key`, `value`).

Counts describe the post-sender-policy state. `total_size` is the UTF-8 byte size of compactly serialized STATE and is informational; the SHA-256 hashes are authoritative for payload-file integrity. Inspection MUST read only the manifest and MUST NEVER print cookie values, storage values, or IndexedDB records. Manifest tab URLs MUST omit query strings and fragments.

## State

STATE contains:

- `cookies`: all CDP cookie attributes available at capture, including name, value, domain, path, expiry, HttpOnly, Secure, SameSite, priority, SameParty, source scheme/port, and partition key;
- `origins`: each serialized origin with `localStorage`, `sessionStorage`, and best-effort `indexedDB` databases, object-store definitions, keys, and structured-clone values that CDP can return by value;
- `tabs`: URL, title, and, when cheap, scroll position and history length.

IndexedDB is explicitly best effort. Values that CDP cannot serialize by value, unsupported key types, database version races, service-worker-owned state, OPFS, Cache Storage, WebSQL, extensions, client certificates, passwords, autofill, and browser settings are outside v1. History length is descriptive; cross-document history entries are not reconstructed.

## Domain policy at both ends

Domain matching is label-boundary suffix matching after lowercasing and removing a cookie domain's leading dot. Thus `example.com` matches `example.com` and `a.example.com`, but not `badexample.com`.

The sender MUST apply its include list (empty means all) and exclude list (exclude wins) to cookies, origins, and tabs before writing STATE. The receiver MUST independently reapply its allow list (empty means all) and deny list (deny wins) immediately before installation. Sender policy is evidence, never authorization at the receiver. Cookie hosts use IDNA ToASCII, lowercase, and leading-dot normalization. Host-only cookies use `url`; domain cookies use `domain`, and a supplied `url` MUST agree. Public-suffix domain cookies MUST be rejected. Denying a child host MUST reject a parent-domain cookie the browser would send there. Storage and tabs use normalized origin hosts. Implementations MUST NOT broaden either policy to make a restore succeed.

## Receive asymmetry and provenance

The receive path is write-only: a received bundle is installable but MUST NOT be offered for re-export by that path. An install receipt records `reexportable: false`. This prevents a relay, façade, or cloud browser from becoming a cookie read API. It does not claim that a browser owner with filesystem/debugging access cannot recapture its own browser through a separate, explicit export operation.

Provenance records capture method, source browser, sender policy, capture time, and transformations. Consumers MUST retain provenance when copying the same bundle. Recapture is a new bundle with new provenance.

## Custody modes

The payload bytes and semantics are identical in all modes; only the encryption key holder changes:

| Mode | Key holder | Relay visibility |
|---|---|---|
| Direct E2E | sending and receiving devices | ciphertext and routing metadata |
| Blind relay | endpoints; relay never receives the key | ciphertext and routing metadata |
| Custodial | provider or user-authorized custody service | plaintext while in custody |

The inner manifest signature remains verifiable after transport encryption is removed. Custody mode MUST be displayed by the transport or product and MUST NOT be inferred from bundle contents alone.

## Install, receipts, and revocation

Import MUST create a fresh isolated browser context and MUST NOT install into the user's default profile. Cookies are installed with CDP `Storage.setCookies` for that browser-context id. Storage is restored in an origin-bound page; tabs are then opened. Cookies SHOULD be reapplied when new targets/contexts appear during the live import operation, because providers may create pages lazily.

Accepted destinations are omitted, `local`, `managed`, `{type:"local"}`, `{type:"managed"}`, `cdp:<ws-url>`, a bare `ws://` or `wss://` URL, and the equivalent typed CDP object. Omitted, `local`, and `managed` install into the adapter-owned browser. Any other string, including the materialization directory supplied as Abra's default destination, MUST fail without launching a browser. The adapter MUST read bundle files only from `materialized_files`; sender payload metadata MUST NOT select a local path.

An importer writes a receipt signed by the pinned local installation key containing: receipt kind, install time, opaque install id, isolated context id, cookie identifiers (never values), installed origins, effective policy, source-bundle digest, and `reexportable: false`. It MUST NOT contain a PID, path, or CDP URL. The capability mapping lives in a private `0600` registry. Revocation MUST verify kind, signature domain, fingerprint, pinned key, and registry/context match before action. It MUST never kill a PID or delete a path supplied by a receipt; registered processes require command-line verification and tool paths require `realpath` containment.

Revocation is scoped to what the receipt installed. On `revoke`, the importer MUST clear installed cookies and origin storage in that isolated context. Disposing the dedicated browser context satisfies this atomically and is preferred. Revocation is local cleanup, not global credential invalidation: it cannot revoke server-side sessions, copies, prior recaptures, or sessions installed elsewhere. A missing/already-disposed context is reported, not silently treated as proof of remote revocation.

## DBSC and non-teleportability

Device Bound Session Credentials can bind authentication to a device-held key. Copying the visible cookies therefore may not transfer the authenticated session. Browsers do not expose a reliable universal “this cookie is DBSC-bound” bit over CDP.

V1 uses an honest heuristic:

1. flag a maintained list of known DBSC-capable domains (`accounts.google.com`, `google.com`, `googleapis.com`, `workspace.google.com`, including subdomains); and
2. add an attribute hint when a Secure + HttpOnly cookie has a session-like name (`__Host-`, `session`, `sid`, `bound`, or `device`).

These signals can produce false positives and false negatives. The manifest marks every result `heuristic: true`. It MUST say “may not teleport,” never “is DBSC,” and MUST preserve the cookies and their HttpOnly/Secure flags unless domain policy removes them.

## Security notes

STATE is equivalent to a bag of bearer credentials. Payloads, receipts, and registries MUST be `0600`; containing directories and temporary profiles MUST be `0700`. Export copies MUST be removed in `finally` and on interrupts. Imports MUST use a fresh tool-owned profile, never a clone of the user's real profile. Keep it encrypted in transit and at rest, minimize retention, avoid logs/backups, and verify integrity before use. Consent MUST be explicit and legible; a shell installer or generic browser permission is not sufficient consent to export authentication state. Secure/HttpOnly flags constrain browser script access, not possession of an exported bundle.

The external adapter MUST reset a materialized bundle to these private modes before reading it. Cadabra may materialize files as `0644` and directories as `0755`.

On macOS, `local` export reads open tabs through a copied profile in a temporary headless Chrome. With no open tabs it captures cookies only, as before. Direct CDP capture remains available.
