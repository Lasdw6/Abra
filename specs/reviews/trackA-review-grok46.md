# Track A security review — Grok 4.6

Scope: uncommitted work in `/Users/vividh/Desktop/abra` vs `5d973ec` (`git diff HEAD` / `git status`). Read SPEC.md (AES-GCM capability-link erratum + fleet policy), DESIGN.md, docs/API.md. Repo was not modified; no mutating git. `cargo test --workspace` = 74 passed. `cd viewer && node --test` = 2 passed.

Crypto that was actually checked (not just read): mint record JSON contains neither the raw key nor a `#` fragment; rewriting `expires_at` in the ABRACAP1 header makes `link::open` fail (AAD bind); `abra log` on a diamond DAG inserted in reverse topological order still emits parent-before-child and is **not** BTreeMap-by-id order.

---

## Findings

### 1. High — `viewer/viewer.js:76`

**Defect.** `esc()` HTML-encodes text nodes but is then interpolated into `href`. `javascript:` and `data:` survive. SPEC §1.1 allows `manifest.link` to be any absolute URI scheme. The viewer has no trust store (DESIGN §10): anyone who can mint a self-signed snapshot (or an unsigned one — finding 2) can put an executable URL in `link`.

**Failure scenario.** Attacker mints a capability link whose signed manifest has `"link":"javascript:alert(document.cookie)"` (or `data:text/html,...`). Victim opens the viewer URL. Title/summary are escaped, so the card looks fine; "Open link" executes in the viewer origin. HTML entity encoding does not help: the HTML parser decodes `&lt;` in attributes before the URL is used, so `data:text/html,&lt;script&gt;...` becomes a live `data:` document.

**Fix.** Parse `manifest.link` with the URL API. Allow only `http:` / `https:` (plus an explicit extra-scheme allowlist if you truly need `abra:` / `vscode:`). Reject `javascript:`, `data:`, `vbscript:`, `file:`. Prefer setting `a.href` from a validated `URL` object rather than string-building `innerHTML`. Add a CSP (`default-src 'none'; img-src blob:; connect-src *` or tighter) as defense in depth.

### 2. High — `viewer/viewer.js:73-78`

**Defect.** After AES-GCM succeeds, the viewer always paints the floor card, clickable `link`, thumbnail, and download buttons. `verified===false` ("invalid signature") and `verified===null` ("browser lacks Ed25519") are badge-only. CLI `link open` is stricter: `RawManifest::parse` (`crates/abra-core/src/manifest.rs:372-389`) rejects a bad signature before `import`. The static viewer does not.

**Failure scenario.** Attacker hosts ciphertext encrypted to the fragment key and a manifest with a garbage `signature`. Victim still sees the card, can click `javascript:` (finding 1), and can download pack files. The "signature verified" badge is also misleading on the happy path: it only means self-consistent Ed25519 under `origin.peer_id` inside the pack, not a trusted mesh peer. DESIGN admits this, but the badge still reads like trust.

**Fix.** If `verified===false`, stop: no `innerHTML` card, no downloads, no `link` anchor. If `verified===null`, keep the badge but still refuse to activate `manifest.link` and optionally refuse downloads. Word the true-verified badge as "self-signed / integrity OK (untrusted origin)".

### 3. High — `viewer/viewer.js:55-63`

**Defect.** `treeEntries` advances with `p = nul + 41`. If the blob is longer than 40 bytes and contains no NUL after a space, `nul === -1` and `p` sticks at 40 → infinite loop. Names are not validated (`..`, `/`, huge depth). Rust `Tree::decode` (`crates/abra-core/src/cas.rs:202-215`) rejects those; the viewer never calls an equivalent.

**Failure scenario.** Attacker-hosted full pack includes a "tree" blob `abra.tree.v1\n` plus ≥41 bytes of NUL-less padding, referenced from `manifest.files`. Decrypt succeeds; `files()` hangs the tab (confirmed with a 80-byte fixture: throws only when a 1000-step guard is added). Nested trees can also stack-overflow `walk`. Combined with finding 2, the pack need not even be signed.

**Fix.** Port the Rust tree rules: magic, bounds, `check_name`, depth ≤ 512, path ≤ 4096, require `p` to strictly increase, cap total files/bytes. Abort the walk on the first violation.

### 4. Medium — `crates/abra-core/src/link.rs:269-283`, `crates/abra-cli/src/main.rs:444-457`

**Defect.** SPEC §9.2: revocation = delete or replace ciphertext with `ABRACAPX`. Implementation tombstones only when the persisted mint URL starts with `file://`. README's production path is `--upload-command` + `--url https://...`. There is no revoke hook, and `link open` / the viewer only look at blob magic + HTTP 404/410 — not the local `revoked` flag.

**Failure scenario.** Operator mints with `--upload-command 'aws s3 cp {file} ...'` and `--url https://objects.example/s/<hash>`. `abra link revoke <id>` flips the mint record and prints "revoked". The S3 object is unchanged. Anyone with the old fragment URL keeps decrypting until the host independently deletes the object or it expires (client clock is advisory).

**Fix.** Tombstone every locally reachable blob path, not just the recorded `file://` URL. For remote URLs, require a `--revoke-command '{url} {hash} {file}'` (or delete-by-hash) and fail revoke if it is missing when the URL is not `file://`. `link open` should also refuse if a local mint record for that ciphertext hash is `revoked: true`.

### 5. Medium — `viewer/viewer.js:72` and `crates/abra-core/src/link.rs:170-214`

**Defect.** No max `ct_len` / pack / blob size. Viewer does `fetch` → `arrayBuffer` → `JSON.parse` → base64-decode every pack blob into a `Map` plus a `files()` array that retains copies. Rust `open`/`import` similarly decode all blobs into RAM and CAS.

**Failure scenario.** Full-mode mint of a multi-GB workspace (or an attacker-crafted pack with a 2 GiB base64 blob). Opening the share URL OOMs the browser tab; `abra link open` OOMs the CLI. Bearer links are meant to be opened by arbitrary third parties.

**Fix.** Enforce a documented cap (e.g. floor packs tens of MB; full packs opt-in with a CLI flag). Check `ct_len` before decrypt; reject individual blobs above N; stream or refuse `full` in the static viewer.

### 6. Medium — `crates/abra-cli/src/main.rs:244-246`, `crates/cadabra/src/lib.rs:465-479`

**Defect.** Guests cannot `pair-*`, `enroll-mint`, token `revoke`, `control`, `lease-take`, or `mesh-profile` via Cadabra. `abra link` is handled **before** the daemon/UDS path and opens the store directly, so a guest role is never consulted. Capability-link mint is outbound sharing and is not gated on `scopes.send`.

**Failure scenario.** Cloud guest enrolled with `send: false` (mesh send disabled). Same `abra` binary, same `--root`. `abra link mint <snapshot> --full --upload-command ...` publishes a bearer URL for every object in that snapshot. That bypasses the send bit that enrollment is supposed to enforce. (A guest with a shell can often exfiltrate materialized files anyway; this is a second, protocol-shaped channel that also ships CAS objects that may not be on disk.)

**Fix.** `run_link` must load `TrustStore` and refuse `mint`/`serve` unless `LocalRole::Full` (or at least `scopes.send` plus an explicit policy). Do not treat store-root access as "already game over" for guest sandboxes whose only identity is the guest key.

### 7. Medium — `crates/abra-net/src/auth.rs:543-600` vs `crates/abra-net/src/delivery.rs:283-325` and `520-571`

**Defect.** Fleet guest→guest is documented as receiver-side policy requiring both scopes. `TrustStore::authorize_offer` implements that, but **delivery never calls it** (only tests do). Live checks are duplicated in `enqueue` (sender guest) and `validate_offer` (receiver). Guests cannot set `mesh-profile` (finding 6 / cadabra blocklist). `enroll-ok` mesh rows are **full peers only** (`delivery.rs:1174-1183`), and join does not copy the issuer's profile (`cadabra/src/lib.rs:187-191`). Default is `MeshProfile::Personal` (`auth.rs:153-159`) — good.

**Failure scenario (safety).** Fail-closed: two guests still cannot deliver to each other after the issuer runs `abra mesh profile fleet`, because neither guest daemon is in `fleet` and neither has the other in its trust store. Not an authorization bypass; the advertised policy is unreachable.

**Failure scenario (if someone later inserts guests into each other's stores without copying the duplicated checks).** Test coverage will not catch a `validate_offer` / `enqueue` drift from `authorize_offer`.

**Fix.** Call `authorize_offer` from `enqueue` and `validate_offer` (single policy function). Push `mesh.profile` (and, for fleet, the bounded guest mesh) at enroll-ok, or document that `fleet` is issuer-local only and does not enable guest↔guest p2p in v1. Keep guests unable to set the profile (already true on the UDS API).

### 8. Medium — `viewer/viewer.js:77`

**Defect.** Thumbnail `media_type` is passed straight into `new Blob(..., {type})` with no allowlist. SPEC §1.1 permits only `image/png|jpeg|webp`.

**Failure scenario.** Attacker pack sets `thumbnail.media_type` to `image/svg+xml` (or `text/html`) with a hostile blob. `img` + SVG script is blocked in current major browsers but is a needless XSS footgun next to finding 1; a future `iframe`/`object` refactor would execute it.

**Fix.** Drop the thumbnail unless `media_type` is one of the three SPEC types (and sniff magic bytes). Never copy attacker MIME into a blob URL used as a document.

### 9. Low — `viewer/viewer.js:65,78` and `viewer/viewer.js:55-63`

**Defect.** Downloads use `a.download = f.name` (tree entry name), not the walked path. Viewer tree names are unvalidated (finding 3). Rust materialize is safe (`cas.rs:202-215`, `hostile_symlink` test). This is the remaining filename issue on the static path.

**Failure scenario.** Hostile tree name `report.html` or a very long name: user downloads attacker HTML and opens it locally (outside the viewer origin). `..` in the download attribute is usually stripped by the browser, so this is not a server-side path traversal.

**Fix.** After porting `check_name`, also sanitize the download attribute to a basename matching `^[A-Za-z0-9._-]{1,255}$` or similar.

### 10. Low — `crates/abra-cli/src/main.rs:578-643`

**Defect.** `link serve` rejects `..` and `\\` but follows symlinks, sends `Access-Control-Allow-Origin: *`, and has no `X-Content-Type-Options: nosniff`. Request path `""` serves `index.html` with `application/octet-stream` because the Content-Type branch keys off the URL path, not the file.

**Failure scenario.** Dev server bound to `0.0.0.0` with a symlink in the share dir leaks that file. `/` may not render the viewer (functional). Not a key leak: fragments are not sent.

**Fix.** `canonicalize` and require the resolved path to stay under the serve root; `nosniff`; set HTML type when the opened file is `index.html`.

### 11. Low — `crates/abra-net/src/delivery.rs:1074-1082`

**Defect.** `capsule-sync` adds `capsule_id` + `scope` to the local NDJSON event log. `events`/`watch` are not guest-blocked; the UDS already "is the device key" (docs/API.md). No capability-link keys appear. Control events still log the full message (pre-existing).

**Failure scenario.** Any process that can connect to `cadabra.sock` already has full authority; this is not a new remote leak. Same-uid malware reading `net/events.ndjson` learns capsule ids that arrived over the mesh.

**Fix.** None required for v1 if the socket stays 0600 / same-uid. Optionally drop `capsule_id` from retained events or gate `events`/`watch` like other sensitive ops.

### 12. Info — `SPEC.md:700-706` vs erratum `SPEC.md:837-842`

**Defect.** Body of §9.2 still specifies XChaCha20-Poly1305 `alg=1` / 24-byte nonce. The erratum (and the code/viewer) use AES-256-GCM `alg=2` / 12-byte nonce. Implementation follows the erratum.

**Failure scenario.** A third-party viewer implemented from §9.2 without reading errata cannot open minted links (interop miss, not a crypto break).

**Fix.** Patch §9.2 in place so the normative wire format is AES-GCM; leave the erratum as history.

---

## What was verified (no defect)

Capability-link crypto matches the erratum:

- Fresh 32-byte key + 12-byte nonce from `OsRng` per mint (`link.rs:133-137`).
- AAD = `ABRACAP1 || alg || nonce || u64be(expires_at)` (`link.rs:139-156`, decrypt `link.rs:185-192`; viewer `viewer.js:26-27`). Expiry cannot be extended by header rewrite (probed).
- Ciphertext object is named by `Hash::of(blob)` (`main.rs:429-431`); bearer key is only appended when printing the share URL (`main.rs:458-468`), after `--upload-command` runs with `{file}`, `{hash}`, `{url}` only (`main.rs:444-448`).
- `MintRecord.url` is documented fragment-free; saved CJSON has no key field (`link.rs:49-60`). Probed on disk.
- `link list` human output has no URL/key (`main.rs:486-494`); JSON list is the mint records, still fragment-free.
- `open` / `decryptCapability` refuse `ABRACAPX`, check expiry **before** decrypt, then verify manifest signature + blob digests in Rust (`link.rs:170-214`). CLI materializes only after that (`main.rs:507-512`).
- Viewer `parseCapabilityUrl` puts the key in `key` and fetches only `u` / the de-fragmented href (`viewer.js:7-15,70`). No `pushState`. Cross-origin `fetch` does not include the fragment in Referer.

Fleet / guests:

- Default `personal` (`auth.rs:153-159`).
- Guests cannot pair, mint enrollment, token-revoke, control, lease-take, or change mesh profile via Cadabra (`cadabra/src/lib.rs:465-479`).
- Receiver `validate_offer` still forbids guest→guest in personal profile (`delivery.rs:520-525`, `545-551`) and, in fleet, checks both the sender's send scope and the local guest receive scope (`delivery.rs:553-569`). Fail-closed.

`abra log`:

- Kahn/BTreeMap implementation (`cadabra/src/lib.rs:822-846`) guarantees locally known parents before children, deterministic snapshot-id order within a ready wave, and errors on cycles. Probed with a 4-node diamond inserted merge-first: log order ≠ id-sort order, parent-before-child held.

Recipes are only pretty-printed (`viewer.js:76`), never executed.

---

## Test adequacy

| Area | Present | Gap |
|---|---|---|
| AES-GCM roundtrip, wrong key, expiry | `core_spec.rs` + `viewer.test.mjs` | No AAD-tamper test in-repo (behavior is correct) |
| Key never persisted | none | Must assert mint CJSON / `link list` JSON / upload argv lack the key |
| Revoke tombstone | mint record `revoked: true` only | Does not read the blob for `ABRACAPX`; no HTTPS upload case |
| Viewer XSS / schemes | none | `javascript:` / `data:` href |
| Viewer tree parser | none | infinite loop + `..` names |
| Invalid signature rendering | none | |
| Fleet | `authorize_offer` only (`net_spec.rs`) | No `enqueue` / `validate_offer` / two-guest delivery test; that API is unused in production |
| `abra log` topology | none (e2e is linear hops) | Diamond / reverse-insert / cycle |
| Guest cannot `link mint` | none | CLI bypasses Cadabra |
| Size limits | none | |

`viewer.test.mjs` checks decrypt shape and fragment parsing; it does not instantiate the DOM card, so findings 1–3 would not fail CI.

---

## Verdict

**Must-fix first.** Do not commit the static viewer as a zero-install receive path until findings 1–3 are fixed: it is an attacker-controlled HTML renderer with executable `manifest.link`, a signature check that does not gate rendering, and a tree walker that can hang the tab.

Capability-link **crypto** (fresh AES-256-GCM key, 12-byte nonce, AAD-bound expiry, key not in mint records / upload argv / `link list`) is in good shape and can stay. Fleet defaults and Cadabra guest locks for pair/enroll/control are fail-closed; do not advertise working guest→guest until finding 7 is wired.

### Top-3 must-fix

1. **Finding 1** — Stop treating `esc(manifest.link)` as a safe `href`; allowlist `http(s)` (and explicit custom schemes). This is XSS in the product you are shipping to anyone with a URL.
2. **Finding 2** — Do not render links or downloads when `verified===false`; do not imply mesh trust with "signature verified".
3. **Finding 3** — Bound and validate the viewer tree parser (no infinite loop, no unbounded walk). Same patch should add a pack-size cap (finding 5) if it is cheap.

Finding 4 (remote revoke is a no-op) should land in the same PR if `--upload-command` remains in README; otherwise remove the production-hosting claim until there is a tombstone path.
