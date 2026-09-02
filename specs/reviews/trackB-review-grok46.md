# Track B security review — `@abra/browser-session`

Reviewer: Grok 4.6
Worktree: `/Users/vividh/Desktop/abra-browser` (branch `browser-session`, HEAD `4551936`)
Scope: `docs/BROWSER-SESSION-BUNDLE.md` and `adapters/browser-session/` (`lib/`, `bin/`, `facade/`, `test/`, `README.md`)
Tests run: `cd adapters/browser-session && node --test` → 4/4 pass (Chrome 152 present). Repo was not modified.

This adapter exports real cookies, origin storage, and tabs into a signed-looking bundle and installs them into a CDP browser. Findings below treat `state.json` / `storage_state.json` as a bag of bearer credentials.

---

## Findings

### 1. CRITICAL — Unverified install receipts are a local process-kill and recursive-delete gadget

- **Where:** `adapters/browser-session/lib/cli.js:74-77`, `adapters/browser-session/lib/browser.js:117-125`
- **Defect:** `revoke` reads a JSON file and immediately uses its fields. It never calls `verifyObject`, never checks `kind`, and never canonicalizes paths. `process.kill(receipt.local_chrome.pid, 'SIGTERM')` accepts any pid (including negative pids, which Node delivers to a process group). The profile-copy guard is a string prefix check, not `realpath`:
  ```javascript
  receipt.local_chrome.profile_copy.startsWith(os.tmpdir() + path.sep)
  await rm(receipt.local_chrome.profile_copy, { recursive: true, force: true })
  ```
  Receipt signatures are written on the CLI import path (`cli.js:70`) with a fresh ephemeral key and then ignored.
- **Failure scenario:** An unprivileged local file the user is tricked into revoking (or any process that can drop a file and invoke `abra-browser revoke`) contains:
  ```json
  {
    "cdp_url": "ws://127.0.0.1:9222/devtools/browser/…",
    "browser_context_id": "any",
    "local_chrome": {
      "pid": -1,
      "profile_copy": "/var/folders/…/T/../Users/victim"
    }
  }
  ```
  Confirmed on this machine: `os.tmpdir() + '/../Users'` **does** pass `startsWith(tmpdir + sep)`. `rm(..., { recursive: true })` then walks out of `/tmp` and deletes the target. `pid: -1` can SIGTERM every process the user can signal. Independently, a live `cdp_url` plus `browser_context_id` disposes an arbitrary isolated context (session teardown).
- **Fix:** Verify the receipt signature against a **pinned** public key (not the key inside the file) and `kind === 'dev.abra.browser-session.receipt.v1'`. Resolve `profile_copy` with `fs.realpath`, require that the resolved path is strictly inside the temp dir, and refuse `pid <= 0`. Prefer killing only the child handle spawned by this process, not an attacker-supplied pid. Treat a missing/invalid signature as a hard error.

### 2. CRITICAL — Exported bundles are world-readable credential files

- **Where:** `adapters/browser-session/lib/util.js:70`, `adapters/browser-session/lib/util.js:82-92`, `adapters/browser-session/lib/cli.js:42-48`, `adapters/browser-session/lib/cli.js:94-99`
- **Defect:** `saveBundle` does `mkdir(dir, { recursive: true })` with default mode and `writeFile` without `mode: 0o600`. `writeJson` is used for `state.json`, `manifest.json`, and receipts. `storage-state export` `copyFile`s the Playwright view (cookie **values**) the same way.
- **Failure scenario:** `node bin/abra-browser.js export --from local --out ./session` was reproduced: directory mode `755`, `state.json` and `storage_state.json` mode `644`. Any local user (or a world-readable backup/sync of the cwd) can read `SUPER_SECRET` session cookies. `inspect` never prints those values, but the files sit next to the command the user just ran. Receipts written into the same directory inherit `644` and contain a live CDP WebSocket URL (finding 6).
- **Fix:** `mkdir(..., { mode: 0o700 })` and `writeFile(..., { mode: 0o600 })` for every payload file (`state.json`, `storage_state.json`, receipts). `fchmod` after `copyFile`. Document that `--out` must be a private directory; refuse to write if the parent is already world-accessible unless `--i-mean-it`.

### 3. HIGH — Local export copies the real Chrome profile into `/tmp` and never deletes it

- **Where:** `adapters/browser-session/lib/browser.js:128-154`
- **Defect:** `launchLocalChrome` `cp`s `~/Library/Application Support/Google/Chrome/<profile>` (Cookies, Login Data / saved passwords, IndexedDB, extensions, etc.) plus `Local State` into `mkdtemp('abra-browser-profile-')`. `withLocalChrome` (used by CLI `--from local` and `bin/adapter.js` export) only `SIGTERM`s Chrome in `finally`; it does **not** `rm` `tempRoot`. The error path kills Chrome (maybe) and also leaves the copy. `fs.cp` is called without `dereference: false` made explicit and without rejecting symlinks inside the profile.
- **Failure scenario:** User exports while Chrome is open (the documented happy path). After the command exits, `/var/folders/…/T/abra-browser-profile-*` still holds a complete profile clone. Same-user malware, a later leaked backup of `/tmp`, or a hung Chrome process that still has `--remote-debugging-port` open can recover the entire cookie jar and password DB. SQLite/Keychain fallback **is** refused (honest); this copy-and-forget path undoes that honesty.
- **Fix:** `try/finally` `rm(tempRoot, { recursive: true, force: true })` after Chrome exits (wait for the child, then delete). On error, delete before throwing. Refuse the copy if any directory entry is a symlink (`lstat` / `filter`). Copy only files required for CDP cookie access if possible; never leave Login Data in `/tmp`.

### 4. HIGH — `--to local` is not an isolated import; it launches a debug-enabled clone of the user’s real profile

- **Where:** `adapters/browser-session/lib/cli.js:62-67`, `adapters/browser-session/lib/browser.js:72-75`, `adapters/browser-session/lib/browser.js:128-148`
- **Defect:** Spec: import MUST create a fresh isolated context and MUST NOT install into the user’s default profile. Implementation: `--to local` first clones the real user profile into a temp user-data-dir, starts Chrome with `--remote-debugging-port=0` (no explicit `--remote-debugging-address=127.0.0.1`), then `Target.createBrowserContext` inside **that** process. Default context of the clone still contains every copied cookie. The child is `unref()`d and left running. `Storage.setCookies` is correctly scoped to `browserContextId` (the integration test checks this for `--to cdp`), but the process as a whole is a live, debuggable copy of the user’s session.
- **Failure scenario:** Operator thinks they are installing a received bundle into a clean isolated Chrome. Any local process fetches `http://127.0.0.1:<port>/json/version` (the DevToolsActivePort file is in the temp dir) and gets a browser-level WebSocket. From there they `Storage.getCookies` on the default context and steal the **real** profile, not just the imported bundle. The debug port remains open until someone happens to `revoke`.
- **Fix:** For import, launch Chrome with an empty `user-data-dir` (not a profile clone). Pass `--remote-debugging-address=127.0.0.1`. Do not `unref` without an explicit `--detach` that prints a loud warning. Prefer `disposeOnDetach: true` unless persistence is requested. Keep the CDP connection as the lifecycle owner.

### 5. HIGH — Receiver domain policy does not bind the cookie Chrome will actually store

- **Where:** `adapters/browser-session/lib/util.js:43-66`, `adapters/browser-session/lib/browser.js:33-36`, `adapters/browser-session/lib/browser.js:72-77`
- **Defect:** Filtering uses `cookie.domain` only (`cookieDomain` → `''` when `domain` is omitted). `cookieForCdp` forwards `url`. Empty include-list means allow-all; deny is suffix-match on that same `domain` string. Two independently confirmed bypasses:
  1. **URL-only cookie:** `filterState` keeps `{ name, value, url: 'https://admin.example.com/' }` when deny is `admin.example.com`, because `allowedDomain('', [], ['admin.example.com']) === true`. CDP `Storage.setCookies` then derives the host from `url`.
  2. **Parent-domain cookie vs subdomain deny:** deny `admin.example.com` **drops** storage/tabs for that host but **keeps** `{ domain: '.example.com', value: 'SECRET' }`. Browsers send that cookie to `admin.example.com`. Confirmed with the live `filterState` implementation.
  Additional policy gaps (same matcher): no Public Suffix List (`--include-domains com` matches `evil.com`; `--include-domains github.io` matches every Pages origin); no punycode/`ToASCII` (Unicode vs `xn--` are different hosts); host-only vs domain-cookie leading-dot is stripped, so policy cannot express “this host only”; `Secure` / `HttpOnly` / `SameSite` / `partitionKey` are not part of the decision.
- **Failure scenario:** Receiver imports with `--deny-domains admin.example.com` (or an adapter `deny_domains` list) believing admin cookies will not be installed. A crafted `state.json` (trivial to re-sign — finding 7) includes either a url-only admin cookie or a parent `Domain=.example.com` session cookie. Install proceeds; the isolated context is authenticated to the denied host.
- **Fix:** Derive the policy host from `cookie.domain` **or**, if absent, `new URL(cookie.url).hostname`; reject cookies with neither. For deny lists, also drop cookies whose domain is a suffix of a denied host (or whose domain would make the browser send them to a denied host). Reject cookie domains that are public suffixes. Normalize IDN with `url.domainToASCII`. Test these cases; today’s test only checks `blocked.test` as both cookie domain and origin.

### 6. HIGH — CDP WebSocket URLs (debugger capability) are persisted and returned as if they were opaque handles

- **Where:** `adapters/browser-session/lib/browser.js:102-110`, `adapters/browser-session/lib/cli.js:68-72`, `adapters/browser-session/bin/adapter.js:32-38`, `adapters/browser-session/lib/cdp.js:7`
- **Defect:** Spec: “In a production daemon the destination reference SHOULD be an opaque local handle rather than a CDP URL.” The receipt stores `cdp_url: wsUrl` (browser-level DevTools URL, including the secret path UUID). CLI writes it to `receipt-<ts>.json` next to the bundle (mode `644`, finding 2). The adapter import response is `{ result: { receipt } }` on **stdout**, so the entire URL is in the NDJSON façade toward Abra core. Connect errors interpolate the same URL: `cannot connect to CDP at ${this.url}`.
- **Failure scenario:** After `import --to cdp 'ws://127.0.0.1:9222/devtools/browser/<secret>'`, `./session/receipt-….json` is world-readable. Another user (or a CI log of adapter stdout, or `abra-browser: cannot connect to CDP at ws://…` on stderr) replays the URL, attaches as a debugger, and dumps cookies from every context the destination Chrome will give them — far beyond the isolated context the receipt was meant to describe.
- **Fix:** Store an opaque install id. If a CDP URL must be kept, write it mode `0600` in a user-private runtime dir, never in the bundle directory, never on adapter stdout, never in `error.message`. Redact URLs in all logs.

### 7. HIGH — Manifest/receipt “Ed25519 integrity” is self-signed with a throwaway key; verification trusts the attacker

- **Where:** `adapters/browser-session/lib/util.js:17-36`, `adapters/browser-session/lib/util.js:72-79`, `adapters/browser-session/lib/cli.js:70`
- **Defect:** `signObject` calls `generateKeyPairSync('ed25519')` on **every** sign, embeds `public_key` in the object, and `verifyObject` verifies with that same embedded key. Domain separation (`abra-browser-session-v1\0…`) is real, but the key is not an identity. `loadBundle` rejects a broken signature or hash mismatch, but an attacker who edits `state.json` just rebuilds hashes and re-signs. Confirmed: an object with `cookies:[{value:'pwn'}]` plus a freshly generated `signature` returns `verifyObject === true`. `loadBundle` also never rejects an unknown `manifest.version` (spec MUST); a mutated `version: 99` re-signed bundle still loads.
- **Failure scenario:** A relay or malicious sender delivers a bundle whose `state.json` adds `evil.com` cookies and whose `manifest.json` is re-signed with a new key. `abra-browser import` / adapter import accepts it. Abra’s outer envelope is specified as the real sender identity, but this standalone loader never requires it. Calling this “signed” on the CLI (`README.md`, inspect path) overstates integrity.
- **Fix:** Either (a) verify against a caller-supplied / daemon-supplied public key and refuse embedded-key TOFU, or (b) stop claiming payload integrity in CLI/inspect and require Abra core to have already authenticated `materialized_files`. Reject `manifest.version !== 1`. Bind `signature.domain` to the expected domain string. Do not generate a new key per object if a custody key is supposed to be rotatable and recorded in provenance.

### 8. HIGH — Write-only receive asymmetry is not enforced on the tool’s own paths

- **Where:** `adapters/browser-session/lib/cli.js:55-72`, `adapters/browser-session/lib/cli.js:94-99`, `adapters/browser-session/bin/adapter.js:24-38`, `adapters/browser-session/lib/browser.js:38-61`, `adapters/browser-session/lib/util.js:148`
- **Defect:** Spec: a received bundle is installable but MUST NOT be offered for re-export by that path; receipts record `reexportable: false`. CLI import sets `receipt.reexportable = false` but never consults it later. Adapter import does **not** set `reexportable` at all and does not sign the receipt. `storage-state export` `loadBundle`s any directory and copies `storage_state.json` (full cookie values) with no provenance check. `capture()` uses `Storage.getCookies` with **no** `browserContextId` (cookies from the default context) but `Target.getTargets` across **all** contexts, then scrapes localStorage/sessionStorage/IndexedDB from imported pages in the isolated context.
- **Failure scenario:** Facade/adapter/cloud browser imports a bundle (write-only by policy). An operator — or a second adapter `export` against the same CDP URL — runs `storage-state export ./session` on the still-on-disk payload, or `export --from cdp` against the destination browser, and recovers origin storage (and possibly cookies, depending on Chrome’s default `getCookies` scope) of the received session. The receive path has become a cookie/storage read API.
- **Fix:** After successful import, refuse `export` / `storage-state export` of that bundle unless provenance says `reexportable: true`. Adapter import must stamp `reexportable: false`. Capture must take an explicit `browserContextId` and must not walk targets from other contexts. Optionally shred or chmod the source bundle on import when `--consume` is set.

### 9. HIGH — Façade is unauthenticated and will copy arbitrary local paths into its data dir

- **Where:** `adapters/browser-session/facade/server.js:9-48`, `adapters/browser-session/facade/server.js:52-55`, `adapters/browser-session/facade/profile-use.js:14-18`
- **Defect:** Default bind is `127.0.0.1:8787` (good) with **no** auth, origin, or Host check. POST/PATCH accept `bundlePath` and `cp(path.resolve(source), destination, { recursive: true })`. Cookie **values** on the JSON body are not stored in profile metadata (`publicProfile` / `domainsFromCookies`) and GET/PATCH responses do not echo them — that part of write-only holds, and the CRUD test covers it. The HTTP API nevertheless implements a confused-deputy recursive copy into `root/bundles/<id>`. Errors return `error.message` to the client. `profile-use sync` first writes a full export into the cwd (`browser-session-<ts>/`, finding 2) then tells the façade to copy it; both copies remain.
- **Failure scenario:** Any local process (or a browser page issuing a “simple” POST with `Content-Type: text/plain` to skip CORS preflight) PATCHes `{ "bundlePath": "/Users/victim/Library/Application Support/Google/Chrome" }`. The façade, running as the user, copies the profile into `.abra-browser-profiles/bundles/<id>`. There is still no cookie-read route, but the plaintext bundle/`state.json` is now in an application directory that is easy to back up, sync, or later expose. `--host 0.0.0.0` makes this a network copy gadget with zero auth.
- **Fix:** Require a shared secret header. Allowlist `bundlePath` to a staging directory the tool created. Never `cp` client-supplied absolute paths. Ignore `Origin` mismatches. Keep the default bind on `127.0.0.1` and refuse `0.0.0.0` without an extra flag. Do not persist full bundles if the façade is metadata-only; if they must be stored, use `0700` dirs and `0600` files.

### 10. MEDIUM — Inspect / summary / façade HTTP responses omit values, but several error and metadata paths can still leak secrets

- **Where:** `adapters/browser-session/lib/cli.js:21-35` (good), `adapters/browser-session/lib/cli.js:50-53` (good), `adapters/browser-session/facade/server.js:41`, `adapters/browser-session/lib/cdp.js:11-12`, `adapters/browser-session/bin/adapter.js:19-20`, `adapters/browser-session/lib/util.js:144`
- **Defect:** `inspect` loads `state.json` but prints only `summary(manifest)`: domain counts, tab URL/title, heuristic DBSC reasons. Façade `publicProfile` strips cookies. Adapter export returns the manifest, not STATE. Those match the spec. Gaps: (1) tab URLs in the signed manifest / inspect output / adapter `payload.manifest.tabs` can carry OAuth tokens and magic links; (2) CDP `msg.error.data` is concatenated into `Error` strings that CLI/adapter emit; Chrome has been known to echo request fragments; (3) `storageRestoreScript` / `idbRestoreScript` embed credential JSON in `Runtime.evaluate` expressions — an evaluate failure’s `exceptionDetails` could theoretically include a snippet; (4) `catch (error) { json(res, 400, { error: error.message }) }` can return filesystem paths from `cp`/`readJson`.
- **Failure scenario:** User runs `inspect` on a bundle captured mid-OAuth redirect; stdout prints `https://idp.example/callback?code=…`. CI captures adapter stderr from a failed `setCookies` and stores it. A façade client sees internal paths.
- **Fix:** Strip query/fragment from tab URLs in manifests (keep them only in STATE). Never put `error.data` or evaluate exception descriptions on stdout/stderr without redaction. Façade should return a generic `bad request`.

### 11. MEDIUM — Cookie re-injection attaches to the whole browser, not only the isolated context

- **Where:** `adapters/browser-session/lib/browser.js:95-101`
- **Defect:** After install, `Target.setAutoAttach` is enabled on the **browser** connection (`flatten: true`, `waitForDebuggerOnStart: false`) with no `browserContextId` filter. The handler always `Storage.setCookies` into the isolated context (good; it does not write into default), but the debugger session auto-attaches to **every** new target, including the user’s default-profile tabs, for `--watch-ms` (and until the socket closes). Default `watchMs` is 0 so the listener is removed immediately — re-injection barely works unless `--watch-ms` is set, which is the opposite of the spec’s SHOULD.
- **Failure scenario:** Import `--to cdp` against a shared/cloud browser the user is also clicking in, with `--watch-ms 60000`. For a minute this tool is a debugger on their normal tabs (pause/script-injection surface) while credentials sit in another context of the same process.
- **Fix:** Auto-attach only inside the created context if the protocol allows it; otherwise ignore `attachedToTarget` unless `params.targetInfo.browserContextId === browserContextId`. Always send `setAutoAttach({ autoAttach: false })` before disconnect. Do not attach to default-context targets.

### 12. MEDIUM — `storage_state` round-trip drops partitioned-cookie fields; tests do not exercise fidelity

- **Where:** `adapters/browser-session/lib/util.js:96-101`, `adapters/browser-session/test/browser-session.test.js:94-102`
- **Defect:** Playwright compatibility projection keeps `name, value, domain, path, expires, httpOnly, secure, sameSite` and defaults `path=/`, `expires=-1`, `httpOnly=false`, `secure=false`, `sameSite='Lax'`. It **drops** `partitionKey` (and CDP `priority` / `sameParty` / `sourceScheme` / `sourcePort`). Missing `sameSite` becomes `Lax`, which is not the same as Chrome “unspecified”. Browser-created `storage_state.json` is therefore not a faithful Playwright cookie. The byte-stable test only round-trips `{"cookies":[],"origins":[]}` via `storageStateRaw`; it never checks `expires`, `sameSite`, `secure`, `httpOnly`, or `partitionKey`.
- **Failure scenario:** Capture a CHIPS / partitioned session cookie, import the Playwright file into another tool, and the cookie is installed unpartitioned (wrong jar) or with `SameSite=Lax` instead of `None`. Cross-site auth silently fails or over-shares.
- **Fix:** Pass through Playwright’s `partitionKey` when present. Do not default `sameSite` unless the source omitted it **and** the caller asked for Playwright defaults. Add a fixture with `expires`, `httpOnly`, `secure`, `sameSite: 'None'`, and `partitionKey` and assert both `state.json` and `storage_state.json`.

### 13. LOW — DBSC heuristic is honest in copy, but the matcher is broad and untested

- **Where:** `adapters/browser-session/lib/util.js:103-128`, `docs/BROWSER-SESSION-BUNDLE.md:88-97`, `adapters/browser-session/lib/cli.js:31-33`
- **Defect:** Domain list + `Secure+HttpOnly` + `/(^__Host-|bound|device|session|sid)/i` matches the spec, cookies are not stripped, and inspect prints “Non-teleportable (heuristic)” / `heuristic: true` rather than “is DBSC”. Good. The regex matches `sidecart`, `sessionid`, etc. (false positives) and will miss DBSC outside Google (false negatives). No test asserts wording or that flagged cookies still appear in STATE.
- **Failure scenario:** Operator sees `accounts.google.com` flagged, assumes the tool stripped Google cookies, and still ships a bundle that contains them (they remain; only the heuristic fires). Conversely, a non-Google DBSC cookie named `auth` is not flagged and is reported as teleportable.
- **Fix:** Keep the honest wording (already correct). Narrow the name regex (word boundaries / known prefixes only). Document false negatives. Add a unit test that a flagged cookie is still present in `state.json`.

### 14. LOW — Test adequacy vs. the threat model

- **Where:** `adapters/browser-session/test/browser-session.test.js` (entire file)
- **Defect:** Four tests cover (1) suffix include/exclude on a same-label cookie domain, (2) CDP round-trip + receiver deny of `127.0.0.1` + summary secrecy + default-context untouched + revoke dispose, (3) empty storage_state bytes, (4) façade CRUD does not echo `SUPER_SECRET`. Missing: url-only cookie deny bypass; parent-domain vs subdomain deny; PSL/`com`; IDN; ephemeral-key re-sign; `version` rejection; `reexportable`; receipt verification; `revoke` path traversal; bundle file modes; temp-profile cleanup; adapter stdout contract; façade `bundlePath`; `--to local` isolation; partitioned cookies; error-path leakage; `inspect` CLI (only `summary()`).
- **Failure scenario:** The 4/4 green run is exactly what a reviewer would get today while findings 1–9 remain exploitable.
- **Fix:** Add regression tests for each must-fix before merge. Include at least one test that `inspect` / adapter export JSON `JSON.stringify` does not contain planted cookie values (`alpha` / `SUPER_SECRET`).

---

## What is in acceptable shape

- Inspect’s intended print path does not dump cookie or storage **values**; the live test plants `alpha`/`beta`/`local-secret` and `summary()` does not match them.
- `--to cdp` install uses `Target.createBrowserContext` and `Storage.setCookies({ browserContextId })`; the integration test shows the default context does not receive imported cookies, and revoke disposes that context.
- SQLite/Keychain fallback is refused with a clear error instead of emitting partial undecrypted cookies.
- Façade GET/PATCH/DELETE responses do not return cookie values; bind defaults to `127.0.0.1`.
- DBSC copy does not claim a CDP bit it does not have.
- `cdp.js` `browserWebSocketFromPort` talks to `127.0.0.1`, not `0.0.0.0`.

These do not offset the credential-at-rest, revoke, and policy-bypass issues.

---

## Verdict

**Must-fix first.** Do not merge this as a handler of real authentication state.

The adapter does several things the spec asked for (isolated CDP context on the import-to-cdp path, manifest-without-values inspect, façade metadata write-only, honest DBSC labeling, no fake Keychain decrypt). It then stores those credentials world-readable, leaves full Chrome profile clones in `/tmp`, treats a random Ed25519 key inside the file as “integrity,” lets `revoke` kill processes and delete directories from untrusted JSON, and applies receiver deny lists to the wrong host fields so a crafted bundle can still install cookies for a denied domain.

### Top-3 must-fix

1. **Revoke is unsafe to point at untrusted JSON** — verify a pinned receipt signature; `realpath` + containment for `profile_copy`; never `kill` attacker pids. (`cli.js:74-77`, `browser.js:117-125`)
2. **Stop leaking credential bytes at rest** — `0600`/`0700` for bundles and receipts; delete temp profile copies in `finally`; do not import into a debug-enabled clone of the user’s real Chrome profile. (`util.js:70,82-92`, `browser.js:128-154`, `cli.js:62-67`)
3. **Make receiver allow/deny actually constrain what Chrome will store** — policy host from `domain` or `url`; drop parent-domain cookies that would be sent to a denied host; reject public-suffix cookie domains; add tests. (`util.js:43-66`, `browser.js:33-36`)

Do these three before any further feature work. Treat finding 7 (ephemeral self-signature) as blocking for any claim that `loadBundle` authenticates a sender; if Abra core already wraps the payload, the CLI still must not imply that a standalone `import` of a re-signed bundle is safe.
