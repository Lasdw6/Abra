# Abra browser-session

A Node 22 tool for moving isolated browser sessions between CDP browsers. It has
no dependencies. Inspect and adapter export do not expose credential values.

**Current limitation:** capture by launching a copied personal Chrome profile is disabled
while a reported sign-out is investigated. Those fallback inventory entries are
not transferable. The old implementation launched a network-enabled copy of
account settings and cookies; reading a copy did not prevent server-side effects.
The offline helper is experimental and is not connected to adapter capture.
See [the investigation](../../docs/reviews/browser-session-investigation.md).

The `saved-cookie-tab` adapter source and restores of its bundles are now
blocked after a second reported source logout. The implementation below is
experimental and is not an available transfer path. It requires `profile` (a Chrome profile directory name), `tab_id`, and
`expected_url`. The caller must establish which profile owns the tab; AppleScript
cannot prove that association. This source copies only the Cookies database and
its journal into a temporary directory, queries that copy, and decrypts eligible
cookies for the selected URL through macOS Keychain. It does not start Chrome.
The bundle includes the selected tab URL, but excludes page storage, partitioned
cookies, and expired cookies. Unknown formats fail. Keychain may require user
permission; prompt persistence is not yet verified. General inventory capture
remains disabled until profile association is reliable.

The optional `inventory` verb lists current HTTP(S) tabs from normal Chrome and
an already-running Abra browser without launching either. Each item carries an
opaque selector. Export checks the browser session, tab identity, and URL again
at capture time and returns `not_found` after a close, restart, or navigation.
The canonical and legacy bundle kind aliases produce one inventory entry.
Normal Chrome connects through Chrome 144+'s built-in, permission-gated remote
debugging support. No extension is required. In your running Chrome, open
`chrome://inspect/#remote-debugging`, enable remote debugging, and allow Abra's
connection when Chrome asks. Abra never changes this setting or restarts Chrome.
Run `node bin/native-browser-host.js --connect` once to start the user-only local
broker and request Chrome's approval. Inventory, export, and import only reuse
that live connection; they never open or reopen it. After Chrome or the broker
restarts, run the explicit connect command again. Chrome's approval covers the
connection, not a permanent grant.

On a machine with the user’s Chrome, omitted and `local` imports open new tabs
in that profile and never write cookies or site storage. Existing tabs are never
navigated, reloaded, or closed. The user already has their own sign-in.

On a sandbox, or when `--to managed` / `--destination cdp` is explicit, portable
cookies are installed into an isolated browser context. Device-bound cookies are
omitted and cannot be overridden.

Chrome documents this connection method at
https://developer.chrome.com/docs/devtools/agents/get-started/configuration#connect-to-an-existing-browser-session.

```sh
node bin/abra-browser.js export --from cdp 'ws://…' --out ./session
node bin/abra-browser.js inspect ./session
node bin/abra-browser.js import ./session --to cdp 'ws://…' --deny-domains admin.example.com
node bin/abra-browser.js preview --from managed --out ./preview.jpg
node bin/abra-browser.js revoke "$HOME/Library/Application Support/Abra/browser-session/receipts/<id>.json"
```

Tool data (signing key, receipts, install registry) lives under
`~/Library/Application Support/Abra/browser-session` on macOS and
`$XDG_DATA_HOME/abra/browser-session` (default `~/.local/share/...`) elsewhere.
`ABRA_BROWSER_DATA_DIR` overrides both. A fresh directory works: the key is
created on first use, so `import ... --to cdp <ws> --trust-sender <fp>` runs on
a Linux box with only node and the bundle.

`inspect` prints the persistent signing-key fingerprint. This installation trusts
its own bundles. For a foreign bundle, verify the fingerprint separately and
pass `--trust-sender <fingerprint>`. The signature proves integrity and key
continuity. Abra's signed outer envelope supplies sender identity.

Bundle files are `0600` in `0700` directories. Receipts contain an opaque install ID. They never contain a PID, path, cookie value, or CDP URL.

Destination capabilities live in a private registry. Receiver policy normalizes case and IDNs. It checks URL and domain consistency and rejects public-suffix cookies.

It also rejects a parent-domain cookie when it could reach a denied child host.

## Your browser

The disabled legacy `export --from local` path on macOS copied open tabs and their cookies and origin
storage from your Chrome. It copies profile state into a temporary directory,
reads it through a headless Chrome, then deletes the copy, including on errors
and interrupts. `--profile` selects a directory under the Chrome root (`Default`
if omitted, or the last-used profile from Local State). `local:<profile>` is the
same choice. Symlinked source profiles are refused.

The AppleScript fallback cannot identify which Chrome profile owns a window. It
uses Chrome's last-used profile for the copied-profile capture, so tabs open in
another profile may capture no session or the wrong account for that site. The
native Chrome connection reads the selected target directly and should be used
when more than one normal profile is open.

On Linux, `local` never falls back to a separate profile. Choose a normal Chrome
tab from live inventory through the native connection. `export --from managed` is an
explicit headless or sandbox operation and errors if none is running.

`preview --from local|managed|cdp` prints JSON metadata (`media_type`, `width`,
`height`, `title`, `items`) and writes the image when `--out` is set. A
debuggable browser yields a JPEG of the active page and the http(s) tab list.
On macOS, `local` against a real Chrome profile has no debugging port, so
preview returns that tab list and a small placeholder PNG instead of a
screenshot. The same limitation skips the export thumbnail. Live export writes
`floor.thumbnail_path` to a file under `os.tmpdir()` so it is not hashed into
the bundle. The adapter process exits after the response; leftover thumbnails
are left for the OS temp cleaner. A 60s timer deletes the file if the process
is still running.

`import --to local` on a user machine opens tabs in the existing Chrome profile
and does not install cookies. `--to managed --detach` is the sandbox path: an
isolated Abra-owned profile that does receive portable cookies. `--to normal`
names the user Chrome path explicitly.

Chrome is found at `CHROME_BIN`, `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`, or `google-chrome` / `google-chrome-stable` / `chromium` / `chromium-browser` on PATH. SQLite/Keychain fallback is deliberately unavailable rather than producing partial credentials.

## Playwright compatibility

`storage-state import` and `storage-state export` round-trip imported bytes. Browser projections preserve supplied fields including `partitionKey` without inventing `SameSite`. Non-re-exportable provenance is refused.

## Adapter and façade

Applications can import the supported JavaScript surface from `lib/index.js`.
It exports whole-context and exact-target capture, bundle save/install, live
install/revoke, manifest construction, and cookie portability helpers. Internal
files may change independently of this entrypoint.

The adapter also accepts an exact CDP target as a structured source:
`{"type":"cdp","cdp_url":"ws://…","target_id":"…","expected_url":"https://…"}`.
Set adapter option `include_storage=false` to capture cookies and tab metadata only.
Set `selected_cookie_keys` to a base64url-encoded JSON string array to include
only chosen cookies. A key is base64url JSON of `[domain,path,name,partitionKey]`.

`bin/adapter.js` implements `abra-adapter/1`. Export puts the real bundle in `files_path`; its `payload` field contains manifest metadata only. Imports mark receipts non-re-exportable and never return a CDP URL.

Import destinations omitted or `local` follow the machine: user Chrome when a
desktop profile exists, otherwise the isolated sandbox browser. `normal` is
always the user’s Chrome (tabs only). `managed` is always the isolated browser
(portable cookies).
Use `--destination cdp:<ws-url>` for a CDP browser you already started. A filesystem path, including Abra's default
materialization directory, is rejected. That path never authorizes a browser
launch.

## Through Abra

On Mac A, send the tabs and sign-ins from your own Chrome:

```sh
abra send <peer> --kind dev.abra.browser.session.v1 --source local
```

On Mac B, accept them as new tabs in the existing Chrome. Cookies are not
written; that machine already has its own sign-in:

```sh
abra accept <id> <dir> --destination local
```

`cdp:http://127.0.0.1:9222` still works if you already started Chrome with
remote debugging. The adapter looks up `/json/version` itself. `cdp:ws://…`
works when you already have the WebSocket URL.

Live inventory selects one tab from normal Chrome. `--source managed` explicitly
captures sessions in Abra's sandbox browser on that machine.

A bundle captured elsewhere (for example by the sandbox coordinator, which runs
`export --from cdp` inside a sandbox with an ephemeral key) is sent as-is with
`--source bundle:<dir>` or `{"type":"bundle","path":"<dir>"}`. The adapter
verifies the signature, refuses received (non-re-exportable) bundles, and
copies the files unchanged, so the receiver sees the original signer's
fingerprint. To land such a bundle on disk without importing it, use
`abra accept <id> <dir> --no-import`, then push it into the target browser with
`import <dir> --to cdp <ws> --trust-sender <fp>`.

`bin/cdp-fixture.mjs` is a test helper for live tests: `set` seeds a cookie,
localStorage entry and tab for one origin over CDP, `get` prints them as JSON
(cookie values included, so test browsers only). It needs `lib/` next to it.

GitHub with a test account is the recommended demo site. Google sessions can fail to transfer because Google uses device-bound session credentials.

The façade requires a bearer secret and defaults to loopback:

```sh
ABRA_BROWSER_FACADE_SECRET='a-long-random-secret' node facade/server.js --root ./.profiles
```

It rejects cross-origin requests and accepts `bundlePath` only below its private `staging/` directory. Non-loopback bind requires `--allow-network`. Errors are generic.

Device-bound cookies are omitted from STATE. The report is heuristic and may be
wrong. There is no override that puts them back.

IndexedDB restore is best effort. Passwords, extensions, Cache Storage, OPFS, client certificates, autofill, browser settings, and full history are not captured.
