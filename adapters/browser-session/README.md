# Abra browser-session

A Node 22 tool for moving isolated browser sessions between CDP browsers. It has
no dependencies. Inspect and adapter export do not expose credential values.

```sh
node bin/abra-browser.js export --from cdp 'ws://…' --out ./session
node bin/abra-browser.js inspect ./session
node bin/abra-browser.js import ./session --to cdp 'ws://…' --deny-domains admin.example.com
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

`export --from local` on macOS copies open tabs and their cookies and origin
storage from your Chrome. It copies profile state into a temporary directory,
reads it through a headless Chrome, then deletes the copy, including on errors
and interrupts. `--profile` selects a directory under the Chrome root (`Default`
if omitted, or the last-used profile from Local State). `local:<profile>` is the
same choice. Symlinked source profiles are refused.

On Linux, and when Chrome's profile root is missing, `local` is the managed
browser this tool opens under the data directory. `export --from managed` always
reads that browser. It errors if none is running.

`import --to local --detach` installs into the managed browser, creating a fresh
isolated context. Chrome stays running until you revoke that context. Debugging
binds to loopback. `--to managed --detach` is the same destination.

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

Import destinations `local`, `managed`, `{type:"local"}`, and an omitted value
all reuse the managed browser. Use `--destination cdp:<ws-url>` for a CDP
browser you already started. A filesystem path, including Abra's default
materialization directory, is rejected. That path never authorizes a browser
launch.

## Through Abra

On Mac A, send the tabs and sign-ins from your own Chrome:

```sh
abra send <peer> --kind dev.abra.browser.session.v1 --source local
```

On Mac B, accept them into a browser Abra opens or reuses there. It is headless
when there is no desktop:

```sh
abra accept <id> <dir> --destination local
```

`cdp:http://127.0.0.1:9222` still works if you already started Chrome with
remote debugging. The adapter looks up `/json/version` itself. `cdp:ws://…`
works when you already have the WebSocket URL.

`--source managed` captures sessions already imported into the Abra browser on
that machine.

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

DBSC is not bypassed. Its report is heuristic and may be wrong. Flagged cookies remain in STATE unless policy removes them.

IndexedDB restore is best effort. Passwords, extensions, Cache Storage, OPFS, client certificates, autofill, browser settings, and full history are not captured.
