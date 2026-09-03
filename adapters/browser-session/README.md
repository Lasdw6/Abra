# Abra browser-session

A zero-dependency Node 22 tool for moving isolated browser sessions between CDP browsers. It captures cookies, local/session storage, best-effort IndexedDB, and tabs without exposing credential values in inspect or adapter-export output.

```sh
node bin/abra-browser.js export --from cdp 'ws://…' --out ./session
node bin/abra-browser.js inspect ./session
node bin/abra-browser.js import ./session --to cdp 'ws://…' --deny-domains admin.example.com
node bin/abra-browser.js revoke "$HOME/Library/Application Support/Abra/browser-session/receipts/<id>.json"
```

`inspect` prints the persistent signing-key fingerprint. This installation's own bundles are trusted automatically. For a foreign standalone bundle, verify the fingerprint out of band and pass `--trust-sender <fingerprint>`. The signature proves integrity and continuity with that key, not a person's identity; Abra's signed outer envelope supplies sender identity.

Bundle files are `0600` in `0700` directories. Receipts contain an opaque install ID—never a PID, path, cookie value, or CDP URL. Destination capabilities live in a private registry. Receiver policy normalizes case and IDNs, checks URL/domain consistency, rejects public-suffix cookies, and rejects a parent-domain cookie if it could reach a denied child host.

## Local Chrome

`export --from local --profile Default` makes a private profile copy and always removes it after Chrome exits, including error and interrupt paths. Symlinked source profiles are refused. `import --to local --detach` launches a fresh empty profile under the tool data directory, never a clone of the user's profile, and binds debugging to loopback. `--detach` is explicit because Chrome remains alive until verified revocation.

Local export currently captures cookies only. Chrome's last-session files are not part of a stable, cheap-to-read format, and the copied profile starts with a blank tab. Use direct CDP capture for the demo and whenever tabs or origin storage matter.

Chrome is expected at `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`. SQLite/Keychain fallback is deliberately unavailable rather than producing partial credentials.

## Playwright compatibility

`storage-state import` and `storage-state export` round-trip imported bytes. Browser projections preserve supplied fields including `partitionKey` without inventing `SameSite`. Non-re-exportable provenance is refused.

## Adapter and façade

`bin/adapter.js` implements `abra-adapter/1`. Export puts the real bundle in `files_path`; its `payload` field contains manifest metadata only. Imports mark receipts non-re-exportable and never return a CDP URL.

Import destinations are explicit. Use `--destination local` to launch a fresh detached Chrome, or `--destination cdp:<ws-url>` to install into a CDP browser. Omitting `--destination` fails the import. The filesystem path passed by Abra as the default destination is only where it materializes the bundle and never authorizes a browser launch.

## Through Abra

On Mac A, start a separate Chrome profile with remote debugging. Sign into the demo site in that Chrome window, then fetch its CDP WebSocket URL and send the session:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 --user-data-dir="$HOME/.abra-demo-chrome"
CDP_URL="$(curl -fsS http://127.0.0.1:9222/json/version | node -e 'let s="";process.stdin.on("data",c=>s+=c).on("end",()=>process.stdout.write(JSON.parse(s).webSocketDebuggerUrl))')"
abra send <peer> --kind dev.abra.browser.session.v1 --source "cdp:$CDP_URL"
```

On Mac B, accept the transfer into a fresh detached local Chrome:

```sh
abra accept <id> --to <dir> --destination local
```

GitHub with a test account is the recommended demo site. Google sessions can fail to transfer because Google uses device-bound session credentials.

The façade requires a bearer secret and defaults to loopback:

```sh
ABRA_BROWSER_FACADE_SECRET='a-long-random-secret' node facade/server.js --root ./.profiles
```

It rejects cross-origin requests and accepts `bundlePath` only below its private `staging/` directory. Non-loopback bind requires `--allow-network`. Errors are generic.

DBSC is not bypassed. Its report is explicitly heuristic, with possible false positives and negatives; flagged cookies remain in STATE unless policy removes them. IndexedDB restore is best effort. Passwords, extensions, Cache Storage, OPFS, client certificates, autofill, browser settings, and full history are not captured.
