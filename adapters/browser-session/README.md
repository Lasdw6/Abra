# Abra browser-session

The `storage_state` of the agent era: a zero-dependency Node 22 tool for moving an isolated browser session between any browsers that expose a CDP WebSocket URL.

It captures cookies with all CDP attributes, local and session storage, best-effort IndexedDB, and tabs. It adds sender/receiver domain policy, an inspectable signed manifest, install receipts, and context-scoped revocation. Browserbase, Browser Use, Steel, Kernel, local Chrome, or another provider are interchangeable at the boundary: supply its `cdpUrl`.

## Quick start

```sh
node bin/abra-browser.js export --from cdp 'ws://…' --include-domains example.com --out ./session
node bin/abra-browser.js inspect ./session
abra send --path ./session

node bin/abra-browser.js import ./session --to cdp 'ws://…' --deny-domains admin.example.com
node bin/abra-browser.js revoke ./session/receipt-….json
```

Local capture copies the selected Chrome profile before launching the copy, so Chrome may remain open:

```sh
node bin/abra-browser.js export --from local --profile Default --out ./session
```

Chrome is expected at `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`. If copied-profile CDP launch is impossible, the conceptual fallback is a consistent copy of Chrome's Cookies SQLite database followed by macOS Keychain decryption. Node 22 has no SQLite API and macOS does not guarantee a `sqlite3` CLI, while modern Chrome encryption formats vary. This release fails clearly instead of silently producing partial or undecrypted cookies. Installing into `--to local` leaves the copied-profile Chrome running; revocation stops it and removes its temporary profile copy.

## Playwright compatibility

```sh
node bin/abra-browser.js storage-state import state.json --out ./session
node bin/abra-browser.js storage-state export ./session --out state-again.json
```

The second file is byte-for-byte identical to the first. Browser-created bundles project cookies and localStorage into the ordinary Playwright shape. Session storage, IndexedDB, and tabs remain in `state.json`.

## Superset versus Browser Use profile sync

| Capability | Abra browser-session | Browser Use profile sync |
|---|---|---|
| Cookies | Bidirectional bundle mechanics | Local → cloud upload |
| Cookie attributes | Preserved through raw CDP | Provider-defined |
| local/session storage | Both | No |
| IndexedDB | Best effort | No |
| Tabs | URL/title, scroll hint | No |
| Provider | Any CDP URL | Browser Use Cloud |
| Domain policy | Sender and receiver | Sender filter |
| Read API | Manifest metadata only on receive path | `cookieDomains` only |
| Revoke | Clears dedicated imported context | Provider lifecycle |
| Custody | Direct, blind relay, or custodial | Custodial cloud profile |

DBSC is not bypassed. Google/Workspace and similar device-bound sessions can fail after otherwise correct cookie installation. The manifest reports only a documented domain-and-cookie-attribute heuristic, with possible false positives and negatives.

## Custody and policy

The same bundle works direct E2E, through a blind relay, or with a custodial service; only the encryption key holder changes. The signed inner manifest remains inspectable after decryption. Sender include/exclude filters reduce what leaves the source. Receiver allow/deny filters are separately authoritative and are applied immediately before installation.

Imports always create a new CDP browser context. A receipt contains identifiers but no values. Revoking it disposes that context, clearing its cookies and origin storage. A received bundle is marked non-re-exportable through the receive flow; a deliberate fresh capture by the browser owner is a new provenance event.

## Adapter mode

`bin/adapter.js` implements `abra-adapter/1` NDJSON on stdin/stdout. Export writes the three payload files into the daemon-provided `staging_dir` and returns a payload fragment; Abra core owns the outer snapshot, CAS, identity, and signature. Import consumes verified `materialized_files` and a CDP destination. Diagnostics go to stderr and each operation uses one process.

## Browser Use façade

Start the write-only-compatible profile metadata service:

```sh
node facade/server.js --root ./.profiles --port 8787
```

It implements `GET/POST /api/v4/profiles` and `GET/PATCH/DELETE /api/v4/profiles/{id}` with `{id,userId,name,lastUsedAt,createdAt,updatedAt,cookieDomains}`. Cookie values accepted on write are never returned or stored in profile metadata. Bundle directories are copied under the façade root; this is a local migration façade, not a hardened multi-tenant secret store.

The migration-shaped command is:

```sh
node facade/profile-use.js sync --profile Default --include-domains example.com --cloud-profile-id PROFILE_ID --endpoint http://127.0.0.1:8787
```

Mapping: `--profile`, include/exclude lists, and cloud profile id retain their Browser Use meanings; `--endpoint` selects this façade. The capture is richer than Browser Use cookie-only sync. Limitations: no Browser Use authentication/billing/browser launch API, no DBSC transfer, no cookie read endpoint, and local profile fallback depends on copied-profile CDP launch.

## Known CDP limits

IndexedDB export is limited to values Chrome can return by value and restore with ordinary object-store operations. Partitioned/experimental cookie attributes are passed through when Chrome accepts them. Full navigation history, service workers, Cache Storage, OPFS, extensions, client certificates, password manager data, and browser settings are not captured. Cookie re-injection listens while the import command remains connected; a provider that creates additional browser contexts later should invoke import for each context or keep the operation alive with `--watch-ms`.
