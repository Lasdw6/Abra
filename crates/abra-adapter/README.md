# abra-adapter

Discovery and the `abra-adapter/1` NDJSON runner. Cadabra uses this crate. Abra
Cloud or a third-party tool can depend on it without pulling in `abra-net` or
the daemon.

Adapters are executables. A request is one JSON object on stdin, a response is
one object on stdout, and each line is at most 1 MiB.

## Calling it

**Registry.** `AdapterRegistry::discover` and `discover_with` find
`abra-adapter.json` under a store root, a persisted `registry.json`, and extra
directories. `export`, `import`, `inspect`, `inventory`, and `control` spawn the matching
adapter. Export staging is created next to the store and checked so the adapter
cannot write outside it.

**Process.** `invoke` starts one adapter executable, writes the request, reads
one response line, and kills the process on timeout.

**Protocol only.** If you cannot stream the adapter's stdin and stdout, use the
file-based helpers. They are the two halves of `invoke`: the same envelope, the
1 MiB cap, the `request_id` check, and the same per-verb normalisation.

```rust
let (request_id, request) = abra_adapter::protocol::build_request("export", body)?;
// send `request` as one NDJSON line, then read one line back
let result = abra_adapter::protocol::parse_response("export", &request_id, &line)?;
```

`build_request` rejects a non-object body. `parse_response` requires an object
`payload` for `export`, turns `import` into `{result, deep_link?}`, returns
`control`'s `result`, and parses `inspect` as `InspectResult`.

`AdapterRegistry::inventory` calls an adapter once by name with its first
declared kind, empty options, no source, and a 10-second timeout.
`inventory_with_options` takes a string-to-string options map for the same call,
allowing callers to select a folder or page. Reports are limited to 256 items
and remain subject to the protocol's 1 MiB response cap.

Inventory reports may include `description`, a plain-text source/setup hint of
at most 1024 UTF-8 bytes with no control characters. Consumers should show it
even for an empty item list. Reports can also include opaque `context` JSON
(up to 16 KiB), such as the current folder, parent, roots, or next page.
Consumers must not treat context as transferable content.
