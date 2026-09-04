# External adapter contract

Adapters are separate executables. They speak UTF-8 NDJSON over stdin/stdout,
one object per line and at most 1 MiB per object; stderr is diagnostics. The
daemon owns CAS, identity, hashing, recipes, and signed manifests. An adapter
never selects snapshot ids or origins and never supplies recipes.
For sandbox workspaces, the daemon gets recipes from the observer ledger. The
ledger and recipes are data only and adapters must not execute them implicitly.
The [observation contract](OBSERVATION.md) separates observed facts from inferred
service candidates and lists the requirements an application must resolve.

## Registration

An `abra-adapter.json` beside the executable contains:

```json
{"spec":"abra-adapter/1","name":"com.example.session","version":"1.0.0","kinds":["com.example.session"],"controls":["dev.abra.workspace"],"verbs":["export","import","inspect","control"],"executable":"session-adapter"}
```

Two adapters claiming a kind are a configuration error requiring explicit user
selection.

`controls` is optional. It lists capsule kinds whose control messages this
adapter handles. These are capsule genesis kinds and need not appear in `kinds`.

Cadabra discovers `<root>/adapters/*/abra-adapter.json`; `abra adapters add
<dir>`, `list`, and `remove <name>` manage additional absolute directories.
`executable` is relative to the manifest directory and cannot escape it. It may
be omitted when the executable filename exactly equals `name`, which keeps the
browser-session manifest shape loadable.

Every request contains `protocol:"abra-adapter/1"`, a hex `request_id`, and a
`verb`. Every response repeats `request_id` and has either `ok:true` plus result
fields, or `ok:false,error:{code,message,retryable}`. Codes are
`invalid_request`, `unsupported_kind`, `unsupported_verb`, `not_found`,
`permission_denied`, `busy`, `cancelled`, and `internal`. There is one process
per operation. Export, import, inspect, and control time out after ten minutes.
Cancellation sends `cancel {request_id}` and kills the process after five seconds.

## Verbs

- `export`: request `{kind,source,staging_dir,options}`. `source` is the parsed
  JSON object when the CLI value parses as an object, otherwise it is the raw
  string. `options` is an object of string values from repeated
  `--adapter-option k=v` arguments. The daemon creates an
  empty writable staging directory. The adapter writes only within it. Success
  returns top-level `{payload,files_path|null,floor?:{title?,summary?,link?,thumbnail_path?},provenance?:{capsule_id,snapshot_id}}`.
  `snapshot_hash` is accepted as an alias for `snapshot_id` in `provenance`.
  The snapshot must exist locally on the sending device. The daemon sends that
  full snapshot before it sends the partial.
  The daemon hashes files, attaches observed recipes/native blobs, and authors
  and signs the manifest.

- `import`: request
  `{kind,payload,materialized_files|null,destination,workspace,options}`.
  `workspace` is a path string or `null`. It names the linked workspace directory
  when the daemon restored one. `destination` is
  the parsed JSON object when `--destination` parses as an object, the raw
  string otherwise, or the `--to` path string when omitted. `options` has the
  same repeated `--adapter-option k=v` form as export. Files have
  already been verified and materialized. Success returns top-level
  `{result,deep_link?}`.
  Recipes are never run implicitly.

- `watch`: reserved. The daemon cannot invoke it yet. Adapters should not
  declare it.

- `inspect`: request `{kind,source,options}`. Success returns top-level
  `{ok:true,summary?,warnings:[{code,message,item?}],blocked:[...]}`. This verb
  only examines the source. Before an adapter `send`, the daemon runs it when
  present. A non-empty `blocked` list stops the send unless `--force` was set.

- `control`: request `{kind,capsule_id,op,text,workspace,options}`. Success
  returns top-level `{result}`. `op` is `pause`, `stop`, or `instruct`. `text` is present
  only for `instruct`. `workspace` is the last local materialization of that
  capsule, or `null` when the daemon has no recorded path.

Cadabra's built-in workspace export/import and handoff handling are the
reference behavior for this contract; they are not external adapter processes.

## JavaScript helper

`adapters/lib/adapter.js` is the shared NDJSON loop for adapters written in
JavaScript. It has no dependencies and needs Node 20 or newer.
`runAdapter({kinds,controls,verbs})` enforces the 1 MiB line cap. It checks the
protocol, hex `request_id`, and kind. It dispatches the verb and emits flat
`ok:true` responses. A thrown `coded(code, message)` becomes
`{code,message,retryable}`. The daemon keeps
`retryable` and shows adapter errors as `<code>: <message>`. A `cancel {request_id}`
aborts the `AbortSignal` handed to the verb and answers `cancelled` once. `watch`
is reserved. The daemon cannot invoke it yet. Adapters should not declare it.

```js
#!/usr/bin/env node
import { coded, runAdapter } from '../../lib/adapter.js';
import { install, writeBundle } from '../lib/session.js';

await runAdapter({
  kinds: ['com.example.session'],
  controls: ['dev.abra.workspace'],
  internalMessage: 'example session operation failed',
  verbs: {
    async export({ source, staging_dir }, { signal }) {
      if (!source) throw coded('invalid_request', 'source is required');
      const payload = await writeBundle(staging_dir, source, signal);
      return { payload, files_path: staging_dir, floor: { title: `Session ${source}` } };
    },
    async import({ materialized_files, destination }) {
      return { result: await install(materialized_files, destination) };
    },
    async inspect({ source }) {
      return { summary: `Session ${source}`, warnings: [], blocked: [] };
    },
    async control({ op, text, workspace }) {
      return { result: { op, text, workspace } };
    }
  }
});
```

The runner is implemented in Cadabra. `abra send <peer> --kind <kind> --source
<value> [--adapter-option k=v ...]` exports into daemon-owned staging before
signing and enqueueing. `abra accept <id> <dir> [--destination <value>]
[--adapter-option k=v ...]` invokes a registered importer after materialization.
Discovery skips broken registrations and reports them through `abra adapters
list`. `abra adapters add` rejects a broken requested directory. Conflicting
kind claims prevent dispatch for that kind.

Reference adapters: `adapters/reference-folder/` is the Python conformance
adapter. Its protocol loop is written out by hand. `watch` is reserved. The
daemon cannot invoke it yet, so adapters should not declare it.
`adapters/codex-session/` moves one Codex CLI session with the JavaScript helper.
`adapters/browser-session/` has its own CLI and facade.
