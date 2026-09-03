# External adapter contract

Adapters are separate executables. They speak UTF-8 NDJSON over stdin/stdout,
one object per line and at most 1 MiB per object; stderr is diagnostics. The
daemon owns CAS, identity, hashing, recipes, and signed manifests. An adapter
never selects snapshot ids or origins and never supplies recipes.

## Registration

An `abra-adapter.json` beside the executable contains:

```json
{"spec":"abra-adapter/1","name":"com.example.browser","version":"1.0.0","kinds":["com.example.session"],"verbs":["export","import","watch"],"executable":"browser-adapter"}
```

Two adapters claiming a kind are a configuration error requiring explicit user
selection.

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
per operation. Export/import time out after ten minutes. Cancellation sends
`cancel {request_id}` and kills the process after five seconds.

## Verbs

- `export`: request `{kind,source,staging_dir,options}`. `source` is the parsed
  JSON object when the CLI value parses as an object, otherwise it is the raw
  string. `options` is an object of string values from repeated
  `--adapter-option k=v` arguments. The daemon creates an
  empty writable staging directory. The adapter writes only within it. Success
  returns `{payload,files_path|null,floor?:{title?,summary?,link?,thumbnail_path?}}`.
  The daemon hashes files, attaches observed recipes/native blobs, and authors
  and signs the manifest.

- `import`: request
  `{kind,payload,materialized_files|null,destination,options}`. `destination` is
  the parsed JSON object when `--destination` parses as an object, the raw
  string otherwise, or the `--to` path string when omitted. `options` has the
  same repeated `--adapter-option k=v` form as export. Files have
  already been verified and materialized. Success returns `{result,deep_link?}`.
  Recipes are never run implicitly.

- `watch`: request `{kind,source,options}`. It first returns
  `{ok:true,watching:true}`, then emits
  `{request_id,event:"changed",cursor,hint}` until cancelled. Events are hints;
  the daemon debounces and re-exports.

Cadabra's built-in workspace export/import and handoff handling are the
reference behavior for this contract; they are not external adapter processes.

The runner is implemented in Cadabra. `abra send <peer> --kind <kind> --source
<value> [--adapter-option k=v ...]` exports into daemon-owned staging before
signing and enqueueing; `abra accept <id> --to <dir> [--destination <value>]
[--adapter-option k=v ...]` invokes a registered importer after verified
materialization. Discovery skips broken registrations and reports them through
`abra adapters list`; `abra adapters add` still rejects the requested broken
directory. If two valid adapters claim the same kind, discovery reports the
conflict and refuses to dispatch that kind. The
reference conformance adapter is `adapters/reference-folder/`.
