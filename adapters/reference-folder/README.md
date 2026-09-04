# Reference folder adapter

`reference-folder.py` is the conformance reference for `abra-adapter/1`.
Export copies a folder into staging. Import copies materialized files to the
destination. Its kind is `dev.abra.folder`.

The protocol loop is written out in Python. It shows the language-neutral
contract. Read it with `docs/ADAPTERS.md`.

JavaScript adapters should not copy this loop. Use `adapters/lib/adapter.js`,
which implements the same framing, error codes, and `cancel` handling; see
`adapters/codex-session/bin/adapter.js`.

```sh
printf '%s\n' '{"protocol":"abra-adapter/1","request_id":"01","verb":"export","kind":"dev.abra.folder","source":"/tmp/src","staging_dir":"/tmp/staging"}' | ./reference-folder.py
```
