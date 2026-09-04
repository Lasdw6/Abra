# Abra codex-session

An `abra-adapter/1` adapter that moves one Codex CLI session. A session is one
`rollout-*.jsonl` file under `$CODEX_HOME/sessions/`. Kind:
`dev.abra.codex.session.v1`. Zero dependencies, Node 20+.

```sh
abra send <peer> --kind dev.abra.codex.session.v1 --source '{"session_id":"<uuid>"}'
abra accept <id> <dir> --destination '{"codex_home":"/home/me/.codex","workspace":"/work/demo"}'
```

`bin/adapter.js` is the stdio loop built on `adapters/lib/adapter.js`; all the
behavior lives in `lib/session.js`.

Export takes a writer lock and validates the rollout. Its first record must be
`session_meta`. The UUID must match the filename, and the file must end in a
newline. Export scans for credential shapes and copies the file to staging as
`session.jsonl`. It writes `manifest.json` with counts, hashes, sizes, and the
last imported ancestor. A secret finding aborts export with its category and
line number. Inspect it locally before using `--adapter-option allow_secrets=true`.

Import verifies the bundle against the manifest and outer payload. It refuses a
rollout that diverged from the declared ancestor. It does not merge histories.
It also refuses the same UUID at another rollout path. Import checks the local
`codex --version`, then installs the file as `0600` under `0700` directories.
It records a checkpoint for the next handoff. Import runs nothing. Its result
contains the `codex resume` command to run by hand.

Sessions are limited to 512 MiB. Export source objects accept `session_id`,
`codex_home`, `workspace_snapshot_id`, `workspace_capsule_id`,
`workspace_ancestor_snapshot_id`, and `workspace_name`. A string source is the
session id.

Destination objects require `codex_home`. They may include `workspace` and
`expected_workspace_ancestor`. The last field must match the bundle's
`workspace_ancestor_snapshot_id`.

`CODEX_BIN` selects the Codex executable for version checks and control.
For `instruct`, control reads the session id from
`<workspace>/.abra/codex-session.json`. It runs `codex exec ... resume` in that
workspace. Pause and stop are recorded only.

Options: `allow_secrets`, `allow_version_mismatch`, `skip_version_check`,
`stage_only`, `lock_nonce`.

## Tests

```sh
node --test adapters/codex-session/test/*.test.js
```

They use temporary `CODEX_HOME` directories and never touch a real `~/.codex`.
`ABRA_CODEX_TEST_REAL=1` additionally enables the one test that shells out to an
installed `codex` binary for the version check. The writer lock uses `perl`
(`PERL_BIN` overrides the path).
