# Add Abra to your sandbox

This path builds one binary, pairs two devices, and adds an adapter.

## Install one binary

```console
$ cargo build --release -p abra-cli
$ install target/release/abra ~/.local/bin/abra
```

The second line is optional. The rest of this page assumes `abra` is on
`PATH`.

## Start it

```console
$ abra daemon --background
```

The command prints the peer id after the daemon starts. It writes logs to
`<root>/daemon.log`. Run `abra stop` to stop a background daemon.

## Pair two machines

On machine B, create a ticket:

```console
$ abra pair ticket
```

Copy the ticket and add it on machine A:

```console
$ abra pair add '<ticket>'
```

Without `abra daemon --yes` on B, `pair add` waits and prints the exact
`abra pair confirm <peer-id>` command to run on B. You can also use
`abra pair pending` there. With `--yes`, B confirms pairing requests without
that step.

## Send a workspace

On A:

```console
$ abra init ./work
$ abra send <peer-b> --path ./work --wait
```

An initialized directory has `.abra/capsule_id`. Sending that path creates and
sends its next full snapshot. `--wait` returns after B acknowledges it.

On B:

```console
$ abra accept --latest --kind dev.abra.workspace ./work
```

`--latest` requires exactly one matching delivery. Pass a snapshot id instead
when several match. With no unread inbox match, it falls back to a capsule
`main` head of that kind sent by another peer, which is what the workspace
quickstart relies on. Replacing an existing workspace keeps local edits unless
you pass `--discard-local`, and refuses a snapshot that does not descend from
the recorded one unless you pass `--allow-divergence`.

## Watch progress

```console
$ abra watch
$ abra handoffs
```

`watch` streams events. `handoffs` gives one current row per snapshot kind.

## Write a small adapter

Create `adapters/example/abra-adapter.json`:

```json
{"spec":"abra-adapter/1","name":"com.example.note","version":"0.1.0","kinds":["com.example.note"],"controls":["dev.abra.workspace"],"verbs":["export","import","inspect","control"],"executable":"adapter.js"}
```

Create an executable `adapters/example/adapter.js`. It uses the shared helper:

```js
#!/usr/bin/env node
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { runAdapter } from '../../lib/adapter.js';
await runAdapter({
  kinds: ['com.example.note'],
  controls: ['dev.abra.workspace'],
  verbs: {
    async export({ source }) {
      return { payload: { text: await readFile(source, 'utf8') } };
    },
    async import({ payload, destination }) {
      await mkdir(destination, { recursive: true });
      await writeFile(`${destination}/note.txt`, payload.text);
      return { result: { imported: true } };
    },
    async inspect() { return { warnings: [], blocked: [] }; },
    async control({ op, text, workspace }) {
      return { result: { op, text, workspace } };
    }
  }});
```

Start the daemon with the adapter directory or its parent:

```console
$ abra stop
$ abra daemon --background --adapters ./adapters
```

`--adapters` is repeatable. `ABRA_ADAPTERS` is the colon-separated form.

## Let a peer act on control

The manifest's `controls` field claims the capsule kind. Its `control` verb
receives `kind`, `capsule_id`, `op`, `text`, `workspace`, and `options`.
`workspace` is the last local materialization recorded for the capsule, or
`null`.

From the peer that sends the command:

```console
$ abra control <peer> --capsule <id> instruct "check the failing test"
```

The result returned by the remote adapter appears in the control
acknowledgement. The acknowledgement may have `ok:false` and an `error`.

## Automate the receiving side

On the receiving machine, grant one sender and kind permission to accept into a
directory and then forward the accepted snapshot:

```console
$ abra policy grant --peer <sender> --kind com.example.note --auto-accept --to ./accepted --forward <next-peer>
```

Auto-accept materializes the files and runs the registered importer before it
marks the inbox item read. Abra then enqueues the same signed snapshot for the
forward peer.

## What Abra will not do

- Execute recipes, payloads, or adapter logic inside the core.
- Act as a general multi-user file-sharing service.
- Interpret payload meanings in the core.
- Apply ignore or exclusion rules in version 1.
- Accept opaque snapshot formats.
