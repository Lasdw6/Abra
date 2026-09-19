# Local transfer demo

Requires Rust 1.91+ and Python 3. This local example pairs two disposable roots, sends a
workspace, checks its restore plan, and materializes it. It needs no cloud account.

Run these commands from a checkout of this repository. To install the CLI into
your Cargo bin directory afterward, run `cargo install --locked --path crates/abra-cli`.
For a release archive, unpack it and add its directory to `PATH`; keep the bundled
`adapters` directory. Register individual adapters with
`abra adapters add /absolute/path/to/adapters/reference-folder` while the daemon
is running. Python and JavaScript adapters need their own interpreters installed.

```sh
cargo build --locked -p abra-cli
ABRA="$PWD/target/debug/abra"
DEMO=$(mktemp -d)
printf 'Demo files: %s\n' "$DEMO"
mkdir "$DEMO/source"
printf 'portable state\n' > "$DEMO/source/checkpoint.txt"
"$ABRA" --root "$DEMO/a" daemon --background --yes
"$ABRA" --root "$DEMO/b" daemon --background --yes
TICKET=$("$ABRA" --root "$DEMO/b" pair ticket)
"$ABRA" --root "$DEMO/a" pair add "$TICKET"
PEER=$("$ABRA" --root "$DEMO/b" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer_id"])')
"$ABRA" --root "$DEMO/a" init "$DEMO/source"
SNAPSHOT=$("$ABRA" --root "$DEMO/a" --json snapshot "$DEMO/source" | python3 -c 'import json,sys; print(json.load(sys.stdin)["snapshot_id"])')
"$ABRA" --root "$DEMO/a" send "$PEER" --snapshot "$SNAPSHOT" --wait
"$ABRA" --root "$DEMO/b" --json restore-plan "$SNAPSHOT"
"$ABRA" --root "$DEMO/b" accept "$SNAPSHOT" "$DEMO/restored"
cat "$DEMO/restored/checkpoint.txt"
"$ABRA" --root "$DEMO/a" stop
"$ABRA" --root "$DEMO/b" stop
```

Use `--yes` only with disposable test roots or where ticket possession is enough
to authorize pairing. Normal pairing asks the receiving device for confirmation.
Keep the printed demo directory to inspect the snapshots; delete it when finished.

See [Add Abra to your sandbox](INTEGRATE.md) for setup steps.
[Local API](API.md) lists commands, fields, results, and events.
[Adapters](ADAPTERS.md) defines the adapter process contract.
[Sandbox observations](OBSERVATION.md) describes the ledger and capture contract.
[Live process checkpoints](PROCESS_CHECKPOINTS.md) explains the optional CRIU path.
[Design](../DESIGN.md) explains design choices. The [protocol specification](../SPEC.md)
defines the wire format.
