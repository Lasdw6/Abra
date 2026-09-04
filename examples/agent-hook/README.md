# Agent post-turn hook

Set `ABRA_PEER` to the receiving peer id and `ABRA_WORKSPACE` to the workspace
root, which must be an initialized capsule (`abra init "$ABRA_WORKSPACE"`).
Call `post-turn.sh` after an agent turn. One `abra send --path <workspace>
--wait` snapshots the workspace, sends that snapshot, and returns only once the
delivery is acknowledged. Repeating it is safe: Abra's CAS deduplicates
unchanged files and its durable outbox tracks delivery.

For a Claude Code Stop hook, invoke this script from your hook command.
