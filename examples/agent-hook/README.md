# Agent post-turn hook

Set `ABRA_PEER` to the receiving peer id and `ABRA_WORKSPACE` to the workspace
root. Call `post-turn.sh "turn label"` after an agent turn. It snapshots the
workspace, then sends that exact snapshot. Repeating it is safe: Abra's CAS
deduplicates unchanged files and its durable outbox tracks delivery.

For a Claude Code Stop hook, invoke this script from your hook command and pass
a short label derived from the turn.
