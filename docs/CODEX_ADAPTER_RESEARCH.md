Codex session transport research, September 12, 2026

Abra can move a saved Codex conversation and workspace, then continue it with a
new Codex process. Extend the existing `adapters/codex-session` adapter and add a
persistent controller around Codex app-server. Exact live-process migration needs
Abra's compatible-host process or VM checkpoint backends.

The existing single-thread, idle-session path now has a repeatable live test.
Multi-agent and live-process handoff remain design work.

What exists in Abra

The adapter exports one rollout JSONL plus a manifest with hashes, version,
ancestry, and optional workspace snapshot references. Import checks integrity
and divergence, installs the rollout, and returns a manual resume command.
`abra send --workspace` transports the workspace as linked provenance beside the
adapter bundle. The adapter does not include child threads, credentials, or
running processes.

`controlSession` currently records pause and stop without performing them.
`instruct` runs `codex exec ... resume` only when `ABRA_CODEX_TEST_REAL=1`;
otherwise it reports that execution was skipped. Its child has a nine-minute
timeout and buffered output. The live test confirms remote `instruct` works when
the destination daemon has that flag and the correct `CODEX_HOME`. This is not
yet a persistent agent controller.

Two details need correction during implementation: the returned resume command omits the destination `CODEX_HOME`, and the workspace marker stores only the session ID. Consequently, later control can select the default home instead of the home used for import. Store the resolved home and executable with the workspace binding, and pass commands as argument arrays. Workspace paths in the current command string also need proper quoting for manual use.

The export lock uses `flock` on `thread-writer-locks/<id>.lock`. A real
`codex-cli 0.154.0` app-server test loaded a thread and kept it open; export then
failed with `busy` because Codex held the same writer lock. This establishes the
idle boundary for the tested version. Other Codex versions still need
compatibility coverage.

Available Codex integration

The official app-server interface supports conversation history, streamed events, approvals, and authentication. Its lifecycle uses `initialize`, `thread/resume`, and `turn/start`; `turn/interrupt` cancels an active turn. Experimental methods expose background terminals and descendant-thread filters. The documentation also distinguishes thread IDs from the live session-tree root ID. Use explicit relationships when gathering child threads. [Official OpenAI app-server documentation](https://learn.chatgpt.com/docs/app-server).

The locally installed binary is `codex-cli 0.154.0`. Its generated experimental JSON schema exposes resume by thread ID, path, or raw history. Path is marked unstable; raw history is explicitly reserved for Codex Cloud. Prefer restoring supported rollout files and resuming by ID. A rendered chat response is not a documented lossless export format. Generate protocol bindings from the supported executable version rather than assuming that current online examples match every installation.

A repeatable live test now exercises the actual adapter through two paired Abra
daemons. A real Codex turn uses a shell tool to create a workspace file and
keeps a second random token only in conversation history. Abra sends the linked
workspace and session to a clean Codex home. Before destination auth is added,
`codex login status` reports `Not logged in`; app-server can still resume the
thread and reconstruct readable history. The destination then receives a
temporary auth copy. Abra remote control starts the next model turn, which reads
the restored file and recalls the conversation-only token. Abra sends the
updated workspace and session back, and a third model turn on the source
confirms the destination assistant message and original memory.

The received rollout was byte-identical to the source rollout. Codex's derived
`thread_history_1.sqlite` was deliberately absent. On `codex-cli 0.154.0`, an
initial `thread/read` therefore returned an empty turn list; `thread/resume`
rebuilt the projection from the rollout, after which `thread/read` returned the
full turn. A receiving chat UI must resume before it assumes history is ready,
or the adapter/controller must explicitly rebuild the projection.

A second live test moved the session from macOS ARM64 to a disposable Daytona
Linux x86_64 sandbox and back. It used the Daytona file API as the carrier and
ran the Codex adapter at both endpoints. Both machines used `codex-cli 0.154.0`.
The repository's `daytona==0.210.0` pin was unavailable from the configured
package index, so this test used the compatible `daytona==0.198.0` SDK.
Daytona restored the full history before it had Codex auth. The test then copied
auth separately, ran a real model turn that recalled the conversation token and
read the transferred workspace file, exported the updated rollout, and resumed
it successfully on the Mac. The successful run took 36.0 seconds and deleted
the sandbox.

Codex's `workspace-write` command sandbox was denied inside the tested Daytona
container with `Operation not permitted`. The successful run disabled Codex's
inner sandbox for the remote turn because Daytona already supplied the isolated
disposable boundary. A production controller needs an explicit sandbox policy
for providers that block nested process isolation.

A separate test ran real Abra daemons on the Mac and inside Daytona with a
verified Linux x86_64 archive. The initial run timed out because Abra published
a direct-only address before Iroh's first network report finished. After Abra
waited for Iroh to become online, the Daytona side still rejected the relay TLS
certificate with `UnknownIssuer`. Daytona routes outbound HTTPS through its
proxy and exposes the proxy CA at `SSL_CERT_FILE`; Iroh otherwise uses only its
embedded Mozilla roots.

Abra now configures Iroh from the standard proxy environment, adds certificates
from `SSL_CERT_FILE` to the embedded roots, and waits up to ten seconds for the
initial relay report. Daytona also rejected the default n0 relay's absolute DNS
hostname with a trailing dot, while its per-sandbox allow-list validator rejected
a wildcard with that dot. Selecting
`https://use1-1.relay.n0.iroh.link` explicitly and allowing the exact hostname
fixed the route. The real Mac ARM64 to Daytona Linux x86_64 test then passed
pairing, confirmation, session acknowledgement, and session import in 14.2
seconds. Both tickets contained the selected relay, and the sandbox was deleted.

The hosted Abra Cloud flow was also exercised with a real Codex thread. The web
site captured it from the Mac, provisioned a Daytona sandbox, and imported the
same thread ID. The destination installed the matching `codex-cli 0.154.0`,
received auth separately, and resumed the thread to a verified model reply. The
cloud worker needed a shared install lock because its restore and inventory
loops could otherwise replace the collector and adapter directory concurrently.
The successful restore was closed from the site and its Daytona sandbox was
confirmed deleted.

A separate real app-server test created a forked child thread. Transporting the
root with the current adapter left the child unavailable at the destination.
This confirms that current success is single-thread continuation, not agent-tree
continuation. Compaction, attachments, active turns, background terminals, and
native live-process restore remain untested.

Recommended bundle

| Part | Proposed contents and behavior |
|---|---|
| Conversation | Root rollout and all selected descendant rollouts, checksums, thread relationships, source Codex version, and history format |
| Workspace | Abra snapshot reference with all required objects, including uncommitted changes and relevant untracked files |
| Execution settings | Model/provider selection, destination path mapping, required tools and runtimes, and references to required skills/configuration |
| Pending work | Last completed turn, interrupted work, outstanding user questions, goals, and known background jobs |
| Processes | Restart instructions and application checkpoints; optional native checkpoint reference where supported |
| Credentials | Absent by default; use destination credentials or an explicitly selected separate credential transfer |

Do not rewrite absolute paths throughout the transcript: old messages are historical evidence. Map the runtime working directory and workspace roots, and separately resolve referenced attachments and tool dependencies. Preserve opaque rollout records. Fail clearly on unsupported history formats rather than treating every valid JSONL file as resumable Codex state.

Recommended handoff

1. Bind Abra's controller to the source thread and obtain exclusive handoff ownership. Block new turns. If Abra cannot control an existing CLI/app session, require that it be idle and closed before portable capture.
2. Prefer waiting for a turn to finish. If interrupted, wait for completion of cancellation, then separately settle child agents and background jobs. A canceled model turn does not prove that every file writer or external operation has stopped.
3. Capture the rollouts and workspace at one coordinated boundary. Record interrupted operations and required dependencies. Retain the source checkpoint for recovery.
4. Transfer using Abra's existing signed, encrypted transport. Verify and restore the workspace and session bundle at the receiver. Resolve the target executable, configuration, and credentials.
5. Load the thread, verify its identity and restored state, then transfer driving ownership before allowing new work. Start a new turn to continue the task and stream progress through the controller. Resuming a thread alone does not mean generation has started.
6. Report stored, loaded, running, or blocked separately. On failure, release the destination claim before re-enabling the source. Use a durable handoff ID and lease generation so retries cannot start two writers.

This controller belongs beside the adapter, probably in the daemon/runtime integration. Keep export/import as bounded operations. A one-shot adapter invocation should not own the only handle to a long-running Codex process.

Authentication

Transport and offline inspection should require no OpenAI login. For continued hosted inference, use the receiving machine's existing ChatGPT login or API key, or request login there. Codex caches credentials in a file or OS credential store; copying a rollout does not copy those credentials. Optional credential migration should be explicit and separate, not a whole-home copy. Keychain-backed credentials need their own treatment. [Official OpenAI authentication documentation](https://learn.chatgpt.com/docs/auth).

Abra peer authorization and Codex provider authentication are separate. Reuse
Abra's trusted-device transport. Running app-server locally over stdio avoids
another network endpoint. Hosted inference still requires provider auth.

Implementation order and remaining proof

The single-thread, idle-session data path works end to end when the caller passes
the correct Codex home and starts Codex explicitly. Next, fix home selection and
replace the one-shot control command with an app-server controller that supports
automatic startup, streamed events, controlled interruption, recovery, and
ownership fencing. Then add child-thread bundles, goals, attachments, and
background-job restart support. Only claim native process continuation after
testing the relevant CRIU or VM backend with Codex itself.

Still-required evidence includes compacted context, attachments, archived
sessions, missing tools, transfer failure and retry, an active in-flight turn,
and background terminals. Cross-machine and cross-architecture application
state continuation has passed through the Daytona provider API, direct Abra
peer transport, and the hosted Abra Cloud workflow.
Outstanding approvals and external side effects need deliberate recovery
behavior, not automatic replay.

Validation used `codex-cli 0.154.0` with both real-test flags enabled. The full
adapter suite reported 13 passed, 0 failed, and 0 skipped in 23.2 seconds. It
covered the writer lock, the known missing child thread, remote `instruct`, and
the two-peer authenticated model round trip. The separate Daytona run passed
the Mac ARM64 to Linux x86_64 to Mac route, including real model continuation
at both ends. The direct daemon run also passed through an explicit n0 relay,
and the hosted cloud restore resumed the same real thread in Daytona. The
ordinary fixtures still emit `ENOENT: no such file or directory, mkdir '/work'`
diagnostics from workspace marker writes. Nothing was committed or pushed.
