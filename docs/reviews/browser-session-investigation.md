# Browser session transfer investigation

## Latest incident: second source logout

After the controlled Morse transfer and its immediate source-authentication
check, the user reported being signed out of GitHub again. The earlier pass
was only an immediate observation; it did not establish the required preservation
of source authentication. The transfer must be treated as a failed regression.

The adapter now rejects `saved-cookie-tab` capture before cookie access and
rejects imports of bundles marked `saved-cookie-db-read-only` before browser
access. Two containment tests pass. The legacy cloned-profile path remains
blocked. Operational deployment, later-job audit, and closure of the exact
isolated Daytona test context are being checked.

The recurrence means copied Chrome account preferences are not a sufficient
explanation for all observed logouts. Reuse of the same website session from
two clients, server-side invalidation, and other causes remain hypotheses.
No further authenticated replay is authorized by this investigation workflow.

## Incident and scope

The user reported that the original Chrome window was signed out after a
transfer. This is distinct from a new, unsigned-in restore profile. The exact
server-side cause has not been established. Unchanged tab URLs or profile files
do not prove that authentication remained valid.

The requested regression case is the private `Lasdw6/morse` GitHub tab, restored
into the existing Daytona sandbox. Tests must not navigate, reload, close, or
write cookies into the original Chrome tabs. Source capture remains disabled
until an alternative passes disposable-data tests.

## Findings established from code

1. `withHeadlessProfile` copied Cookies, Preferences, Secure Preferences,
   origin storage, Network, and root Local State. It then launched Chrome with
   that copy and `captureCopiedTab` navigated to the real site. There was no
   network isolation. Cookie filtering happened after browser startup and page
   navigation. This allows authenticated network activity during capture,
   including browser-account activity unrelated to the selected site's bundle.
   Server-side token invalidation is a plausible explanation for the incident,
   not a proven one.
2. AppleScript inventory does not identify the profile owning a tab. Applying
   `profile.last_used` to every tab can select another account. For the controlled
   Morse test, the browser tool identifies profile `Vividh`; Chrome's profile
   metadata maps that name to `Profile 1`.
3. Normal-profile restore writes shared cookies. Checking existing tabs first
   cannot make the check and write atomic with concurrent user navigation.
   Default restores now use a separate managed Chrome profile and isolated
   browser context; normal-profile imports are explicit opt-in only.
4. Saved-profile cleanup signals the saved child PID and finds other processes
   using a command substring. PID reuse and prefix matching need stronger
   ownership checks. This has not been shown to explain the reported logout.
5. A successful bundle restore is not proof of an accepted login or a visible
   browser window. The Daytona browser had been headless. A visible desktop
   restore was subsequently verified, but its example.com page showed
   ERR_CONNECTION_RESET. Authentication needs a separate live assertion.

## Containment

- Copied-profile startup is blocked before cloning or spawning.
- Fallback local-tab inventory entries are not transferable.
- Automatic native-debugging connections remain disabled.
- Additional real-account transfers were paused until the replacement passed tests;
  one controlled Morse test is now in progress.
- The containment checks passed with Chrome integration tests disabled:
  40 passed, 7 skipped. This verifies the guard, not a repaired capture path.

## Required evidence before enabling a replacement

- No source-site or browser-account network requests during capture, enforced
  rather than inferred from Chrome flags.
- No writes to the original profile and no copied account/sync configuration.
- Exact source profile and tab binding; no last-used-profile guess.
- Only the selected site's authentication enters the bundle; values never
  appear in logs or test reports.
- Disposable cookie/storage fixtures round-trip through the actual adapter.
- The private Morse repository is accessible in an isolated Daytona browser.
- The original browser retains its tabs and remains authenticated after the
  test. These observations cannot establish a permanent guarantee against a
  website invalidating a copied session later.

## Status

The source baseline was checked in a **new** tab at the exact private repository
URL. It redirected to GitHub `/login` before any new capture or restore. The
original open tab displayed cached private repository content; that observation
was insufficient to establish valid authentication. No new restore was enqueued.
The fresh sign-in page was left open for the user. The user subsequently signed in. A fresh test tab now shows the private Morse
repository and the signed-in user menu. No new transfer has yet been verified.

Cloud audit found exactly two live transfers, with one capture and one restore
per transfer and no duplicate continuation. The newer snapshot was the exact
Morse URL, captured from `Profile 1`; its historical restore had succeeded.
Daytona's visible browser later contained only the older example.com snapshot.
The earlier window recovery replayed that older snapshot, not Morse. Success
history must not be presented as current session availability.

The offline Chrome helper was abandoned as a capture approach and moved to
unwired experimental files. It is not part of the adapter. Initial OS isolation exposed writes to the normal Crashpad
path and temporary socket paths; these were denied, and Chrome failed to start.
The helper must pass real subprocess canaries before it can be used for capture.

The subprocess enforcement canary passed: a disposable Node process could write
only into its capture directory; attempted writes to a source marker and
connections to both loopback and the local interface were denied. This is not a
passing Chrome capture test. Chrome still failed before its debugging pipe was
available, reporting failures to create its ProcessSingleton socket directory.
A proposed wildcard write exception for Chrome-named directories in the user's
system temporary directory was rejected in review: it could cover another
Chrome instance's temporary files. The prototype must not ship with that
exception or a permissive fallback.

## Recommended implementation direction

Replace browser-profile cloning with a narrowly scoped saved-cookie reader:
explicit profile selection, a read-only consistent SQLite snapshot, selected
domain rows only, and supported OS decryption. Unknown encryption formats or
missing OS permission must return an error, not launch a network-enabled clone.
Treat any origin-storage reader separately and describe exactly which saved
state it can reproduce. Cookies are not live JavaScript memory or a guarantee
that a site will accept a copied session.

Keep incoming state in a separate Chrome profile/context. For interactive
sandboxes, establish and verify the desktop display before the first restore.
Test success must require a fresh authenticated page in that visible browser,
with a fresh source-authentication check before and after; a success receipt
alone is insufficient.

References checked during the investigation:

- [Chromium cookie architecture](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/cookies/README.md)
- [Chrome flags for automation](https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md)
- [Node SQLite read-only access and consistent backup](https://nodejs.org/api/sqlite.html)

Investigation remains open. The old copied-profile capture is still disabled.

## Direct reader validation in progress

A new cookie-only reader avoids starting Chrome or navigating to the source site.
A metadata-only check of the explicitly selected `Profile 1/Cookies` database
found schema version 24 and 15 GitHub rows using the supported `v10` format.
No cookie values or Keychain key were printed.

Independent review required expiry filtering, exclusion of partitioned cookies
for the initial implementation, and a stable temporary database snapshot so
SQLite does not open the live source or interact with its shared-memory file.
The real transfer remains pending those changes and fixture validation.
Keychain permission behavior also remains untested; this implementation must
not claim that repeated permission prompts have been solved.

A further import defect was found: an auto-attach callback could reapply old
snapshot cookies after a site rotated them during navigation. Removed the
callback; cookies are installed once before destination navigation. A real
disposable Chrome fixture with a local server confirms its replacement session
cookie survives import. This was a separate correctness issue, not proof of the
reported source logout's cause.

## Replacement validation

The production adapter test suite passed **56/56**, with real disposable Chrome
tests enabled and no skips. The saved-cookie route now validates the selected
tab before and after capture, includes only its URL metadata and eligible
unpartitioned cookies, and rejects expired cookies and unsupported encryption.
SQLite opens a private temporary copy of the main database and WAL. Synthetic
WAL tests verify committed rows are retained and source files are unchanged.
The legacy copied-profile capture remains blocked.

The controlled Profile 1 test was approved in independent code review. Further
hardening should reject a symlinked WAL and compare nanosecond file identities
across the entire two-pass snapshot, in addition to current byte equality and
per-file metadata checks. Automatic tab-to-profile association is still unsolved
for general AppleScript inventory.

The new controlled capture succeeded through the existing Mac collector without
a Keychain error or a Chrome debugging prompt. Before restoring, all 87 baseline
Chrome tabs retained their IDs and URLs. The fresh source test page still showed
the signed-in menu; a fresh post-restore authentication check is still required.

## Controlled Morse transfer result

One new capture (`2f69919b680e…`) and one new restore (`d0383f759956…`)
succeeded through the cloud. The validated snapshot contained 15 cookies for
GitHub, one exact `https://github.com/Lasdw6/morse` tab, and no storage origins.
The existing Daytona environment received the updated adapter before restore.
The update initially lost the adapter executable bit; restoring mode 755 fixed
the resulting `Permission denied` inventory error before capture began.

Computer-use verification of Daytona's VNC showed the exact Morse URL, signed-in
user navigation, repository Settings, and both `Private` and `Private repository`
labels. The remote page was unstyled, so asset-network diagnosis remains separate.
A fresh navigation of the assistant-created source test tab after restore still
showed the private Morse repository and signed-in menu. All 87 baseline source
tab IDs and URLs remained present and unchanged. No original user tab was
reloaded, navigated, closed, or used as an import target.

This demonstrates one authenticated GitHub transfer with source authentication
still working immediately afterward. It does not prove the historical Google
account logout's exact cause, restore that Google account, establish permanent
server acceptance of copied sessions, or solve general tab-to-profile mapping.

Anonymous network checks inside Daytona found `github.com` responding HTTP 200,
while `github.githubassets.com` resolved but its HTTPS connection failed with
`ConnectionResetError [Errno 104]`. Abra's Daytona create request sets lifecycle
options and private access; it sets no outbound network restriction. The exact
party resetting CDN connections is not established. The page styling issue
remains unresolved and must not be described as a complete usable-browser pass.

Full cloud operation IDs:

- Capture: `2f69919b680eca1bde8a0a5aa08764fae82c6f79f7460d5fb1ece98fd0bf5805`
- Restore: `d0383f75995638847422ab566ef6c5f66e249fcdd857f51b2239525c171796f4`

Second-incident audit found no captures or restores after the controlled test.
The exact Daytona Morse context was closed using its signed receipt and matching
registry ownership. This did not call GitHub's sign-out endpoint or close the
normal Mac browser. The containment suite passed 50 tests with 8 Chrome tests
skipped and no failures. Operational block deployment is being verified.

GitHub's published session model describes server-side session records and
revocation ([GitHub engineering](https://github.blog/news-insights/the-library/modeling-your-app-s-user-session/)).
This supports distinguishing local file safety from session validity, but does
not establish why this account was signed out or prove that cross-device reuse
was the trigger.

Containment deployment verified: source checksums match the Mac and hosted
adapters, and the worker refreshed Daytona successfully. Fresh Daytona inventory
contains only the prior example.com item; Morse is absent and adapter error is
null. The Mac collector stayed running. No authenticated replay, cookie read,
GitHub logout action, normal Mac browser action, or broad browser termination
was performed during this containment.
