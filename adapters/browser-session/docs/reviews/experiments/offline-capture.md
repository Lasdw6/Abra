# Offline saved-profile capture experiment

This prototype is deliberately not wired into the browser adapter.

The Seatbelt policy denies every network operation for Chrome and its child
processes. It permits writes only inside one canonical disposable directory,
plus `/dev/null`. CDP uses inherited file descriptors via
`--remote-debugging-pipe`, so it does not require a listening socket.

The Node enforcement canary passes on macOS: writes to a synthetic source are
denied, writes to the disposable directory succeed, and both loopback and LAN
connections are denied.

Google Chrome does not currently start under the strict policy. Before opening
CDP, Chrome tries to create
`$DARWIN_USER_TEMP_DIR/com.google.Chrome.<random>/SingletonSocket`, outside the
disposable directory, and exits with `Failed to create socket directory` and
`Failed to create a ProcessSingleton for your profile directory`. Allowing a
wildcard for those directories would permit writes outside the private copy,
including names shared with unrelated Chrome processes, so the production
guard must stay disabled rather than weaken the policy.

Crashpad also attempts to open the normal user's Chrome Crashpad settings and
is denied. The supplied crash-reporting flags do not prevent that early access.
No real profile, cookies, Keychain item, or browser session was accessed while
testing this prototype.

A later extraction design should copy only a consistent cookie database and
explicit origin storage into the disposable directory. It should not copy
Preferences, Secure Preferences, the complete Local State, or the whole
Network directory. Chrome cookie decryption may require an explicit macOS
Keychain authorization and must fail closed when the encryption version is not
supported. Even a correct local snapshot cannot guarantee that a server will
accept the restored session: services can invalidate cookies because of expiry,
IP or device binding, risk checks, or server-side logout.
