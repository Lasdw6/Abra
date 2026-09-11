# Files adapter

`dev.abra.files` exposes `dev.abra.files.v1` through the standard
`abra-adapter/1` NDJSON protocol. Python 3.9 or newer on macOS/Linux is required.
Abra core handles packing, transport, verification, and materialization.

Browse existing folders on a device, select files or folders, and choose the
receiving folder. There is no required shared folder and no need to move source
files first. Inventory reads folder entries and metadata, never file contents.
Selecting all accessible folders enables browsing; it does not start a transfer
or recursively scan the filesystem. The operating system's permissions apply.

## Inventory options

Options are strings in the inventory request's `options` map:

- `mode`: `all` (default) or `selected`.
- `paths`: a JSON array of up to 32 existing folder paths for selected mode.
- `browse_path`: the folder to list. In selected mode it must be inside a
  selected root; omit it to list the chosen roots themselves.
- `offset`: directory page offset, starting at `0`.

All mode starts at the current user's home folder. `ABRA_FILES_ROOT` remains an
optional initial browse location for installations and tests; it does not
restrict source or destination paths. Absolute paths and `~` paths are accepted.
Cloud stores options per device and sends them with each inventory poll. The
report's `context` describes navigation and echoes the requested options so the
UI can distinguish a new report from the previous folder's contents.

The adapter returns at most 256 entries per page and `context.next_offset` for
more. Pagination reflects the live directory stream, so refresh a folder if its
entries change while paging. Symlinks, special files, and incomplete
`.abra-incoming-*` folders are omitted. Missing or inaccessible folders report
errors; browsing does not create them.

## Transfers

Export requires an inventory source selector. It rechecks the selected file and
parent directory identities, then copies the selected contents into staging.
Deleted, replaced, or modified selections fail. Directory contents are read at
transfer time. Transfers are limited to 1 GiB, 10,000 entries, and 64 levels.
Symlinks and special files anywhere in a selected directory are rejected.

Import requires an explicit destination path on the receiving device. Original
file and folder names are placed directly inside it. Existing names, including
symlinks, cause a conflict error; nothing is overwritten. A new destination
folder is created if requested. Copying uses a private temporary directory,
then each top-level entry is published with an atomic no-replace operation.
A late failure may leave already-published entries; the error identifies them.
Interrupted copies may leave a hidden incomplete directory.

The receipt returns `result.destination`, the actual destination folder, and
`result.paths`, the files/folders received, plus file, entry, and byte counts.
Regular contents, empty folders, and ordinary permission bits are preserved.
Ownership, ACLs, extended attributes, timestamps, hard-link identity, and special
permission bits are not preserved. Sources should stop changing for a consistent
copy; this is not a filesystem snapshot.

Run disposable fixture tests:

```sh
python3 -m unittest discover -s adapters/files/tests -v
```
