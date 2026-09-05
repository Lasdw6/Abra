"""Safe tree extraction, also run once in a sandbox when restoring a workspace."""

import os
import posixpath
import shutil
import tarfile
import tempfile


def _name(value):
    name = posixpath.normpath(value)
    if name == ".." or name.startswith("../") or posixpath.isabs(name):
        raise ValueError("archive path escapes the tree: %s" % value)
    return name


def unpack_tree(archive, local_dir):
    """Extract into an empty directory without following archive-supplied links."""
    if os.path.islink(local_dir):
        raise ValueError("extraction destination is a symlink")
    local_dir = os.path.realpath(local_dir)
    os.makedirs(local_dir, mode=0o700, exist_ok=True)
    if os.listdir(local_dir):
        raise ValueError("extraction destination must be empty")
    with tarfile.open(archive) as tar:
        entries = {}
        for member in tar.getmembers():
            name = _name(member.name)
            if name == "." and member.isdir():
                continue
            if name == "." or name in entries:
                raise ValueError("invalid or duplicate archive entry: %s" % member.name)
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise ValueError("unsupported archive entry: %s" % member.name)
            entries[name] = member

        # No entry may be written beneath a link. Hardlinks are copied from a
        # regular archive member; symlinks are created only after all writes.
        for name, member in entries.items():
            parent = posixpath.dirname(name)
            while parent:
                if parent in entries and not entries[parent].isdir():
                    raise ValueError("archive entry has a non-directory parent: %s" % name)
                parent = posixpath.dirname(parent)
            if member.islnk():
                target = entries.get(_name(member.linkname))
                if target is None or not target.isfile():
                    raise ValueError("archive hardlink must target a regular member: %s" % name)
            if member.issym():
                if posixpath.isabs(member.linkname):
                    raise ValueError("archive symlink has an absolute target: %s" % name)
                # Check each component before normalization so a/../b cannot
                # hide a traversal through another link at a.
                target = posixpath.dirname(name)
                for component in member.linkname.split("/"):
                    target = _name(posixpath.join(target, component))
                    if target in entries and entries[target].issym():
                        raise ValueError("archive symlink traverses another link: %s" % name)

        for name, member in entries.items():
            destination = os.path.join(local_dir, name)
            if member.isdir():
                os.makedirs(destination, mode=0o700, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(destination), mode=0o700, exist_ok=True)
            if member.issym():
                continue
            source = entries[_name(member.linkname)] if member.islnk() else member
            with tar.extractfile(source) as incoming, open(destination, "xb") as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            os.chmod(destination, source.mode & 0o777)
        for name, member in entries.items():
            if member.issym():
                os.symlink(member.linkname, os.path.join(local_dir, name))


def restore_tree(archive, workspace, replace=False):
    """Validate before replacing contents; keep the workspace mount point intact."""
    workspace = os.path.abspath(workspace)
    # Resolve platform aliases (e.g. macOS /tmp) but reject a symlink workspace.
    if workspace == os.path.abspath(os.sep) or os.path.islink(workspace):
        raise ValueError("restore destination must be a non-root directory, not a symlink")
    workspace = os.path.realpath(workspace)
    if workspace == os.path.abspath(os.sep):
        raise ValueError("cannot restore over the filesystem root")
    os.makedirs(workspace, mode=0o700, exist_ok=True)
    if os.listdir(workspace) and not replace:
        raise ValueError("workspace is not empty; use --replace-workspace to replace its contents")
    with tempfile.TemporaryDirectory(dir=workspace, prefix=".abra-restore-") as staging:
        tree = os.path.join(staging, "tree")
        unpack_tree(archive, tree)
        for name in os.listdir(workspace):
            destination = os.path.join(workspace, name)
            if destination == staging:
                continue
            if not replace:
                raise ValueError("workspace changed during restore; refusing to overwrite it")
            if os.path.isdir(destination) and not os.path.islink(destination):
                shutil.rmtree(destination)
            else:
                os.unlink(destination)
        for name in os.listdir(tree):
            os.replace(os.path.join(tree, name), os.path.join(workspace, name))


if __name__ == "__main__":
    import sys

    restore_tree(sys.argv[1], sys.argv[2], replace=sys.argv[3] == "replace")
