"""The receiving side of a pull: a tar stream on stdin, unpacked under argv[1].

Run by path, in the gateway profile: `<python> -I <PKG>/phiward/tar_extract.py DEST` (`-I` keeps
this file's folder off `sys.path`). It is not imported. Standard library only. What exists is
kept; links, special files, `..` and `.claude` are skipped; nothing is followed through a link.
A file or folder it cannot make (no permission, no space) fails the pull (exit 1); the rest is
still written.
"""
import os
import stat
import sys
import tarfile
dest = os.path.realpath(sys.argv[1])
os.makedirs(dest, mode=0o755, exist_ok=True)
NF = os.O_NOFOLLOW | os.O_CLOEXEC
def folder(parts):
    """The folder's descriptor, made where it is missing. FileExistsError: a step exists and is
    not a folder (a file, a link), so it is kept; any other OSError: it cannot be made."""
    fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | NF)
    try:
        for p in parts:
            try:
                os.mkdir(p, 0o755, dir_fd=fd)
            except FileExistsError:
                if not stat.S_ISDIR(os.stat(p, dir_fd=fd, follow_symlinks=False).st_mode):
                    raise
            nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise
kept = skipped = failed = 0
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
    for m in t:
        parts = [p for p in m.name.split("/") if p not in ("", ".")]
        if not parts or ".." in parts or any(p.casefold() == ".claude" for p in parts):
            skipped += 1
            continue
        if not m.isdir() and not m.isreg():
            skipped += 1
            continue
        try:
            fd = folder(parts if m.isdir() else parts[:-1])
        except FileExistsError:
            kept += 1
            continue
        except OSError:
            failed += 1
            continue
        if m.isdir():
            os.close(fd)
            continue
        try:
            try:
                out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o644,
                              dir_fd=fd)
            except FileExistsError:
                kept += 1
                continue
            except OSError:
                failed += 1
                continue
            src = t.extractfile(m)
            with os.fdopen(out, "wb") as fh:
                while True:
                    b = src.read(1 << 20)
                    if not b:
                        break
                    fh.write(b)
        finally:
            os.close(fd)
sys.stdout.write(f"kept {kept} existing, skipped {skipped}, failed {failed}\n")
sys.exit(1 if failed else 0)
