"""The receiving side of a pull: a tar stream on stdin, unpacked under argv[1].

Run by path, in the gateway profile: `<python> -I <PKG>/phiward/tar_extract.py DEST` (`-I` keeps
this file's folder off `sys.path`). It is not imported. Standard library only. What exists is
kept; links, special files, `..` and `.claude` are skipped; nothing is followed through a link.
"""
import os
import sys
import tarfile
dest = os.path.realpath(sys.argv[1])
os.makedirs(dest, mode=0o755, exist_ok=True)
NF = os.O_NOFOLLOW | os.O_CLOEXEC
def folder(parts):
    fd = os.open(dest, os.O_RDONLY | os.O_DIRECTORY | NF)
    try:
        for p in parts:
            try:
                os.mkdir(p, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | NF, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except OSError:
        os.close(fd)
        return None
kept = skipped = 0
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
    for m in t:
        parts = [p for p in m.name.split("/") if p not in ("", ".")]
        if not parts or ".." in parts or any(p.casefold() == ".claude" for p in parts):
            skipped += 1
            continue
        if m.isdir():
            fd = folder(parts)
            if fd is None:
                kept += 1
            else:
                os.close(fd)
            continue
        if not m.isreg():
            skipped += 1
            continue
        fd = folder(parts[:-1])
        if fd is None:
            kept += 1
            continue
        try:
            try:
                out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | NF, 0o644,
                              dir_fd=fd)
            except OSError:
                kept += 1
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
sys.stdout.write(f"kept {kept} existing, skipped {skipped}\n")
