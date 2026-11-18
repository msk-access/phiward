"""Reading a file that the agent may have placed or replaced.

The hook and the broker run outside every sandbox, so a file they read must not be a way in:
`read_text` opens it once, without blocking (a FIFO or a device never stalls the reader), as a
regular file of bounded size, and, unless `follow` is set, without following a link in its last
part. The caller checks where it may be.
"""

import os
import stat

LIMIT = 16 * 1024 * 1024


class UnsafeFile(OSError):
    pass


def read_text(path: str, limit: int = LIMIT, follow: bool = False) -> str:
    flags = os.O_RDONLY | os.O_NONBLOCK | (0 if follow else os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if not follow and os.path.islink(path):
            raise UnsafeFile("it is a link") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeFile("it is not a regular file")
        if st.st_size > limit:
            raise UnsafeFile("it is too large")
        chunks = []
        size = 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            size += len(b)
            if size > limit:
                raise UnsafeFile("it is too large")
            chunks.append(b)
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8")


def write_new(path: str, text: str, mode: int = 0o600) -> None:
    """Write `text` to `path` in place of what is there: through a fresh name that is never
    followed as a link, and only when the file moved into place is the one written. On any
    failure the fresh name is removed (a caller does not know it). For the operator's own
    folders: a folder the agent can write needs dir_fd-based writes (broker.Spool)."""
    import secrets
    # a hidden name beside the file: a walk that skips dot names never takes it for a file
    folder, name = os.path.split(path)
    tmp = os.path.join(folder, f".{name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            mine = os.fstat(fh.fileno())
            now = os.lstat(tmp)
            if (now.st_dev, now.st_ino) != (mine.st_dev, mine.st_ino):
                raise OSError("the new file was replaced before it was moved into place")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def remove_tree(path: str) -> bool:
    """Remove `path` (a folder of any depth, or a file), never through a link: carryover's remover,
    which goes down by descriptor without recursion (shutil.rmtree recurses before Python 3.12,
    and its ignore_errors does not catch RecursionError). False when something stayed."""
    from phiward import carryover
    try:
        carryover._remove(path)
    except (OSError, RecursionError, carryover.CarryoverError):
        return False
    return True
