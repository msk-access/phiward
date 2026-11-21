"""The sandbox check's made-up servers, outside the session: check.sh starts it before the first
session, and cleanup.sh stops it (it also ends when check.sh is gone). It serves made-up data
only (FAKE-PT-0001):
- HTTP on 127.0.0.1 and, where it can, [::1], one port for both: any request gets status 222
  and the made-up body;
- a unix socket bound under a temporary name and then renamed, as ssh's ControlMaster does
  (SOCKDIR/cm.sock), that sends the made-up body to whoever connects;
- for each mode, one more (SOCKDIR/late-MODE.sock), bound only once the session wrote its ready
  file (PROJECT/unix-ready-MODE): a socket made after the session started.
What it did goes to STATE, one fact per line: `port N`, `v6 yes|no`, `renamed PATH`, then
`ready`; later `late-MODE PATH` (or `late-MODE error`). It ends once its parent is no longer
PARENT (check.sh's PID, given, since check.sh may be gone before this starts).
Usage: python3 netsrv.py STATE SOCKDIR PROJECT PARENT"""
import errno
import os
import socket
import sys
import threading
import time

BODY = b"FAKE-PT-0001\n"
HTTP = (b"HTTP/1.0 222 Made-Up\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s"
        % (len(BODY), BODY))
MODES = ("A", "B")


def serve(srv, reply, read):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.settimeout(2)
            if read:
                try:
                    conn.recv(4096)
                except OSError:
                    pass
            conn.sendall(reply)
        except OSError:
            pass
        finally:
            conn.close()


def start(srv, reply, read=False):
    srv.listen(16)
    threading.Thread(target=serve, args=(srv, reply, read), daemon=True).start()


def tcp():
    """(the 127.0.0.1 socket, the [::1] one or None, their port)."""
    for _ in range(50):
        v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        v4.bind(("127.0.0.1", 0))
        port = v4.getsockname()[1]
        try:
            v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            return v4, None, port
        try:
            v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            v6.bind(("::1", port))
            return v4, v6, port
        except OSError as e:
            v6.close()
            if e.errno != errno.EADDRINUSE:
                return v4, None, port
            v4.close()
    sys.exit("netsrv: no port for 127.0.0.1 and [::1]")


def unix(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    return s


def main(state, sockdir, project, parent):
    parent = int(parent)

    def note(line):
        with open(state, "a") as fh:
            fh.write(line + "\n")

    v4, v6, port = tcp()
    start(v4, HTTP, read=True)
    if v6 is not None:
        start(v6, HTTP, read=True)
    note(f"port {port}")
    note("v6 " + ("yes" if v6 is not None else "no"))
    renamed = os.path.join(sockdir, "cm.sock")
    tmp = f"{renamed}.{os.urandom(8).hex()}"  # as ssh: bound under a temporary name, renamed
    s = unix(tmp)
    os.rename(tmp, renamed)
    start(s, BODY)
    note(f"renamed {renamed}")
    note("ready")
    late = {}
    while os.getppid() == parent:  # check.sh is gone (a kill -9): end with it
        for m in MODES:
            if m not in late and os.path.lexists(os.path.join(project, f"unix-ready-{m}")):
                path = os.path.join(sockdir, f"late-{m}.sock")
                try:
                    late[m] = unix(path)
                    start(late[m], BODY)
                    note(f"late-{m} {path}")
                except OSError:
                    late[m] = None
                    note(f"late-{m} error")
        time.sleep(0.1)


if __name__ == "__main__":
    main(*sys.argv[1:5])
