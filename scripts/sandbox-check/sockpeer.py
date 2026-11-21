"""Made-up unix-socket servers outside the session, for the sandbox check (Linux, Mode B): each
answers PEER to a connection. In folder DIR: `renamed` (bound as a temp name, linked to its
name, the temp name removed, as OpenSSH's ControlMaster does), `rebound` (bound, then after
DELAY seconds removed and bound again) and `late` (bound after DELAY seconds, once the session
has started). Runs until it is ended. Usage: python3 sockpeer.py DIR DELAY"""
import os
import socket
import sys
import threading
import time

folder, delay = sys.argv[1], float(sys.argv[2])


def serve(path):
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    s.listen(8)

    def loop():
        try:
            while True:
                c, _ = s.accept()
                c.sendall(b"PEER")
                c.close()
        except OSError:
            pass
    threading.Thread(target=loop, daemon=True).start()
    return s


def at(name):
    return os.path.join(folder, name)


serve(at("renamed.Xtmp"))
os.link(at("renamed.Xtmp"), at("renamed"))
os.unlink(at("renamed.Xtmp"))
first = serve(at("rebound"))
time.sleep(delay)
first.close()
os.unlink(at("rebound"))
serve(at("rebound"))
serve(at("late"))
while True:
    time.sleep(60)
