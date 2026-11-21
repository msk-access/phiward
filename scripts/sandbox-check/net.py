"""The sandbox check's network probes: probes.sh runs it inside the session, and check.sh outside
it (to see that the made-up servers answer). It prints one line of fixed words and digits, never
a byte it received, so nothing a server sends reaches the shell:
  tcp HOST PORT   connect straight (no proxy), send a GET, read the status line:
                  `RESPONSE NNN`, `RESPONSE other` (it connected, no HTTP status), or
                  `REFUSED CLASS`; a name is tried at each address it has
  unix PATH       connect to a unix socket: `CONNECTED` or `REFUSED CLASS`
  https URL       a GET through the proxy the environment names, as Bash's tools do:
                  `STATUS NNN` (any HTTP status: the network works), or `FAILED CLASS`
                  (`tunnel`: the proxy refused the CONNECT). The certificate is not checked:
                  only whether a status comes back counts, and the request carries nothing.
CLASS: refused, not-permitted, permission, no-such, unreachable, timeout, no-name, tls, other.
Usage: python3 -I -S net.py tcp HOST PORT | unix PATH | https URL"""
import errno
import socket
import ssl
import sys
import urllib.error
import urllib.request

ERRNO = {errno.ECONNREFUSED: "refused", errno.EPERM: "not-permitted", errno.EACCES: "permission",
         errno.ENOENT: "no-such", errno.ENOTDIR: "no-such", errno.ENETUNREACH: "unreachable",
         errno.EHOSTUNREACH: "unreachable", errno.EADDRNOTAVAIL: "unreachable",
         errno.EAFNOSUPPORT: "unreachable", errno.ETIMEDOUT: "timeout"}


def cls(e):
    # a lookup error's number is not an errno: first
    if isinstance(e, socket.gaierror):
        return "no-name"
    if isinstance(e, socket.timeout):
        return "timeout"
    if isinstance(e, ssl.SSLError):
        return "tls"
    return ERRNO.get(getattr(e, "errno", None), "other")


def tcp(host, port):
    try:
        addrs = socket.getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
    except OSError as e:
        return "REFUSED " + cls(e)
    last = None
    for family, kind, proto, _, addr in addrs:
        try:
            s = socket.socket(family, kind, proto)
        except OSError as e:
            last = e
            continue
        try:
            s.settimeout(5)
            s.connect(addr)
        except OSError as e:
            s.close()
            last = e
            continue
        head = b""
        try:
            s.sendall(b"GET / HTTP/1.0\r\nHost: sbx\r\n\r\n")
            while len(head) < 12:
                got = s.recv(12 - len(head))
                if not got:
                    break
                head += got
        except OSError:
            pass
        finally:
            s.close()
        # it connected: something on that port answered, whatever it sent
        if head[:5] == b"HTTP/" and head[9:12].isdigit():
            return "RESPONSE " + head[9:12].decode()
        return "RESPONSE other"
    return "REFUSED " + (cls(last) if last is not None else "other")


def unix(path):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as e:
        return "REFUSED " + cls(e)
    try:
        s.settimeout(5)
        s.connect(path)
    except OSError as e:
        return "REFUSED " + cls(e)
    finally:
        s.close()
    return "CONNECTED"


def https(url):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # the proxy from the environment (HTTPS_PROXY), as urllib reads it by default
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "phiward-sandbox-check"})
    try:
        with opener.open(req, timeout=20) as r:
            return "STATUS %03d" % r.status
    except urllib.error.HTTPError as e:
        return "STATUS %03d" % e.code
    except urllib.error.URLError as e:
        reason = e.reason
        if str(reason).startswith("Tunnel connection failed"):
            return "FAILED tunnel"
        return "FAILED " + (cls(reason) if isinstance(reason, OSError) else "other")
    except OSError as e:
        if str(e).startswith("Tunnel connection failed"):
            return "FAILED tunnel"
        return "FAILED " + cls(e)


def main(argv):
    kind = argv[1] if len(argv) > 1 else ""
    if kind == "tcp" and len(argv) == 4:
        out = tcp(argv[2], argv[3])
    elif kind == "unix" and len(argv) == 3:
        out = unix(argv[2])
    elif kind == "https" and len(argv) == 3:
        out = https(argv[2])
    else:
        return 2
    print(out)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception:  # never a traceback: it could show what was read
        print("FAILED other" if sys.argv[1:2] == ["https"] else "REFUSED other")
        sys.exit(0)
