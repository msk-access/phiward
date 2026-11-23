"""The network of a `phiward launch` session: one CONNECT proxy in the launcher, outside the
profile, with the operator's rights. The tool has no direct outbound IP connection. On macOS the profile
allows only the proxy's port on loopback, which the launcher holds on both 127.0.0.1 and [::1]
for its whole life. On Linux the session has a network namespace of its own, and a relay in the
session's helper listens on the namespace's own 127.0.0.1. The relay holds one end of a socket
pair from the start; for each connection it sends `c` on it, and the proxy answers `y` with one
end of a new socket pair (SCM_RIGHTS), whose other end it serves like an accepted connection, or
`n` without one (the connection is refused). No socket with a path leads to the proxy.

How one CONNECT is decided:
- the session's token (`Proxy-Authorization: Basic`, user `phiward`); without it, 407;
- one request per connection, CONNECT only (anything else: 405); after a 200 the connection is
  a tunnel to the checked address and nothing in it is read as a request;
- the target: brackets and one trailing dot taken off; no name is refused by its text
  (`localhost`, `*.localhost` and this machine's names are refused by their addresses below);
- one lookup (getaddrinfo), and only the addresses it returns are judged, never the text
  (`0177.1`, `2130706433` and `0` are loopback or unspecified once parsed). An embedded IPv4 is
  unwrapped first (mapped, compatible, NAT64, 6to4). Each form must be global and not one of
  this machine's addresses (read again for each connection). The private ranges (PRIVATE) are
  refused unless the user config's `[launch] private_networks` names them; loopback,
  link-local, unspecified and multicast addresses always are. One address that fails refuses
  the name;
- the connection goes to an address that was checked (each in turn, a short timeout each),
  never to the name again. Through an
  upstream proxy (the launcher's HTTPS_PROXY) it is `CONNECT <checked address>:<port>`; a name
  that does not resolve here is refused, never forwarded.

Raw sockets only: never urllib's or http.client's network code (they read the proxy variables
and follow `file://`). Limits: MAX_CONNECTIONS at once (one more is refused, not queued), and
timeouts on the header, the connection and idle tunnels. When a check cannot decide, it refuses.
"""

import base64
import hmac
import ipaddress
import os
import secrets
import selectors
import socket
import sys
import threading
import time
from typing import Callable, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

PRIVATE = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))
_COMPAT = ipaddress.ip_network("::/96")
_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
USER = "phiward"
MAX_CONNECTIONS = 64
MAX_HEADER = 16384
HEADER_TIMEOUT = 15.0
CONNECT_TIMEOUT = 30.0
PER_ADDRESS_TIMEOUT = 10.0  # each checked address in turn (broken IPv6 must not cost 30 s)
IDLE_TIMEOUT = 900.0
PORTS = (49152, 65535)  # the proxy's port, a new random one in this range for each launch
_TRIES = 32

Address = ipaddress._BaseAddress  # type: ignore[attr-defined]
Network = ipaddress._BaseNetwork  # type: ignore[attr-defined]


class ProxyError(Exception):
    pass


class Upstream(NamedTuple):
    host: str
    port: int
    auth: str  # a whole `Proxy-Authorization` value, or ""


# --- the address check -------------------------------------------------------------------------

def _embedded(a: Address) -> Optional[ipaddress.IPv4Address]:
    """The IPv4 address an IPv6 address carries (mapped, compatible, translated, NAT64, 6to4),
    or None."""
    if a.version != 6:
        return None
    if a.ipv4_mapped is not None:
        return a.ipv4_mapped
    if a in _COMPAT or a in _NAT64 or a in _TRANSLATED:
        return ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
    return a.sixtofour


def _within(a: Address, nets: Iterable[Network]) -> bool:
    return any(a.version == n.version and a in n for n in nets)


def address_problem(text: str, own: Set[Address], allow: Sequence[Network] = ()) -> str:
    """Why the proxy refuses this address, or "" when it may connect there. `own` are this
    machine's addresses; `allow` the user config's private networks."""
    try:
        a = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return "not an address"
    if a.version == 6 and a in _NAT64_LOCAL:
        return "a translated address"
    forms = [a]
    e = _embedded(a)
    if e is not None:
        forms.append(e)
    for f in forms:
        if f in own:
            return "this machine's own address"
        if f.is_loopback or f.is_link_local or f.is_unspecified or f.is_multicast:
            return "this machine or its local link"
        if f.is_global:
            continue
        if _within(f, PRIVATE) and _within(f, allow):
            continue
        return "not a public address"
    return ""


def private_network_problem(text: str) -> str:
    """Why a `[launch] private_networks` entry cannot be used, or ""."""
    try:
        n = ipaddress.ip_network(text, strict=True)
    except ValueError:
        return "is not a network with its prefix length (for example 10.20.0.0/16)"
    if not any(n.version == p.version and n.subnet_of(p) for p in PRIVATE):  # type: ignore[arg-type]
        return ("is not inside a private range (" + ", ".join(str(p) for p in PRIVATE) +
                "); this machine, its link and public addresses cannot be listed")
    return ""


# --- this machine -------------------------------------------------------------------------------

def own_addresses() -> Set[Address]:
    """This machine's addresses now, from getifaddrs(3). Raises OSError when they cannot be read
    (the proxy then refuses)."""
    import ctypes

    class _Ifa(ctypes.Structure):
        pass
    _Ifa._fields_ = [("ifa_next", ctypes.POINTER(_Ifa)), ("ifa_name", ctypes.c_char_p),
                     ("ifa_flags", ctypes.c_uint), ("ifa_addr", ctypes.c_void_p),
                     ("ifa_netmask", ctypes.c_void_p), ("ifa_dstaddr", ctypes.c_void_p),
                     ("ifa_data", ctypes.c_void_p)]
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib" if sys.platform == "darwin" else None,
                      use_errno=True)
    head = ctypes.POINTER(_Ifa)()
    if lib.getifaddrs(ctypes.byref(head)) != 0:
        n = ctypes.get_errno()
        raise OSError(n, os.strerror(n))
    out: Set[Address] = set()
    try:
        p = head
        while p:
            sa = p.contents.ifa_addr
            if sa:
                fam = (ctypes.c_uint8.from_address(sa + 1).value if sys.platform == "darwin"
                       else ctypes.c_uint16.from_address(sa).value)
                if fam == socket.AF_INET:
                    out.add(ipaddress.IPv4Address(ctypes.string_at(sa + 4, 4)))
                elif fam == socket.AF_INET6:
                    out.add(ipaddress.IPv6Address(ctypes.string_at(sa + 8, 16)))
            p = p.contents.ifa_next
    finally:
        lib.freeifaddrs(head)
    return out


_own_addresses = own_addresses


def _resolve(host: str, port: int) -> List[str]:
    return [ai[4][0] for ai in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM,
                                                  socket.IPPROTO_TCP)]


def _dial(ip: str, port: int, timeout: float) -> socket.socket:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        s.connect((ip, port))
    except BaseException:
        s.close()
        raise
    return s


# --- the target and the upstream ----------------------------------------------------------------

_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-_")


def _port(text: str) -> int:
    if not text.isdigit() or not 0 < int(text) < 65536 or len(text) > 5:
        raise ValueError("no port")
    return int(text)


def target(authority: str) -> Tuple[str, int]:
    """(host, port) of a CONNECT target: `host:port` or `[v6]:port`. The host comes back
    lowercase, without brackets or one trailing dot."""
    if authority.startswith("["):
        host, sep, rest = authority[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError("no port")
        port = _port(rest[1:])
        ipaddress.IPv6Address(host)  # only an address in brackets
        return host.lower(), port
    host, sep, rest = authority.rpartition(":")
    if not sep:
        raise ValueError("no port")
    port = _port(rest)
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or not set(host) <= _HOST_CHARS:
        raise ValueError("not a host name")
    return host, port


def upstream_from(env) -> Optional[Upstream]:
    """The proxy the launcher's own environment names for HTTPS (https_proxy, HTTPS_PROXY,
    all_proxy, ALL_PROXY, the first that is set), or None. Only `http://host[:port]` can be
    chained; anything else raises ProxyError."""
    from urllib.parse import unquote, urlsplit  # parsing only: no network code
    for k in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        value = (env.get(k) or "").strip()
        if value:
            break
    else:
        return None
    why = f"{k} ({value.split('@')[-1]}) cannot be chained: "
    try:
        u = urlsplit(value)
        port = u.port
    except ValueError:
        raise ProxyError(why + "it is not a URL") from None
    if u.scheme.lower() != "http":
        raise ProxyError(why + "only an http:// proxy can be")
    if not u.hostname or u.path not in ("", "/") or u.query or u.fragment:
        raise ProxyError(why + "give it as http://host:port")
    auth = ""
    if u.username is not None:
        cred = f"{unquote(u.username)}:{unquote(u.password or '')}".encode()
        auth = "Basic " + base64.b64encode(cred).decode("ascii")
    return Upstream(u.hostname, port or 80, auth)


# --- the proxy ----------------------------------------------------------------------------------

def random_port() -> int:
    return PORTS[0] + secrets.randbelow(PORTS[1] - PORTS[0] + 1)


_pair = socket.socketpair  # the socket pairs of the relay (a seam for the tests)


class _Refuse(Exception):
    def __init__(self, code: int, why: str, extra: str = "") -> None:
        super().__init__(why)
        self.code, self.why, self.extra = code, why, extra


_REASONS = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed",
            407: "Proxy Authentication Required", 408: "Request Timeout",
            431: "Request Header Fields Too Large", 502: "Bad Gateway",
            503: "Service Unavailable"}


def _read_head(s: socket.socket, deadline: float) -> Tuple[bytes, bytes]:
    """The request or response head (up to its blank line) and the bytes read after it."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        left = deadline - time.monotonic()
        if left <= 0:
            raise _Refuse(408, "no request in time")
        s.settimeout(left)
        try:
            d = s.recv(4096)
        except socket.timeout:
            raise _Refuse(408, "no request in time") from None
        if not d:
            raise _Refuse(400, "the connection closed")
        buf += d
        if len(buf) > MAX_HEADER and b"\r\n\r\n" not in buf[:MAX_HEADER + 4]:
            raise _Refuse(431, "the request head is too long")
    head, _, rest = buf.partition(b"\r\n\r\n")
    if len(head) > MAX_HEADER:
        raise _Refuse(431, "the request head is too long")
    return head, rest


class Proxy:
    def __init__(self, token: str, allow: Sequence[Network] = (),
                 upstream: Optional[Upstream] = None,
                 resolver: Optional[Callable[[str, int], List[str]]] = None,
                 own_addresses: Optional[Callable[[], Set[Address]]] = None,
                 dial: Optional[Callable[[str, int, float], socket.socket]] = None,
                 limit: int = MAX_CONNECTIONS, header_timeout: float = HEADER_TIMEOUT,
                 connect_timeout: float = CONNECT_TIMEOUT,
                 idle_timeout: float = IDLE_TIMEOUT) -> None:
        self.token = token
        self.allow = list(allow)
        self.upstream = upstream
        self.resolver = resolver or _resolve
        self.own_addresses = own_addresses or _own_addresses
        self.dial = dial or _dial
        self.header_timeout, self.connect_timeout = header_timeout, connect_timeout
        self.idle_timeout = idle_timeout
        self.listeners: List[socket.socket] = []
        self.port = 0
        self.session_end: Optional[socket.socket] = None  # Linux: the relay's end of the pair
        self._control: Optional[socket.socket] = None
        self._slots = threading.BoundedSemaphore(limit)
        self._closed = threading.Event()
        self._want = f"{USER}:{token}".encode()

    # listening

    def listen_loopback(self, ports: Optional[Sequence[int]] = None) -> int:
        """Bind one port on both 127.0.0.1 and [::1] (IPV6_V6ONLY, no SO_REUSEADDR, no
        SO_REUSEPORT): a port where either address is taken is never used. Random ports from
        PORTS unless `ports` is given."""
        tries = list(ports) if ports is not None else [random_port() for _ in range(_TRIES)]
        last = ""
        for port in tries:
            pair: List[socket.socket] = []
            try:
                s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                pair.append(s4)
                s4.bind(("127.0.0.1", port))
                s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                pair.append(s6)
                s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s6.bind(("::1", port))
                for s in pair:
                    s.listen(128)
            except OSError as exc:
                last = exc.strerror or str(exc)
                for s in pair:
                    s.close()
                continue
            self.listeners += pair
            self.port = port
            return port
        raise ProxyError(f"the proxy cannot hold a port on both 127.0.0.1 and [::1] ({last})")

    def listen_pair(self) -> socket.socket:
        """The socket pair the session's relay asks for connections on: its end is returned
        (inheritable, for the helper) and kept in `session_end` until `close`."""
        try:
            mine, theirs = _pair()
        except OSError as exc:
            raise ProxyError(f"the proxy cannot make its socket pair ({exc.strerror or exc})")
        theirs.set_inheritable(True)
        self._control, self.session_end = mine, theirs
        return theirs

    def take_session_end(self) -> int:
        """The relay's end as a descriptor of its own (inheritable), no longer the proxy's to
        close: the launcher passes it to the session and closes it."""
        if self.session_end is None:
            raise ProxyError("the proxy has no socket pair")
        fd = self.session_end.detach()
        self.session_end = None
        return fd

    def serve(self) -> None:
        for ls in self.listeners:
            threading.Thread(target=self._accept_loop, args=(ls,), daemon=True).start()
        if self._control is not None:
            threading.Thread(target=self._pair_loop, args=(self._control,), daemon=True).start()

    def close(self) -> None:
        self._closed.set()
        for ls in self.listeners + [self._control, self.session_end]:
            if ls is None:
                continue
            try:
                ls.close()
            except OSError:
                pass

    def url(self, port: int = 0) -> str:
        return f"http://{USER}:{self.token}@127.0.0.1:{port or self.port}"

    # serving

    def _accept_loop(self, ls: socket.socket) -> None:
        try:
            while not self._closed.is_set():
                try:
                    c, _ = ls.accept()
                except OSError:
                    if self._closed.is_set():
                        return
                    time.sleep(0.05)
                    continue
                if not self._slots.acquire(blocking=False):
                    self._refuse(c, _Refuse(503, "too many connections at once"))
                    continue
                try:
                    self._start_worker(c)
                except BaseException:
                    self._slots.release()
                    c.close()
                    raise
        except BaseException:
            pass
        # the worker is gone: the listener stays held (no other process can take the port) and
        # every connection is closed unanswered
        while not self._closed.is_set():
            try:
                c, _ = ls.accept()
                c.close()
            except OSError:
                if self._closed.is_set():
                    return
                time.sleep(0.05)

    def _pair_loop(self, ctl: socket.socket) -> None:
        """One request (`c`) on the relay's pair: `y` with one end of a new pair, the other end
        served as an accepted connection; `n` without one when no pair can be made, or once the
        worker is gone (a refusal, as on loopback). It ends when the relay's end closes."""
        broken = False
        while not self._closed.is_set():
            try:
                if not ctl.recv(1):
                    return
            except OSError:
                return
            c = theirs = None
            try:
                if broken:
                    raise OSError("the worker is gone")
                c, theirs = _pair()
            except OSError:
                try:
                    ctl.sendall(b"n")
                    continue
                except OSError:
                    return
            try:
                socket.send_fds(ctl, [b"y"], [theirs.fileno()])
            except OSError:
                c.close()
                return
            finally:
                theirs.close()
            if not self._slots.acquire(blocking=False):
                self._refuse(c, _Refuse(503, "too many connections at once"))
                continue
            try:
                self._start_worker(c)
            except BaseException:
                self._slots.release()
                c.close()
                broken = True

    def _start_worker(self, c: socket.socket) -> None:
        threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    @staticmethod
    def _refuse(c: socket.socket, r: _Refuse) -> None:
        body = f"phiward launch: {r.why}\n".encode()
        try:
            c.settimeout(2)
            c.sendall(f"HTTP/1.1 {r.code} {_REASONS.get(r.code, 'Refused')}\r\n{r.extra}"
                      f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                      "Connection: close\r\n\r\n".encode() + body)
        except OSError:
            pass
        finally:
            c.close()

    def _handle(self, c: socket.socket) -> None:
        remote = None
        try:
            try:
                remote, rest, early = self._decide(c)
            except _Refuse as r:
                self._refuse(c, r)
                return
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + early)
            if rest:
                remote.sendall(rest)
            self._splice(c, remote)
        except Exception:  # noqa: BLE001 - one connection's failure ends that connection only
            pass
        finally:
            for s in (c, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self._slots.release()

    def _decide(self, c: socket.socket) -> Tuple[socket.socket, bytes, bytes]:
        """The checked connection for one request: (the remote, the client's bytes after the
        head, the upstream's bytes after its answer). Raises _Refuse."""
        head, rest = _read_head(c, time.monotonic() + self.header_timeout)
        try:
            lines = head.decode("latin-1").split("\r\n")
        except ValueError:
            raise _Refuse(400, "a request phiward cannot read") from None
        auth = ""
        for ln in lines[1:]:
            k, sep, v = ln.partition(":")
            if sep and k.strip().lower() == "proxy-authorization":
                auth = v.strip()
        if not self._token_ok(auth):
            raise _Refuse(407, "this proxy is only for its own session",
                          'Proxy-Authenticate: Basic realm="phiward"\r\n')
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise _Refuse(400, "a request phiward cannot read")
        if parts[0] != "CONNECT":
            raise _Refuse(405, "only CONNECT (HTTPS) goes through phiward's proxy")
        try:
            host, port = target(parts[1])
        except ValueError:
            raise _Refuse(400, "not a host:port target") from None
        try:
            addrs = list(dict.fromkeys(self.resolver(host, port)))
        except Exception:  # noqa: BLE001 - any lookup failure refuses
            raise _Refuse(403, f"{host} does not resolve here") from None
        if not addrs:
            raise _Refuse(403, f"{host} does not resolve here")
        try:
            own = self.own_addresses()
        except Exception:  # noqa: BLE001 - cannot tell: refuse
            raise _Refuse(403, "this machine's addresses cannot be read") from None
        for a in addrs:
            why = address_problem(a, own, self.allow)
            if why:
                raise _Refuse(403, f"{host} is {why}")
        # every address was checked above; each is tried in turn, with a short timeout
        each = min(self.connect_timeout, PER_ADDRESS_TIMEOUT)
        for ip in addrs:
            try:
                # an address of the user's private networks is dialled directly: an upstream
                # (a corporate HTTPS_PROXY) does not reach the internal network
                if self.upstream is None or self._allowed_private(ip):
                    return self.dial(ip, port, each), rest, b""
                remote, early = self._via_upstream(ip, port, each)
                return remote, rest, early
            except Exception:  # noqa: BLE001 - this address failed: the next one
                continue
        raise _Refuse(502, f"{host} cannot be reached")

    def _allowed_private(self, ip: str) -> bool:
        """Whether a checked address is one of `[launch] private_networks`, not a public one."""
        a = ipaddress.ip_address(ip.split("%", 1)[0])
        return not a.is_global and _within(a, self.allow)

    def _token_ok(self, auth: str) -> bool:
        scheme, _, value = auth.partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            got = base64.b64decode(value.strip(), validate=True)
        except ValueError:
            return False
        return hmac.compare_digest(got, self._want)

    def _via_upstream(self, ip: str, port: int, timeout: float) -> Tuple[socket.socket, bytes]:
        up = self.upstream
        assert up is not None
        s = socket.create_connection((up.host, up.port), timeout=timeout)
        try:
            where = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            req = f"CONNECT {where} HTTP/1.1\r\nHost: {where}\r\n"
            if up.auth:
                req += f"Proxy-Authorization: {up.auth}\r\n"
            s.sendall(req.encode("ascii") + b"\r\n")
            try:
                head, early = _read_head(s, time.monotonic() + timeout)
            except _Refuse:
                raise _Refuse(502, "the upstream proxy did not answer") from None
            status = head.split(b"\r\n", 1)[0].split()
            if len(status) < 2 or status[1] != b"200":
                raise _Refuse(502, "the upstream proxy refused the connection")
            return s, early
        except BaseException:
            s.close()
            raise

    def _splice(self, a: socket.socket, b: socket.socket) -> None:
        """Copy both ways until both sides are done or the tunnel is idle too long."""
        sel = selectors.DefaultSelector()
        try:
            for s in (a, b):
                s.settimeout(self.idle_timeout)
            other = {a: b, b: a}
            open_ = {a, b}
            for s in open_:
                sel.register(s, selectors.EVENT_READ)
            while open_:
                ready = sel.select(self.idle_timeout)
                if not ready:
                    return
                for key, _ in ready:
                    s = key.fileobj
                    data = s.recv(65536)  # type: ignore[union-attr]
                    if data:
                        other[s].sendall(data)  # type: ignore[index]
                        continue
                    sel.unregister(s)
                    open_.discard(s)  # type: ignore[arg-type]
                    try:
                        other[s].shutdown(socket.SHUT_WR)  # type: ignore[index]
                    except OSError:
                        return
        finally:
            sel.close()


def start(env, allow: Sequence[str] = (), pair: bool = False) -> Proxy:
    """The proxy for one launch, serving: on a socket pair for the session's relay (`pair`,
    Linux; its end is `session_end`), otherwise on a random loopback port held on both addresses
    (macOS). Raises ProxyError."""
    nets = [ipaddress.ip_network(n) for n in allow]
    p = Proxy(secrets.token_hex(16), nets, upstream_from(env))
    try:
        if pair:
            p.listen_pair()
        else:
            p.listen_loopback()
    except BaseException:
        p.close()
        raise
    p.serve()
    return p

