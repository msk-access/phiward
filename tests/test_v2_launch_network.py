"""The network of a `phiward launch` session: the tool has no direct IP network, only a CONNECT
proxy that the launcher runs outside the profile, and that proxy allows only public addresses.

- macOS: the profile denies every IP connection except the proxy's random port on loopback; the
  launcher binds that port on both 127.0.0.1 and [::1] before the tool starts.
- Linux: the session has a network namespace of its own; a relay in the session's helper listens
  on the namespace's own 127.0.0.1 and gets each connection to the proxy as one end of a new
  socket pair, passed over a socket pair it holds from the start. No socket with a path leads to
  the proxy.
- The proxy: a per-session token, one lookup, only the addresses it returns are judged (embedded
  IPv4 unwrapped first), this host's addresses read again for each connection, private ranges only
  from the user's config, an upstream proxy only by checked address, limits and timeouts.

Made-up servers only (they answer FAKE-PT-0001); every server a test starts is stopped."""

import base64
import errno
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from helpers import landlock_abi, needs_confine, tool_py

SRC = str(Path(__file__).resolve().parents[1] / "src")
PY = sys.executable
macos = pytest.mark.skipif(sys.platform != "darwin", reason="macOS")
linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux")
ID = "0123456789abcdef"
TOKEN = "f" * 32


def _np():
    from phiward import netproxy
    return netproxy


# --- made-up servers ---------------------------------------------------------------------------

class FakeServer:
    """A made-up server on this machine's loopback (127.0.0.1, and [::1] on the same port where it
    can): it answers FAKE-PT-0001 and records what it was sent."""

    def __init__(self, answer=b"FAKE-PT-0001\n", v6=True):
        self.answer, self.got, self.socks, self.stop = answer, [], [], threading.Event()
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.bind(("127.0.0.1", 0))
        self.port = s4.getsockname()[1]
        self.socks.append(s4)
        if v6 and socket.has_ipv6:
            try:
                s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s6.bind(("::1", self.port))
                self.socks.append(s6)
            except OSError:
                s6.close()
        for s in self.socks:
            s.listen(16)
            s.settimeout(0.2)
            threading.Thread(target=self._serve, args=(s,), daemon=True).start()

    def _serve(self, s):
        while not self.stop.is_set():
            try:
                c, _ = s.accept()
            except OSError:
                continue
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            c.settimeout(2)
            c.sendall(self.answer)
            try:
                data = c.recv(4096)
                if data:
                    self.got.append(data)
            except OSError:
                pass
        finally:
            c.close()

    def close(self):
        self.stop.set()
        for s in self.socks:
            s.close()


@pytest.fixture
def server():
    s = FakeServer()
    yield s
    s.close()


class FakeUpstream:
    """A made-up upstream proxy on loopback: records each request head, answers 200 and then
    FAKE-PT-0001 as the tunnel's first bytes."""

    def __init__(self):
        self.heads, self.stop = [], threading.Event()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            try:
                c.settimeout(2)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                self.heads.append(buf)
                c.sendall(b"HTTP/1.1 200 OK\r\n\r\nFAKE-PT-0001\n")
            except OSError:
                pass
            finally:
                c.close()

    def close(self):
        self.stop.set()
        self.sock.close()


class Dial:
    """The proxy's outbound connection, made up: records (address, port) and hands back one end of
    a socket pair whose other end answers FAKE-PT-0001 and records what it gets."""

    def __init__(self):
        self.calls, self.got, self.ends = [], [], []

    def __call__(self, ip, port, timeout):
        self.calls.append((ip, port))
        a, b = socket.socketpair()
        self.ends += [a, b]

        def far():
            try:
                b.sendall(b"FAKE-PT-0001\n")
                b.settimeout(2)
                while True:
                    d = b.recv(4096)
                    if not d:
                        break
                    self.got.append(d)
            except OSError:
                pass
        threading.Thread(target=far, daemon=True).start()
        return a

    def close(self):
        for s in self.ends:
            s.close()


class Resolver:
    def __init__(self, table=None):
        self.table, self.calls = dict(table or {}), []

    def __call__(self, host, port):
        self.calls.append(host)
        if host in self.table:
            v = self.table[host]
            if isinstance(v, Exception):
                raise v
            return list(v)
        return [ai[4][0] for ai in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)]


@pytest.fixture
def make_proxy():
    made = []

    def make(**kw):
        np = _np()
        kw.setdefault("own_addresses", lambda: set())
        kw.setdefault("own_names", lambda: {"fake-host", "fake-host.local"})
        p = np.Proxy(kw.pop("token", TOKEN), **kw)
        p.listen_loopback()
        p.serve()
        made.append(p)
        return p
    yield make
    for p in made:
        p.close()


def _auth(token=TOKEN):
    return "Proxy-Authorization: Basic " + base64.b64encode(f"phiward:{token}".encode()).decode()


def ask(proxy, authority, token=TOKEN, extra=b"", method="CONNECT", read_more=False):
    """Send one request to the proxy; returns (status line, everything read after it)."""
    c = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
    try:
        head = f"{method} {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        if token is not None:
            head += _auth(token) + "\r\n"
        c.sendall(head.encode() + b"\r\n" + extra)
        data = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                d = c.recv(4096)
            except (socket.timeout, ConnectionResetError):  # a reset is a refusal too
                break
            if not d:
                break
            data += d
            if b"\r\n\r\n" in data and not read_more:
                break
            if read_more and b"FAKE-PT-0001" in data:
                break
        line, _, rest = data.partition(b"\r\n")
        return line.decode("latin-1"), rest
    finally:
        c.close()


def _status(line):
    parts = line.split()
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


# --- 3, 7: the address check, through the lookup's answer ----------------------------------------

@pytest.mark.parametrize("authority", [
    "127.0.0.1:443", "0177.1:443", "[::1]:443", "[::ffff:127.0.0.1]:443", "localhost:443",
    "x.localhost:443", "0.0.0.0:443", "169.254.169.254:80", "fake-host:443", "FAKE-HOST.:443",
    "fake-host.local:443"])
def test_3_the_proxy_refuses_this_machine_and_its_link(make_proxy, authority):
    dial = Dial()
    p = make_proxy(dial=dial)
    try:
        line, _ = ask(p, authority)
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, (authority, line)


def test_3_a_name_that_resolves_to_loopback_is_refused(make_proxy):
    dial, res = Dial(), Resolver({"public-looking.example": ["127.0.0.1"]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, _ = ask(p, "public-looking.example:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, line


def test_3_one_bad_address_refuses_the_whole_name(make_proxy):
    dial, res = Dial(), Resolver({"mixed.example": ["8.8.4.4", "127.0.0.1"]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, _ = ask(p, "mixed.example:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, line


def test_3_it_connects_to_the_checked_address_after_one_lookup(make_proxy):
    dial, res = Dial(), Resolver({"pub.example": ["8.8.4.4"]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, rest = ask(p, "pub.example:443", read_more=True)
    finally:
        dial.close()
    assert _status(line) == 200, line
    assert dial.calls == [("8.8.4.4", 443)] and res.calls == ["pub.example"]
    assert b"FAKE-PT-0001" in rest


class FlakyDial(Dial):
    """Made up: the IPv6 addresses do not connect (broken IPv6), the others do."""

    def __init__(self):
        super().__init__()
        self.timeouts = []

    def __call__(self, ip, port, timeout):
        self.timeouts.append(timeout)
        if ":" in ip:
            self.calls.append((ip, port))
            raise OSError(errno.ENETUNREACH, "made-up broken IPv6")
        return super().__call__(ip, port, timeout)


def test_3_each_checked_address_is_tried_in_turn(make_proxy):
    dial = FlakyDial()
    res = Resolver({"pub.example": ["2001:4860:4860::8888", "8.8.4.4"]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, rest = ask(p, "pub.example:443", read_more=True)
    finally:
        dial.close()
    assert _status(line) == 200 and b"FAKE-PT-0001" in rest, line
    assert dial.calls == [("2001:4860:4860::8888", 443), ("8.8.4.4", 443)], dial.calls
    assert all(t <= _np().PER_ADDRESS_TIMEOUT for t in dial.timeouts), dial.timeouts


def test_3_every_address_is_checked_before_any_is_dialled(make_proxy):
    dial = FlakyDial()
    res = Resolver({"pub.example": ["2001:4860:4860::8888", "8.8.4.4", "10.1.2.3"]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, _ = ask(p, "pub.example:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, (line, dial.calls)


def test_3_when_no_address_connects_it_is_a_502(make_proxy):
    dial = FlakyDial()
    res = Resolver({"pub.example": ["2001:4860:4860::8888", "2001:4860:4860::8844"]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, _ = ask(p, "pub.example:443")
    finally:
        dial.close()
    assert _status(line) == 502 and len(dial.calls) == 2, (line, dial.calls)


def test_3_a_lookup_that_fails_is_refused(make_proxy):
    dial = Dial()
    res = Resolver({"broken.example": socket.gaierror(socket.EAI_NONAME, "made up")})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, _ = ask(p, "broken.example:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, line


@pytest.mark.parametrize("literal", [
    "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::7f00:1", "2002:7f00:1::", "::ffff:127.0.0.1",
    "::ffff:0:7f00:1",
    "2130706433", "0x7f.1", "0177.1", "0", "localhost.", "::1"])
def test_7_every_loopback_spelling_is_refused(make_proxy, literal):
    dial = Dial()
    p = make_proxy(dial=dial)
    host = f"[{literal}]" if ":" in literal else literal
    try:
        line, _ = ask(p, f"{host}:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, (literal, line)


@pytest.mark.parametrize("answer", ["::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::7f00:1",
                                    "2002:7f00:1::", "::ffff:127.0.0.1", "::ffff:0:7f00:1"])
def test_7_the_check_judges_the_lookups_answer_not_the_text(make_proxy, answer):
    dial, res = Dial(), Resolver({"looks-public.example": [answer]})
    p = make_proxy(dial=dial, resolver=res)
    try:
        line, _ = ask(p, "looks-public.example:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, (answer, line)


@pytest.mark.parametrize("addr", ["10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "fd00::1",
                                  "fe80::1", "169.254.1.1", "224.0.0.1"])
def test_d2_private_and_local_ranges_are_refused_by_default(addr):
    assert _np().address_problem(addr, set(), ()), addr


def test_d2_an_exception_from_the_user_config_opens_only_its_private_range():
    import ipaddress
    np = _np()
    allow = [ipaddress.ip_network("10.20.0.0/16")]
    assert np.address_problem("10.20.1.2", set(), allow) == ""
    assert np.address_problem("10.21.0.1", set(), allow)
    # loopback and this host's own addresses stay refused, whatever a list says
    assert np.address_problem("127.0.0.1", set(), [ipaddress.ip_network("127.0.0.0/8")])
    assert np.address_problem("10.20.1.2", {ipaddress.ip_address("10.20.1.2")}, allow)


@pytest.mark.parametrize("bad", ["127.0.0.0/8", "8.8.8.0/24", "10.0.0.1/8", "x", "169.254.0.0/16",
                                 "::1/128"])
def test_d2_a_private_network_that_is_not_private_is_a_config_problem(tree, bad):
    from phiward import config
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + f'[launch]\nprivate_networks = ["{bad}"]\n')
    assert config.load(str(tree / "repo")).problem, bad


def test_d2_the_user_config_sets_private_networks(tree):
    from phiward import config
    p = Path(os.environ["PHIWARD_CONFIG"])
    p.write_text(p.read_text() + '[launch]\nprivate_networks = ["10.20.0.0/16", "fd12::/16"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.launch_private_networks == ["10.20.0.0/16", "fd12::/16"]


def test_d2_a_project_file_cannot_add_a_private_network(tree):
    from phiward import config
    (tree / "repo" / ".phiward.toml").write_text('[launch]\nprivate_networks = ["10.0.0.0/8"]\n')
    cfg = config.load(str(tree / "repo"))
    assert not cfg.problem and cfg.launch_private_networks == []
    assert "launch.private_networks" in cfg.ignored


# --- 9: a dead worker leaves the port held and every connection refused --------------------------

def test_9_a_dead_worker_refuses_and_keeps_the_port(make_proxy):
    p = make_proxy(dial=Dial())

    def broken(conn):
        raise RuntimeError("made-up fault")
    p._start_worker = broken
    for _ in range(2):
        line, _ = ask(p, "pub.example:443")
        assert _status(line) != 200, line
    for fam, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            with pytest.raises(OSError) as e:
                s.bind((host, p.port))
            assert e.value.errno == errno.EADDRINUSE
        finally:
            s.close()


# --- 10: one request per connection -------------------------------------------------------------

def test_10_a_refused_connect_closes_the_connection(make_proxy):
    dial = Dial()
    p = make_proxy(dial=dial)
    second = f"CONNECT pub.example:443 HTTP/1.1\r\n{_auth()}\r\n\r\n".encode()
    try:
        line, rest = ask(p, "127.0.0.1:443", extra=second, read_more=True)
    finally:
        dial.close()
    assert _status(line) == 403 and b"200" not in rest and not dial.calls, (line, rest)


def test_10_a_plain_request_is_refused(make_proxy):
    dial = Dial()
    p = make_proxy(dial=dial)
    try:
        line, _ = ask(p, "http://pub.example/", method="GET")
    finally:
        dial.close()
    assert _status(line) == 405 and not dial.calls, line


def test_10_bytes_after_a_connect_go_only_to_the_checked_host(make_proxy):
    dial, res = Dial(), Resolver({"pub.example": ["8.8.4.4"]})
    p = make_proxy(dial=dial, resolver=res)
    second = f"CONNECT 127.0.0.1:443 HTTP/1.1\r\n{_auth()}\r\n\r\n".encode()
    try:
        line, _ = ask(p, "pub.example:443", extra=second, read_more=True)
        time.sleep(0.3)
    finally:
        dial.close()
    assert _status(line) == 200 and dial.calls == [("8.8.4.4", 443)], (line, dial.calls)
    assert b"CONNECT 127.0.0.1" in b"".join(dial.got)  # tunnel data for the checked host


# --- 11: an upstream proxy gets only a checked address -------------------------------------------

def _with_upstream(make_proxy, table):
    up = FakeUpstream()
    np = _np()
    p = make_proxy(resolver=Resolver(table),
                   upstream=np.Upstream("127.0.0.1", up.port, ""))
    return up, p


def test_11_a_name_that_resolves_to_loopback_is_never_sent_upstream(make_proxy):
    up, p = _with_upstream(make_proxy, {"loop.example": ["127.0.0.1"]})
    try:
        line, _ = ask(p, "loop.example:443")
    finally:
        up.close()
    assert _status(line) == 403 and up.heads == [], (line, up.heads)


def test_11_a_name_that_does_not_resolve_here_is_refused(make_proxy):
    up, p = _with_upstream(make_proxy, {"split.example": socket.gaierror(socket.EAI_NONAME, "x")})
    try:
        line, _ = ask(p, "split.example:443")
    finally:
        up.close()
    assert _status(line) == 403 and up.heads == [], (line, up.heads)


@pytest.mark.parametrize("addr,sent", [("8.8.4.4", b"CONNECT 8.8.4.4:443 "),
                                       ("2001:4860:4860::8888", b"CONNECT [2001:4860:4860::8888]:443 ")])
def test_11_upstream_gets_connect_to_the_checked_address(make_proxy, addr, sent):
    up, p = _with_upstream(make_proxy, {"pub.example": [addr]})
    try:
        line, rest = ask(p, "pub.example:443", read_more=True)
    finally:
        up.close()
    assert _status(line) == 200 and b"FAKE-PT-0001" in rest, (line, rest)
    assert len(up.heads) == 1 and up.heads[0].startswith(sent), up.heads
    assert b"pub.example" not in up.heads[0]


@pytest.mark.parametrize("value", ["https://proxy.example:3128", "socks5://proxy.example:1080",
                                   "proxy.example:3128", "http://", "http://proxy.example:99999"])
def test_11_an_upstream_that_cannot_be_chained_is_a_refusal(value):
    np = _np()
    with pytest.raises(np.ProxyError):
        np.upstream_from({"HTTPS_PROXY": value})


def test_11_the_upstream_comes_from_the_launchers_environment():
    np = _np()
    up = np.upstream_from({"https_proxy": "http://user:p%40ss@proxy.example:3128/"})
    assert (up.host, up.port) == ("proxy.example", 3128)
    assert base64.b64decode(up.auth.split()[-1]) == b"user:p@ss"
    assert np.upstream_from({}) is None


# --- 12: this host's addresses, read again for each connection -----------------------------------

def test_12_an_address_this_host_gets_mid_session_is_refused_next_time(make_proxy):
    import ipaddress
    seen = []

    def own():
        seen.append(1)
        return set() if len(seen) == 1 else {ipaddress.ip_address("8.8.4.4")}
    dial, res = Dial(), Resolver({"pub.example": ["8.8.4.4"]})
    p = make_proxy(dial=dial, resolver=res, own_addresses=own)
    try:
        first, _ = ask(p, "pub.example:443")
        second, _ = ask(p, "pub.example:443")
    finally:
        dial.close()
    assert _status(first) == 200 and _status(second) == 403, (first, second)


def test_12_addresses_that_cannot_be_read_refuse(make_proxy):
    def own():
        raise OSError("made up")
    dial = Dial()
    p = make_proxy(dial=dial, resolver=Resolver({"pub.example": ["8.8.4.4"]}), own_addresses=own)
    try:
        line, _ = ask(p, "pub.example:443")
    finally:
        dial.close()
    assert _status(line) == 403 and not dial.calls, line


def test_12_this_hosts_addresses_are_read_from_the_system():
    import ipaddress
    own = _np().own_addresses()
    assert ipaddress.ip_address("127.0.0.1") in own, own


# --- 13: limits ----------------------------------------------------------------------------------

def test_13_the_connection_past_the_limit_is_refused(make_proxy):
    p = make_proxy(dial=Dial(), limit=2, header_timeout=5)
    held = [socket.create_connection(("127.0.0.1", p.port), timeout=5) for _ in range(2)]
    try:
        time.sleep(0.3)
        line, _ = ask(p, "pub.example:443")
    finally:
        for c in held:
            c.close()
    assert _status(line) == 503, line


def test_13_a_client_that_sends_no_header_is_closed(make_proxy):
    p = make_proxy(dial=Dial(), header_timeout=0.5)
    c = socket.create_connection(("127.0.0.1", p.port), timeout=5)
    try:
        start = time.time()
        data = c.recv(4096)
        took = time.time() - start
    finally:
        c.close()
    assert took < 4 and not data.startswith(b"HTTP/1.1 200"), (took, data)


def test_13_a_header_past_the_cap_is_refused(make_proxy):
    dial = Dial()
    p = make_proxy(dial=dial, resolver=Resolver({"pub.example": ["8.8.4.4"]}))
    big = "X-Fake: " + "a" * 70000 + "\r\n"
    c = socket.create_connection(("127.0.0.1", p.port), timeout=5)
    try:
        try:
            c.sendall(f"CONNECT pub.example:443 HTTP/1.1\r\n{big}".encode())
        except OSError:
            pass
        data = c.recv(4096)
    except OSError:
        data = b""
    finally:
        c.close()
        dial.close()
    assert not data.startswith(b"HTTP/1.1 200") and not dial.calls, data


# --- 14: the token -------------------------------------------------------------------------------

@pytest.mark.parametrize("token", [None, "e" * 32, ""])
def test_14_a_connect_without_this_sessions_token_gets_407(make_proxy, token):
    dial = Dial()
    p = make_proxy(dial=dial, resolver=Resolver({"pub.example": ["8.8.4.4"]}))
    try:
        line, rest = ask(p, "pub.example:443", token=token)
    finally:
        dial.close()
    assert _status(line) == 407 and not dial.calls, line
    assert b"Proxy-Authenticate: Basic" in rest


# --- 8: macOS: the proxy holds its port on both loopback addresses -------------------------------

@macos
@pytest.mark.parametrize("fam,host", [(socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")],
                         ids=["v6", "v4"])
def test_8_a_port_squatted_on_either_loopback_address_is_not_used(fam, host):
    np = _np()
    squat = socket.socket(fam, socket.SOCK_STREAM)
    if fam == socket.AF_INET6:
        squat.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    squat.bind((host, 0))
    squat.listen(1)
    port = squat.getsockname()[1]
    p = np.Proxy(TOKEN)
    try:
        with pytest.raises(np.ProxyError):
            p.listen_loopback(ports=[port])
    finally:
        p.close()
        squat.close()


@macos
@pytest.mark.parametrize("opt", [None, "SO_REUSEADDR", "SO_REUSEPORT"])
def test_8_while_the_session_runs_no_process_can_bind_the_proxys_port(make_proxy, opt):
    p = make_proxy(dial=Dial())
    for fam, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            if opt:
                s.setsockopt(socket.SOL_SOCKET, getattr(socket, opt), 1)
            with pytest.raises(OSError):
                s.bind((host, p.port))
        finally:
            s.close()


@macos
@needs_confine
def test_8_launch_refuses_when_the_proxys_port_is_squatted(tree, monkeypatch):
    from phiward import netproxy, wholetool
    squat = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    squat.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    squat.bind(("::1", 0))
    squat.listen(1)
    port = squat.getsockname()[1]
    monkeypatch.setattr(netproxy, "PORTS", (port, port))
    monkeypatch.chdir(tree / "repo")
    run = wholetool._Run()
    try:
        code = wholetool._launch("generic", False, ["--", PY, "-c", "print('RAN')"],
                                 dict(os.environ), run, "")
    finally:
        squat.close()
    assert code != 0 and not run.ran and any("proxy" in n for n in run.notes), run.notes


# --- 4: the tool's environment, and a proxy that cannot start ------------------------------------

def launch(tree, code, extra=(), env_extra=None, timeout=90):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.update(env_extra or {})
    r = subprocess.run([PY, "-m", "phiward", "launch", *extra, "--", PY, "-c", code],
                       cwd=str(tree / "repo"), capture_output=True, text=True, env=env,
                       timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


ENV_PROBE = ("import os, json; print('ENV', json.dumps({k: os.environ.get(k) for k in "
             "('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', "
             "'NO_PROXY', 'no_proxy')}))")


def _env_of(out):
    line = [ln for ln in out.splitlines() if ln.startswith("ENV ")]
    assert line, out
    return json.loads(line[0][4:])


@needs_confine
def test_4_the_tool_gets_the_proxy_variables_and_no_bypass(tree):
    _, out = launch(tree, ENV_PROBE, env_extra={"NO_PROXY": "localhost,127.0.0.1",
                                               "no_proxy": "*"})
    got = _env_of(out)
    urls = {got[k] for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                             "ALL_PROXY", "all_proxy")}
    assert len(urls) == 1, got
    url = urls.pop()
    assert url and url.startswith("http://phiward:") and "@127.0.0.1:" in url, got
    assert got["NO_PROXY"] == "" and got["no_proxy"] == "", got


@needs_confine
def test_4_each_session_has_its_own_token(tree):
    a = _env_of(launch(tree, ENV_PROBE)[1])["HTTPS_PROXY"]
    b = _env_of(launch(tree, ENV_PROBE)[1])["HTTPS_PROXY"]
    assert a and b and a.split("@")[0] != b.split("@")[0]


@needs_confine
def test_4_a_proxy_that_cannot_start_stops_launch(tree, monkeypatch):
    from phiward import netproxy, wholetool

    def fail(*a, **k):
        raise netproxy.ProxyError("made-up bind failure")
    monkeypatch.setattr(netproxy, "start", fail)
    monkeypatch.chdir(tree / "repo")
    run = wholetool._Run()
    code = wholetool._launch("generic", False, ["--", PY, "-c", "print('RAN')"],
                             dict(os.environ), run, "")
    assert code != 0 and not run.ran and any("proxy" in n for n in run.notes), run.notes


@needs_confine
def test_4_an_upstream_that_cannot_be_chained_stops_launch(tree):
    code, out = launch(tree, "print('RAN')", env_extra={"HTTPS_PROXY": "socks5://proxy.example:1"})
    assert code != 0 and "RAN" not in out and "proxy" in out, out


# --- 1, 2: no direct way to this machine's loopback, by any spelling -----------------------------

SPELLINGS = ["127.0.0.1", "127.1", "0.0.0.0", "::1", "::ffff:127.0.0.1", "::"]


def _probe(port):
    return f"""
import base64, json, os, socket
out = {{}}
for host in {SPELLINGS!r}:
    try:
        ai = socket.getaddrinfo(host, {port}, 0, socket.SOCK_STREAM)[0]
        s = socket.socket(ai[0], socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(ai[4])
        out[host] = 'REACHED ' + s.recv(64).decode('ascii', 'replace')
        s.close()
    except OSError as e:
        out[host] = 'REFUSED %s' % e.errno
print('DIRECT', json.dumps(out))
url = os.environ.get('HTTPS_PROXY', '')
if not url.startswith('http://'):
    print('VIA-PROXY NOPROXY')
else:
    cred, _, where = url[7:].rstrip('/').rpartition('@')
    h, _, p = where.rpartition(':')
    s = socket.create_connection((h, int(p)), timeout=10)
    auth = base64.b64encode(cred.encode()).decode()
    s.sendall(('CONNECT 127.0.0.1:{port} HTTP/1.1\\r\\nProxy-Authorization: Basic %s\\r\\n\\r\\n'
               % auth).encode())
    print('VIA-PROXY', s.recv(200).split(b'\\r\\n')[0].decode())
"""


def _direct(out):
    line = [ln for ln in out.splitlines() if ln.startswith("DIRECT ")]
    assert line, out
    return json.loads(line[0][7:])


def _inner(args):
    return (f"import subprocess, os\n"
            f"p = subprocess.run([{PY!r}, '-m', 'phiward', 'launch'] + {list(args)!r}, "
            f"stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, "
            f"env=dict(os.environ, PYTHONPATH={SRC!r}))\nprint(p.stdout)\n")


# macOS: a launch inside a session uses the account's home, which only a CI runner may give a test
# (as in test_v2_nested_launch)
_NESTED = pytest.param("nested", marks=pytest.mark.skipif(
    sys.platform == "darwin" and not os.environ.get("GITHUB_ACTIONS"),
    reason="macOS on GitHub Actions only: a launch inside a session uses the account's home"))


@needs_confine
@pytest.mark.parametrize("how", ["plain", "entry", _NESTED])
def test_1_2_the_session_cannot_reach_this_machines_loopback(tree, server, how):
    probe = _probe(server.port)
    if how == "plain":
        _, out = launch(tree, probe)
    elif how == "entry":
        _, out = launch(tree, probe, extra=("--entry", ID))
    else:
        # macOS: a launch inside a session knows it by the account's home folder, never HOME
        home = {}
        if sys.platform == "darwin":
            import pwd
            home = {"HOME": pwd.getpwuid(os.getuid()).pw_dir}
        _, out = launch(tree, _inner(["--", PY, "-c", probe]), env_extra=home)
    got = _direct(out)
    assert not any(v.startswith("REACHED") for v in got.values()), got
    if sys.platform == "darwin":  # the profile refuses: EPERM, not a missing listener
        assert all(v == f"REFUSED {errno.EPERM}" for v in got.values()), got
    assert "FAKE-PT-0001" not in out, out
    # the proxy is reachable, and it refuses this machine too
    assert "VIA-PROXY HTTP/1.1 403" in out, out


@macos
def test_1_the_profile_allows_only_the_proxys_port(tree, server):
    """The real seatbelt_tool_profile of a conftest tree, run by sandbox-exec: the made-up
    server's port is refused in every spelling; the port the profile names is reachable."""
    from phiward import config, confine, wholetool
    if confine.backend() != "seatbelt":
        pytest.skip("no sandbox-exec")
    other = FakeServer(answer=b"PROXY-PORT\n", v6=False)
    try:
        cfg = config.load(str(tree / "repo"))
        folder = tree / "home" / ".phiward" / "tools" / "generic"
        run = folder / "runs" / "r1"
        (run / "tmp").mkdir(parents=True)
        canary = str(tree / "home" / ".phiward" / "canary")
        prof = wholetool.seatbelt_tool_profile(cfg, [str(tree / "repo"), str(run)],
                                               str(tree / "repo"), dict(os.environ), str(folder),
                                               canary, proxy_port=other.port)
        code = _probe(server.port).split("url = ")[0] + (
            "s = socket.create_connection(('127.0.0.1', %d), timeout=5)\n"
            "print('ALLOWED', s.recv(64).decode())\n" % other.port)
        r = subprocess.run([confine.SANDBOX_EXEC, "-p", prof, PY, "-c", code],
                           capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
    finally:
        other.close()
    got = _direct(out)
    assert all(v == f"REFUSED {errno.EPERM}" for v in got.values()), got
    assert "ALLOWED PROXY-PORT" in out, out


@macos
def test_1_the_profiles_one_port_is_tcp_only(tree):
    """The profile's one allowed port takes TCP only: a UDP datagram to 127.0.0.1:P or [::1]:P
    does not arrive; TCP to [::1]:P does, and ::ffff:127.0.0.1:P is refused."""
    from phiward import config, confine, wholetool
    if confine.backend() != "seatbelt":
        pytest.skip("no sandbox-exec")
    tcp = FakeServer(answer=b"PROXY-PORT\n")
    port = tcp.port
    udp = []
    for fam, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        u = socket.socket(fam, socket.SOCK_DGRAM)
        if fam == socket.AF_INET6:
            u.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        u.bind((host, port))
        u.settimeout(0.5)
        udp.append(u)
    try:
        cfg = config.load(str(tree / "repo"))
        folder = tree / "home" / ".phiward" / "tools" / "generic"
        run = folder / "runs" / "r1"
        (run / "tmp").mkdir(parents=True)
        prof = wholetool.seatbelt_tool_profile(cfg, [str(tree / "repo"), str(run)],
                                               str(tree / "repo"), dict(os.environ), str(folder),
                                               str(tree / "home" / ".phiward" / "canary"),
                                               proxy_port=port)
        code = ("import socket\n"
                "for fam, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):\n"
                "    u = socket.socket(fam, socket.SOCK_DGRAM)\n"
                "    try:\n"
                f"        u.sendto(b'FAKE-PT-0001', (host, {port}))\n"
                "        print('SENT', host)\n"
                "    except OSError as e:\n"
                "        print('UDP-REFUSED', host, e.errno)\n"
                "for host in ('::1', '::ffff:127.0.0.1'):\n"
                "    try:\n"
                f"        s = socket.create_connection((host, {port}), timeout=5)\n"
                "        print('TCP', host, s.recv(64).decode().strip())\n"
                "    except OSError as e:\n"
                "        print('TCP-REFUSED', host, e.errno)\n")
        r = subprocess.run([confine.SANDBOX_EXEC, "-p", prof, PY, "-c", code],
                           capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        got = []
        for u in udp:
            try:
                got.append(u.recv(64))
            except OSError:
                pass
    finally:
        tcp.close()
        for u in udp:
            u.close()
    assert got == [], (got, out)
    assert "TCP ::1 PROXY-PORT" in out and "TCP-REFUSED ::ffff:127.0.0.1" in out, out


# --- 13: limits at launch level: tunnels held while carry-over runs ------------------------------

class HoldingUpstream(FakeUpstream):
    """A made-up upstream proxy that answers 200 and keeps every tunnel open until stopped."""

    def __init__(self):
        self.held = []
        super().__init__()

    def _serve(self):
        while not self.stop.is_set():
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            try:
                c.settimeout(2)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    d = c.recv(4096)
                    if not d:
                        break
                    buf += d
                self.heads.append(buf)
                c.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
                self.held.append(c)
            except OSError:
                c.close()

    def close(self):
        super().close()
        for c in self.held:
            c.close()


# the tool opens 64 tunnels (to a public address, through the made-up upstream), leaves them to a
# child that keeps them open for a while, and exits: on macOS the child outlives the tool, so the
# tunnels are open while carry-over runs (on Linux the session's namespace ends them)
HOG = r"""
import base64, os, socket, sys, time
url = os.environ.get('HTTPS_PROXY', '')
cred, _, where = url[7:].rstrip('/').rpartition('@')
h, _, p = where.rpartition(':')
auth = base64.b64encode(cred.encode()).decode()
held = []
for _ in range(64):
    try:
        s = socket.create_connection((h, int(p)), timeout=10)
        s.sendall(('CONNECT 8.8.4.4:443 HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n'
                   % auth).encode())
        if not s.recv(200).startswith(b'HTTP/1.1 200'):
            break
        held.append(s)
    except OSError:
        break
print('HELD', len(held), flush=True)
pid = os.fork()
if pid == 0:
    os.setsid()
    nul = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(nul, fd)
    time.sleep(8)
    os._exit(0)
print('CHILD', pid, flush=True)
"""


@needs_confine
def test_13_carry_over_finishes_while_64_tunnels_are_held(tree):
    import resource
    up = HoldingUpstream()
    report = tree / "pub" / "report.json"
    hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]

    def low_limit():  # a low soft limit of open files: the launcher must raise it itself
        resource.setrlimit(resource.RLIMIT_NOFILE, (100, hard))
    env = dict(os.environ, PYTHONPATH=SRC, HTTPS_PROXY=f"http://127.0.0.1:{up.port}")
    try:
        r = subprocess.run([PY, "-m", "phiward", "launch", "--report", str(report), "--", PY, "-c",
                            HOG], cwd=str(tree / "repo"), capture_output=True, text=True, env=env,
                           timeout=120, stdin=subprocess.DEVNULL, preexec_fn=low_limit)
        out = r.stdout + r.stderr
        child = [ln.split()[1] for ln in out.splitlines() if ln.startswith("CHILD ")]
        if sys.platform == "darwin" and child:  # the child this test's session started
            try:
                os.kill(int(child[0]), 9)
            except (ProcessLookupError, PermissionError):
                pass
    finally:
        up.close()
    assert r.returncode == 0 and "HELD 64" in out, out
    data = json.loads(report.read_text())
    assert data["exit"] == 0 and data["ran"] is True, data
    assert not any("did not finish" in n for n in data["notes"]), data["notes"]


# --- 5, 15: Linux -------------------------------------------------------------------------------

@linux
def test_5_the_session_settings_keep_bash_inside_the_inner_sandbox(tmp_path):
    from phiward import wholetool
    d = tmp_path / "cfg"
    d.mkdir()
    fd = os.open(str(d), os.O_RDONLY)
    try:
        wholetool.ADAPTERS["claude"].turn_own_sandbox_off(fd)
    finally:
        os.close(fd)
    data = json.loads((d / "settings.json").read_text())
    assert data["sandbox"]["allowUnsandboxedCommands"] is False, data


def test_15_network_namespaces_turned_off_are_named(tmp_path):
    from phiward import confine
    f = tmp_path / "max_net_namespaces"
    f.write_text("0\n")
    why = confine.net_namespace_problem("/fake/bwrap", sysctl=str(f),
                                        run=lambda *a, **k: pytest.fail("no probe needed"))
    assert "max_net_namespaces" in why, why


def test_15_a_bwrap_that_cannot_make_a_network_namespace_is_named(tmp_path):
    from phiward import confine
    f = tmp_path / "max_net_namespaces"
    f.write_text("1000\n")

    def fake(cmd, **k):
        assert "--unshare-net" in cmd
        return subprocess.CompletedProcess(cmd, 1, "", "bwrap: Creating new namespace failed: "
                                                       "Operation not permitted\n")
    why = confine.net_namespace_problem("/fake/bwrap", sysctl=str(f), run=fake)
    assert "Creating new namespace failed" in why, why
    ok = confine.net_namespace_problem(
        "/fake/bwrap", sysctl=str(f),
        run=lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, "", ""))
    assert ok == ""


def test_15_doctor_names_the_cause():
    from phiward import doctor
    lines = doctor.launch_network_lines(platform="linux", problem="user.max_net_namespaces is 0")
    assert any("WARNING" in ln and "max_net_namespaces" in ln and "launch" in ln for ln in lines)
    assert doctor.launch_network_lines(platform="linux", problem="") == []
    assert doctor.launch_network_lines(platform="darwin", problem="x") == []


@linux
@needs_confine
def test_15_launch_refuses_without_network_namespaces(tree, monkeypatch, tmp_path):
    from phiward import confine, wholetool
    f = tmp_path / "max_net_namespaces"
    f.write_text("0\n")
    monkeypatch.setattr(confine, "NETNS_SYSCTL", str(f))
    monkeypatch.chdir(tree / "repo")
    run = wholetool._Run()
    code = wholetool._launch("generic", False, ["--", PY, "-c", "print('RAN')"],
                             dict(os.environ), run, "")
    assert code != 0 and not run.ran and any("max_net_namespaces" in n for n in run.notes), \
        run.notes


# --- 17: Linux: the relay reaches the proxy by a socket pair, never by a socket with a path -------

def _launch_tool(tree, tool, code, env_extra=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.update(env_extra or {})
    r = subprocess.run([PY, "-m", "phiward", "launch", "--tool", tool, "--", tool_py(tree, tool),
                        "-c", code], cwd=str(tree / "repo"), capture_output=True, text=True,
                       env=env, timeout=120, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


CONNECT_UP = r"""
import base64, os, socket
url = os.environ.get('HTTPS_PROXY', '')
cred, _, where = url[7:].rstrip('/').rpartition('@')
h, _, p = where.rpartition(':')
try:
    s = socket.create_connection((h, int(p)), timeout=10)
    s.sendall(('CONNECT 8.8.4.4:443 HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n'
               % base64.b64encode(cred.encode()).decode()).encode())
    s.settimeout(10)
    got = b''
    while b'FAKE-PT-0001' not in got:
        d = s.recv(4096)
        if not d:
            break
        got += d
    print('GOT', got.split(b'\r\n')[0].decode(), b'FAKE-PT-0001' in got)
except OSError as e:
    print('FAILED', e)
"""


# below Landlock ABI 9, generic is the mode where the tool cannot make unix sockets at all and
# claude the one where Claude Code's filter holds Bash; from ABI 9 both are Landlock's
@linux
@needs_confine
@pytest.mark.parametrize("tool", ["generic", "claude"])
def test_17_the_tool_reaches_a_made_up_upstream_through_the_proxy(tree, tool):
    up = FakeUpstream()
    try:
        _, out = _launch_tool(tree, tool, CONNECT_UP,
                              {"HTTPS_PROXY": f"http://127.0.0.1:{up.port}"})
        heads = list(up.heads)
    finally:
        up.close()
    assert "GOT HTTP/1.1 200" in out and "True" in out, out
    assert any(h.startswith(b"CONNECT 8.8.4.4:443 ") for h in heads), heads


# every mount in the session's view, and every entry of its /tmp, that is a socket, and what a
# connect to it gets
NO_SOCKET_PATH = r"""
import json, os, socket, stat
found = []
with open('/proc/self/mountinfo') as fh:
    points = [ln.split()[4] for ln in fh]
for p in points:
    try:
        if stat.S_ISSOCK(os.stat(p).st_mode):
            found.append(p)
    except OSError:
        pass
for root, dirs, files in os.walk('/tmp'):
    for n in dirs + files:
        try:
            if stat.S_ISSOCK(os.lstat(os.path.join(root, n)).st_mode):
                found.append(os.path.join(root, n))
        except OSError:
            pass
got = {}
for p in sorted(set(found)):
    try:
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(5)
        s.connect(p)
        got[p] = 'REACHED'
        s.close()
    except OSError as e:
        got[p] = 'REFUSED %s' % e.errno
print('SOCKETS', json.dumps(got))
"""


def _host_socket(path):
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


@linux
@needs_confine
@pytest.mark.parametrize("tool", ["generic", "claude"])
def test_17_no_socket_with_a_path_leads_to_the_proxy_in_the_session(tree, tool):
    """The proxy has no path (the relay gets each connection on a socket pair), so a socket in
    the view is either in the session's own /tmp (none may be) or a host service's, bound in
    with its folder (GitHub's runners have snapd's and acpid's in /run): the session cannot
    reach it (the rule of test_v2_launch_sockets: the tool itself, for --tool claude, only with
    Landlock ABI 9; below it Claude Code's own sandbox holds them for Bash, a stated limit)."""
    _, out = _launch_tool(tree, tool, NO_SOCKET_PATH)
    line = [ln for ln in out.splitlines() if ln.startswith("SOCKETS ")]
    assert line, out
    got = json.loads(line[0][8:])
    ours = [p for p in got if p == "/tmp" or p.startswith("/tmp/") or not _host_socket(p)]
    assert ours == [], got
    if tool == "generic" or landlock_abi() >= 9:
        assert not [p for p, v in got.items() if v == "REACHED"], got


def test_17_the_proxy_for_a_relay_listens_on_no_path():
    np = _np()
    p = np.start({}, pair=True)
    try:
        assert p.listeners == [] and p.port == 0, p.listeners
        end = p.session_end
        assert end.family == socket.AF_UNIX and end.getsockname() in ("", b""), end
    finally:
        p.close()


def _ask_pair(end):
    end.sendall(b"c")
    msg, fds, _flags, _addr = socket.recv_fds(end, 1, 4)
    return msg, [socket.socket(fileno=f) for f in fds]


def test_17_each_request_on_the_pair_gets_a_connection_to_the_proxy(monkeypatch):
    np = _np()
    p = np.start({}, pair=True)
    try:
        msg, socks = _ask_pair(p.session_end)
        assert msg == b"y" and len(socks) == 1, (msg, socks)
        c = socks[0]
        c.settimeout(10)
        c.sendall(b"CONNECT pub.example:443 HTTP/1.1\r\n\r\n")  # no token: the proxy's 407
        assert c.recv(200).startswith(b"HTTP/1.1 407")
        c.close()
    finally:
        p.close()


def test_17_a_pair_that_cannot_be_made_refuses_the_connection(monkeypatch):
    np = _np()

    def fail():
        raise OSError(errno.EMFILE, "made-up: too many open files")
    p = np.start({}, pair=True)
    monkeypatch.setattr(np, "_pair", fail)
    try:
        msg, socks = _ask_pair(p.session_end)
        assert msg == b"n" and socks == [], (msg, socks)
    finally:
        p.close()


RELAY_PROBE = r"""
import base64, os, socket
url = os.environ['HTTPS_PROXY']
h, _, p = url.rpartition('@')[2].rpartition(':')
try:
    s = socket.create_connection((h, int(p)), timeout=10)
    s.settimeout(10)
    s.sendall(b'CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n' % int(os.environ['DIRECT']))
    print('RELAY', repr(s.recv(200)))
except OSError as e:
    print('RELAY-FAILED', e.errno)
"""


@linux
def test_17_a_failed_fd_pass_refuses_the_connection_and_dials_nothing(server):
    """The helper's relay on its own (outside bwrap): the launcher's end answers `n` without a
    descriptor; the tool's connection is closed unanswered and nothing is dialled directly."""
    from phiward import netproxy, wholetool
    mine, theirs = socket.socketpair()
    port = netproxy.random_port()
    answered = []

    def launcher():
        try:
            while True:
                b = mine.recv(1)
                if not b:
                    return
                answered.append(b)
                mine.sendall(b"n")
        except OSError:
            pass
    threading.Thread(target=launcher, daemon=True).start()
    env = dict(os.environ, PHIWARD_PROXY_RELAY=f"{port}:{theirs.fileno()}",
               HTTPS_PROXY=f"http://phiward:{TOKEN}@127.0.0.1:{port}", DIRECT=str(server.port))
    code = f"import time; time.sleep(0.5)\n{RELAY_PROBE}"
    try:
        r = subprocess.run([PY, "-I", "-S", "-c", wholetool.HELPER_LINUX, "-1", "none", "0", PY,
                            "-c", code], pass_fds=[theirs.fileno()], env=env,
                           capture_output=True, text=True, timeout=60)
    finally:
        theirs.close()
        mine.close()
    out = r.stdout + r.stderr
    assert "RELAY b''" in out or "RELAY-FAILED" in out, out
    assert answered == [b"c"], answered
    assert server.got == [], server.got


# --- 16: macOS: no Mach service that makes connections outside the profile ----------------------

def test_16_no_background_transfer_service_in_the_mach_allows():
    from phiward import wholetool
    assert "com.apple.nsurlsessiond" not in wholetool.MACH_ALLOW
    assert "com.apple.networkd" not in wholetool.MACH_ALLOW
    # certificate services that can fetch URLs outside the profile: the OS trust store needs
    # only the user's trustd agent (kept: a stated limit)
    assert "com.apple.ocspd" not in wholetool.MACH_ALLOW
    assert "com.apple.trustd" not in wholetool.MACH_ALLOW
