"""`phiward broker --service [--write]`: run the broker as a login service.

The broker is the trusted side: the agent must never start or control it. A login service keeps
that (the operator installs it, once, in their own terminal) and saves keeping a terminal open:
a LaunchAgent on macOS, a systemd user service on Linux. It starts at login and starts again if
it stops. Its log goes to `log_folder()` (~/Library/Logs/phiward on macOS, ~/.local/state/phiward
on Linux), which is on the hidden list: it holds the real exit status of gateway commands and
request sizes, never a path or a word of a request. `phiward doctor` shows whether it runs.

The service gets the PATH of the terminal it is installed from (the broker finds gateway programs
on the operator's PATH): install it from a terminal where your tools are found, and again after
your PATH changes.

Without `--write` it prints the file and the commands. With `--write` it writes the file; in the
operator's own terminal it then loads the service, or restarts it when it runs already
(launchctl or systemctl --user); without a terminal it only prints those commands.
"""

import os
import shutil
import sys
from typing import List, Tuple

from phiward import pathid


LABEL = "org.phiward.broker"


def service_file(home: str = "") -> str:
    home = home or os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "LaunchAgents", LABEL + ".plist")
    return os.path.join(home, ".config", "systemd", "user", "phiward-broker.service")


def log_folder(home: str = "") -> str:
    """Where the login service writes the broker's log (a command's real exit status, request
    sizes; never a path or a word of a request). On the hidden list: no session reads it."""
    home = home or os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Logs", "phiward")
    return os.path.join(home, ".local", "state", "phiward")


def _env() -> List[Tuple[str, str]]:
    # the operator's PATH as it is now: the broker runs a gateway program from the operator's
    # PATH (conda tools such as samtools), and a login service otherwise gets only the system's
    path = ":".join(_safe_path_entries(os.environ.get("PATH", ""))) or "/usr/bin:/bin:/usr/sbin:/sbin"
    out = [("PATH", path)]
    # the ticket cache and krb5 config the broker must hide from gateway commands, as the
    # operator's own shell names them
    for k in ("PHIWARD_CONFIG", "PHIWARD_SPOOL", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
              "KRB5CCNAME", "KRB5_CONFIG", "KRB5_KTNAME", "KRB5_CLIENT_KTNAME"):
        if os.environ.get(k):
            out.append((k, _env_value(k, os.environ[k])))
    return out


_KRB5_TYPES = ("FILE:", "DIR:", "KCM:", "API:", "KEYRING:", "MEMORY:", "MSLSA:", "WRFILE:")


def _env_value(key: str, value: str) -> str:
    """A path variable as an absolute path; a Kerberos cache name keeps its type prefix
    (`DIR:`, `FILE:`, `KCM:`), with only the path after it made absolute."""
    if key == "KRB5CCNAME":
        for t in _KRB5_TYPES:
            if value.upper().startswith(t):
                rest = value[len(t):]
                return t + (os.path.abspath(os.path.expanduser(rest)) if rest.startswith(("/", "~"))
                            else rest)
    if key in ("KRB5_CONFIG",):
        return ":".join(os.path.abspath(os.path.expanduser(v)) for v in value.split(":") if v)
    return os.path.abspath(os.path.expanduser(value))


def path_inputs() -> Tuple[str, str, Tuple[str, ...], Tuple[str, ...]]:
    """What the PATH filter reads from this process: (the real home folder, the real current
    folder, the folders the agent's sandbox may write in any project, the real temp folders).
    A cache of the filter's result keys on this (mcp_config._launchers_on); the file system's
    own state (modes, folders, `.git`) is not in it."""
    from phiward import claude_settings
    home = os.path.realpath(pathid.home())
    return (home, os.path.realpath(os.getcwd()),
            tuple(claude_settings.agent_writable_anywhere(home)),
            tuple(os.path.realpath(t) for t in claude_settings._temp_roots()))


def _safe_path_entries(path: str) -> List[str]:
    return path_entries(path, path_inputs())


def path_entries(path: str, inputs: Tuple[str, str, Tuple[str, ...], Tuple[str, ...]],
                 work_trees: bool = True) -> List[str]:
    """PATH entries the broker may search outside every sandbox: absolute, existing folders that
    pass `selfcheck.safe_path`, are not a project's, and are not ones the agent's sandbox may
    write (`claude_settings.agent_writable_anywhere`, a temp folder outside the home folder): a
    relative entry, or one the agent or another account can write, would let it choose the
    program the broker runs. `inputs`: `path_inputs()`."""
    out: List[str] = []
    home, here, writable, temps = inputs
    # the current folder counts as a project unless it is the home folder or above it (run
    # from the home folder, `~/.local/bin` stays)
    project = "" if (here == home or _below(home, here)) else here
    # `writable`: what the agent's sandbox may write in any project; `temps`: a temp folder
    # wherever it is (`$TMPDIR=~/tmp` on a cluster), except the home folder's own entries when
    # the home folder is inside it (a test's home, or `TMPDIR=$HOME`)
    for e in path.split(":"):
        if not e.startswith("/") or e in out:
            continue
        real = os.path.realpath(e)
        # a folder inside the current project or inside a git work tree below the home folder
        # is a project's (its `.venv/bin`, `node_modules/.bin`): the agent can write there
        if (project and (real == project or _below(real, project))) or (
                work_trees and _in_work_tree(real, home)):
            continue
        if any(real == w or _below(real, w) for w in writable) or any(
                (real == t or _below(real, t)) and not (
                    (home == t or _below(home, t)) and (real == home or _below(real, home)))
                for t in temps):
            continue
        if not os.path.isdir(e):
            continue
        from phiward import selfcheck
        if selfcheck.safe_path(e) is not None:
            # the one rule (selfcheck.safe_path): the folder and each folder above it are the
            # operator's or root's and no group or other account can write them (Homebrew's
            # admin-group folders on macOS are its one exception)
            continue
        out.append(e)
    return out


def dropped_path_entries(path: str) -> List[str]:
    """The PATH entries the broker does not search, for doctor to name."""
    keep = set(_safe_path_entries(path))
    return [e for e in path.split(":") if e and e not in keep]


def _below(a: str, b: str) -> bool:
    return pathid.inside(a, b, strict=True)


def _in_work_tree(folder: str, home: str) -> bool:
    """Whether `folder` is inside a git work tree below the home folder, where projects live.
    The search stops at the home folder and does not count it (a dotfiles repository there), and
    folders outside the home folder are tools' (Homebrew keeps /opt/homebrew/.git)."""
    if not _below(folder, home):
        return False
    d = folder
    while d != home and d != "/" and d:
        if os.path.lexists(os.path.join(d, ".git")):
            return True
        d = os.path.dirname(d)
    return False


def _systemd(s: str) -> str:
    """A value inside a quoted systemd `Environment=` word: backslash, quote and `%` escaped."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")


def _xml(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(exe: str) -> str:
    if sys.platform == "darwin":
        env = "".join(f"\n      <key>{_xml(k)}</key><string>{_xml(v)}</string>" for k, v in _env())
        return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array><string>{_xml(exe)}</string><string>broker</string></array>
    <key>EnvironmentVariables</key>
    <dict>{env}
    </dict>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>/dev/null</string>
    <key>StandardErrorPath</key><string>{_xml(os.path.join(log_folder(), "broker.log"))}</string>
  </dict>
</plist>
'''
    env = "".join(f'Environment="{_systemd(k)}={_systemd(v)}"\n' for k, v in _env()
                  if "\n" not in k + v)
    return f"""[Unit]
Description=phiward broker (runs the gateway outside the agent's sandbox)

[Service]
ExecStart="{_systemd(exe)}" broker
{env}Restart=always
StandardOutput=null
StandardError=append:{_systemd(os.path.join(log_folder(), "broker.log"))}

[Install]
WantedBy=default.target
"""


def load(path: str, runner=None) -> bool:
    """Load the service, or restart it when it is loaded already (the operator's terminal only).
    True when every command worked."""
    import subprocess
    if runner is None and os.environ.get("PHIWARD_SERVICE_RUNNER") == "none":
        return False  # the test suite: never load a real login service; the commands are printed
    real = runner or (lambda cmd, **k: subprocess.run(cmd, **k))

    def run(cmd, **k):
        try:
            return real(cmd, **k)
        except (OSError, subprocess.SubprocessError):
            # no service manager here (a container, WSL), or it hangs: not loaded
            return subprocess.CompletedProcess(cmd, 127, "", "")
    q = dict(capture_output=True, text=True, timeout=30)
    uid = os.getuid()
    if sys.platform == "darwin":
        target = f"gui/{uid}/{LABEL}"
        if run(["launchctl", "print", target], **q).returncode == 0:
            steps = [["launchctl", "kickstart", "-k", target]]
        else:
            steps = [["launchctl", "bootstrap", f"gui/{uid}", path]]
    else:
        unit = "phiward-broker.service"
        steps = [["systemctl", "--user", "daemon-reload"]]
        if run(["systemctl", "--user", "is-enabled", unit], **q).returncode == 0:
            steps.append(["systemctl", "--user", "restart", unit])
        else:
            steps.append(["systemctl", "--user", "enable", "--now", unit])
    return all(run(c, **q).returncode == 0 for c in steps)


def _manager() -> str:
    return "launchctl" if sys.platform == "darwin" else "systemctl"


def no_manager_text() -> str:
    """What to say when this system has no service manager to start the broker at login (a
    container, WSL without systemd, an HPC node); "" when it has one."""
    if shutil.which(_manager()):
        return ""
    return (f"This system has no {_manager()} (no service manager for your login), so the broker "
            "cannot start by itself. Start it yourself in a terminal that stays open: `phiward "
            "broker`.\n")


def load_commands(path: str) -> List[str]:
    if sys.platform == "darwin":
        return [f"launchctl bootstrap gui/{os.getuid()} {path}"]
    return ["systemctl --user daemon-reload",
            "systemctl --user enable --now phiward-broker.service"]


def unload_commands(path: str) -> List[str]:
    if sys.platform == "darwin":
        return [f"launchctl bootout gui/{os.getuid()} {path}"]
    return ["systemctl --user disable --now phiward-broker.service"]


def main(argv: List[str]) -> int:
    if any(a in ("-h", "--help") for a in argv):
        from phiward import broker
        sys.stdout.write(broker.HELP)
        return 0
    from phiward.install import OVERRIDES
    overrides = [k for k in OVERRIDES if os.environ.get(k)]
    try:
        tty = sys.stdin.isatty()
    except (AttributeError, ValueError):
        tty = False
    if overrides and not tty:
        # without a terminal (an agent tool) the service must use the default places: a service
        # file that names a config would run the broker with it
        sys.stderr.write(f"phiward broker --service: {', '.join(overrides)} is set; run this in "
                         "your own terminal, or unset it. Nothing was written.\n")
        return 2
    # found only on PATH entries the agent cannot write
    # the launcher phiward's install record lists (the same one `phiward mcp wrap` writes);
    # without a record, found only on PATH entries the agent cannot write
    from phiward import mcp_config
    exe = mcp_config.installed_launcher()
    if not exe:
        sys.stderr.write("phiward broker --service: no installed phiward launcher was found (not "
                         "in an install record, nor in a PATH folder only you can write); install "
                         "it with uv tool or pipx first\n")
        return 2
    exe = os.path.realpath(exe)
    path = service_file()
    text = render(exe)
    if "--write" not in argv:
        sys.stdout.write(f"# {path}\n{text}\n# then, in your own terminal:\n")
        for c in load_commands(path):
            sys.stdout.write(f"#   {c}\n")
        return 0
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(log_folder(), mode=0o700, exist_ok=True)
    from phiward import safeio
    safeio.write_new(path, text, mode=0o644)  # through a fresh name, never a link
    sys.stdout.write(f"phiward broker --service: wrote {path}\n")
    missing = no_manager_text()
    if missing:
        sys.stdout.write(missing)
    elif tty:
        # the operator's own terminal: load it now, or restart it if it runs already
        if load(path):
            sys.stdout.write("The broker service is running now, and starts at every login.\n")
        else:
            sys.stdout.write("It could not be loaded here. Load it yourself:\n")
            for c in load_commands(path):
                sys.stdout.write(f"  {c}\n")
    else:
        sys.stdout.write("Load it now (and at every login it starts by itself):\n")
        for c in load_commands(path):
            sys.stdout.write(f"  {c}\n")
    sys.stdout.write("To stop and remove it later:\n")
    for c in unload_commands(path):
        sys.stdout.write(f"  {c}\n")
    sys.stdout.write(f"  rm {path}\n")
    return 0
