#!/bin/sh
# As the new user: quickstart steps 1 to 3, then wrap an MCP server, then the $SCENARIO's own
# steps (check.sh lists them). Exits non-zero, with the output, at the first step that does not
# do what the docs say.
fail() { echo "FAIL: $1"; cat "$2" 2>/dev/null; exit 1; }
mkdir -p ~/data/FAKE-PT-0001 ~/proj
echo "FAKE-PT-0001 line" > ~/data/FAKE-PT-0001/a.txt
(cd ~/proj && git init -q)
# 1. install (the wheel in place of `uv tool install phiward==...` or `pipx install ...`)
[ "$SCENARIO" = home-775 ] && chmod 775 ~
if [ "$SCENARIO" = linked-home ]; then
  # the shell says /home/tester, the real folder is /var/home/tester
  [ "$(readlink -f ~)" = /var/home/tester ] || fail "the home folder is not behind a link"
fi
if [ "$INSTALLER" = pipx ] && [ "$SCENARIO" = owned-python ]; then
  # pipx on a Python the user owns, that no uv tool environment manages
  uv python install -q 3.12 >/dev/null 2>&1 || fail "uv python install"
  own=$(uv python find --python-preference only-managed 3.12) || fail "uv python find"
  pipx install -q --python "$own" /qs/wheel/phiward-*.whl >/dev/null 2>&1 || fail "pipx install"
  pipx ensurepath >/dev/null 2>&1 || true
elif [ "$INSTALLER" = pipx ] && [ "$SCENARIO" = outside-python ]; then
  # pipx on a Python the user owns outside the home folder, made group-writable as umask 002
  # makes it: doctor names one step for all of it, and after that step it is clean
  uv python install -q 3.12 >/dev/null 2>&1 || fail "uv python install"
  own=$(uv python find --python-preference only-managed 3.12) || fail "uv python find"
  cp -a "$(dirname "$(dirname "$own")")"/. /opt/py/ && chmod -R g+w /opt/py || fail "copy python"
  pipx install -q --python /opt/py/bin/python3.12 /qs/wheel/phiward-*.whl >/dev/null 2>&1 \
    || fail "pipx install"
  export PATH="$HOME/.local/bin:$PATH"
  cd ~ && phiward doctor > /tmp/doctor0.out 2>&1
  grep "phiward's Python can be changed" /tmp/doctor0.out > /tmp/step.out \
    || fail "doctor: no step for a Python outside the home folder" /tmp/doctor0.out
  grep -q "find \." /tmp/step.out || fail "doctor: no find step" /tmp/step.out
  python3 -c "import re,sys; [print(c) for c in re.findall(r'\`([^\`]+)\`', open('/tmp/step.out').read()) if c.startswith(('chmod ', '(cd '))]" > /tmp/step.sh
  sh /tmp/step.sh || fail "the step" /tmp/step.sh
  phiward doctor > /tmp/doctor1.out 2>&1
  # what is left is inside the home folder (umask 002 made ~/.local group-writable): install's
  grep "phiward's Python can be changed" /tmp/doctor1.out | grep -q "outside your home" \
    && fail "doctor after the one step still names something outside the home folder" \
      /tmp/doctor1.out
  pipx ensurepath >/dev/null 2>&1 || true
elif [ "$INSTALLER" = pipx ]; then
  pipx install -q /qs/wheel/phiward-*.whl >/dev/null 2>&1 || fail "pipx install"
  pipx ensurepath >/dev/null 2>&1 || true
else
  uv tool install -q /qs/wheel/phiward-*.whl || fail "uv tool install"
  uv tool update-shell >/dev/null 2>&1 || true
fi
export PATH="$HOME/.local/bin:$PATH"  # a new terminal
if [ "$INSTALLER" = pipx ] && [ "$(umask)" = 0002 ] && [ "$SCENARIO" = plain ]; then
  # before setup, a pipx venv on the system Python with a group-writable ~/.local: the step for
  # phiward's Python is install (it fixes ~/.local), never a chmod on the venv's linked python
  # (the package's WARNING gives it; a second WARNING only when its step differs)
  cd ~ && phiward doctor > /tmp/doctor0.out 2>&1
  grep -E "phiward's (own files fail its self-check|Python can be changed)" /tmp/doctor0.out \
    > /tmp/doctor0.self || true
  grep -q "install claude --user --write" /tmp/doctor0.self && ! grep -q "chmod" /tmp/doctor0.self \
    || fail "doctor before setup: the step for phiward's Python is not install" /tmp/doctor0.out
  grep "phiward's Python can be changed" /tmp/doctor0.out | grep -q chmod \
    && fail "doctor before setup: a chmod step" /tmp/doctor0.out
fi
# 2. set it up by hand, choice 1 (answers.txt: the folder, defaults, no HPC, yes to each)
cd ~ && script -qec "phiward setup" /dev/null < /qs/answers.txt > /tmp/setup.out 2>&1 \
  || fail "phiward setup" /tmp/setup.out
grep -q Traceback /tmp/setup.out && fail "phiward setup crashed" /tmp/setup.out
# no systemd in a container: setup says so, and the operator runs the broker
phiward broker > /tmp/broker.log 2>&1 &
sleep 3
# 3. check it
if [ "$SCENARIO" = home-775 ]; then
  # the one thing phiward never changes: it names the step
  cd ~/proj && phiward doctor > /tmp/doctor.out 2>&1
  grep -q "chmod go-w ~" /tmp/doctor.out || fail "doctor: no chmod step for the home folder" /tmp/doctor.out
  chmod go-w ~
fi
cd ~/proj && phiward doctor > /tmp/doctor.out 2>&1 || fail "phiward doctor" /tmp/doctor.out
grep -q WARNING /tmp/doctor.out && fail "doctor has a WARNING" /tmp/doctor.out
grep -q "protected roots: 1" /tmp/doctor.out || fail "doctor: no protected root" /tmp/doctor.out
# wrap an MCP server (docs/modes.md): a tiny stdio server that tries the protected file
cp /qs/srv.py ~/proj/srv.py
printf '{"mcpServers": {"docs": {"command": "python3", "args": ["%s/proj/srv.py"]}}}\n' "$HOME" \
  > ~/.claude.json
phiward mcp list | grep -q "not wrapped" || fail "mcp list before wrap"
script -qec "phiward mcp wrap docs" /dev/null < /qs/yes.txt > /tmp/wrap.out 2>&1 \
  || fail "phiward mcp wrap" /tmp/wrap.out
phiward mcp list > /tmp/list.out 2>&1
grep -q "docs (~/.claude.json): wrapped" /tmp/list.out || fail "mcp list after wrap" /tmp/list.out
[ -f ~/.phiward/backups/*/original ] || fail "no backup in ~/.phiward/backups"
# start the wrapped server from its entry, as Claude Code does: it must answer, and must not
# read the protected file
cd ~/proj && python3 /qs/start.py > /tmp/start.out 2>&1 || fail "the wrapped server" /tmp/start.out
grep -q "answered" /tmp/start.out || fail "the wrapped server did not answer" /tmp/start.out
grep -q "READ-DENIED" ~/proj/probe.out || fail "the wrapped server read the protected file" ~/proj/probe.out
grep -q "hook from project: exit 0" /tmp/start.out \
  || fail "the hook did not trust the live wrapped server" /tmp/start.out
grep -q "hook from home: exit 0" /tmp/start.out \
  || fail "the hook did not trust it from a home-folder session" /tmp/start.out
# 3 again: doctor after wrap
cd ~/proj && phiward doctor > /tmp/doctor2.out 2>&1
grep -q WARNING /tmp/doctor2.out && fail "doctor after wrap has a WARNING" /tmp/doctor2.out
# another program on the same Python makes new __pycache__ folders: phiward still starts
py=$(dirname "$(readlink -f "$(command -v phiward)")")/python
"$py" -c "import sqlite3, xml.dom.minidom, wsgiref.util, http.cookiejar" || fail "stdlib import"
cd ~/proj && phiward doctor > /tmp/doctor3.out 2>&1
grep -q WARNING /tmp/doctor3.out && fail "doctor after another program used the Python" /tmp/doctor3.out
STEP="phiward install claude --user --write"
case "$SCENARIO" in
upgrade)
  # an upgrade writes phiward's files again with umask 002: wrapped servers refuse with the one
  # step, doctor gives it too, and after it all is clean
  uv tool install -q --reinstall /qs/wheel/phiward-*.whl || fail "uv tool reinstall"
  cd ~/proj && python3 /qs/start.py > /tmp/start2.out 2>&1
  grep -q "$STEP" /tmp/start2.out || fail "the wrapped server's refusal has no step" /tmp/start2.out
  phiward doctor > /tmp/doctor4.out 2>&1
  grep -q "$STEP" /tmp/doctor4.out || fail "doctor after the upgrade has no step" /tmp/doctor4.out
  $STEP > /tmp/install2.out 2>&1 || fail "install again" /tmp/install2.out
  phiward doctor > /tmp/doctor5.out 2>&1
  grep -q WARNING /tmp/doctor5.out && fail "doctor after install again" /tmp/doctor5.out
  python3 /qs/start.py > /tmp/start3.out 2>&1
  grep -q "answered" /tmp/start3.out || fail "the wrapped server after install again" /tmp/start3.out ;;
attack)
  # another account of the shared group: before install fixes it, doctor says so; after, it
  # can neither move a folder above phiward's Python nor plant a start-up file
  chmod 755 ~
  chmod g+w ~/.local/share/uv/tools ~/.local/share/uv
  phiward doctor > /tmp/doctor4.out 2>&1
  grep -q "$STEP" /tmp/doctor4.out || fail "doctor did not see a group-writable folder" /tmp/doctor4.out
  $STEP > /tmp/install2.out 2>&1 || fail "install again" /tmp/install2.out
  site=$("$py" -c "import sysconfig; print(sysconfig.get_path('purelib'))")
  sudo -u bob sh -c "mv $HOME/.local/share/uv/tools/phiward /tmp/moved" 2>/dev/null \
    && fail "bob moved phiward's tool folder"
  sudo -u bob sh -c "echo 'import os' > $site/evil.pth" 2>/dev/null \
    && fail "bob planted a .pth"
  phiward doctor > /tmp/doctor5.out 2>&1
  grep -q WARNING /tmp/doctor5.out && fail "doctor after the attack" /tmp/doctor5.out ;;
old-settings)
  # an allowWrite inside ~/.phiward (an older phiward's spool): the refusal names its file
  python3 /qs/allow.py ~/.claude/settings.json
  python3 /qs/hook.py ~/proj > /tmp/hook1.out 2>&1
  grep -q "~/.claude/settings.json" /tmp/hook1.out || fail "the refusal does not name the user file" /tmp/hook1.out
  python3 /qs/allow.py ~/.claude/settings.json remove
  mkdir -p ~/proj/.claude && python3 /qs/allow.py ~/proj/.claude/settings.local.json
  python3 /qs/hook.py ~/proj > /tmp/hook2.out 2>&1
  grep -q ".claude/settings.local.json" /tmp/hook2.out || fail "the refusal does not name the project file" /tmp/hook2.out ;;
esac
echo "ok: setup, doctor, wrap, list, the wrapped server, the hook, doctor again, $SCENARIO ($INSTALLER, $(id -gn) group, umask $(umask))"
