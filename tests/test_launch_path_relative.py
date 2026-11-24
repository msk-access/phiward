"""An empty PATH entry (a leading or trailing `:`, or `::`) means the folder the shell stands in,
and `.` or another relative entry is resolved against it. launch runs the tool in the project,
and the operator's own shell stands in the project or a folder of it after the session: there,
such an entry names a folder of the project, and a program the session wrote there runs later.
Which folder a later command stands in cannot be known (a subfolder turns `../bin` into the
project's `bin`), so launch refuses every empty or relative entry, fail-closed, and its step says
to remove it. An absolute entry outside the project is not refused. Made-up trees only."""

import os

import pytest

from phiward import config, doctor, wholetool

RELATIVE = [":/usr/bin", "/usr/bin:", "/usr/bin::/bin", ".:/usr/bin", "bin:/usr/bin",
            "../elsewhere/bin:/usr/bin", ""]


def _env(path):
    env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}
    env["PATH"] = path
    return env


def _refusal(tree, env):
    with pytest.raises(wholetool.LaunchError) as exc:
        wholetool.build(["/bin/echo", "x"], str(tree / "repo"), env, wholetool.ADAPTERS["generic"])
    return str(exc.value)


@pytest.mark.parametrize("path", RELATIVE)
def test_an_empty_or_relative_entry_is_found(tree, path):
    (tree / "repo" / "bin").mkdir(parents=True, exist_ok=True)
    proj = os.path.realpath(tree / "repo")
    assert wholetool._path_entry_inside(proj, _env(path)), path


@pytest.mark.parametrize("path", RELATIVE)
def test_launch_refuses_an_empty_or_relative_entry_and_says_to_remove_it(tree, path):
    msg = _refusal(tree, _env(path))
    assert "empty or relative" in msg and "remove" in msg.lower(), msg
    assert "deactivate" not in msg, msg


def test_doctor_warns_about_an_empty_entry(tree):
    project = str(tree / "repo")
    out = "\n".join(doctor.launch_report(project, str(tree / "home"), config.load(project),
                                         env=_env("/usr/bin::/bin"), platform="darwin",
                                         version=(2, 1, 300), installed=True))
    assert "WARNING" in out and "empty or relative" in out, out


def test_a_write_to_folder_refuses_an_empty_entry(tree):
    other = tree / "other"
    other.mkdir()
    cfg = config.load(str(tree / "repo"))
    assert wholetool.launch_write_problem(str(other), cfg, _env("/usr/bin:")) == \
        wholetool.PATH_INSIDE


def test_an_absolute_entry_outside_the_project_is_not_refused(tree):
    (tree / "sys" / "bin").mkdir(parents=True)
    proj = os.path.realpath(tree / "repo")
    assert wholetool._path_entry_inside(proj, _env(f"{tree}/sys/bin:/usr/bin:/bin")) == ""
