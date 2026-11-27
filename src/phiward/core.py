"""The normalized action, the decision, and the dispatcher that runs every enabled guard."""

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

# The step for a config problem. Its reader is the agent (a hook, `run` or `copy` refusal) or the
# operator (doctor, install, a git hook run by hand); only the operator can run doctor.
DOCTOR_STEP = "the operator runs `phiward doctor` in their own terminal"
# The step when the hook itself cannot run: every tool call is refused, so the agent can fix
# nothing. `fasthook` and `entry` load no phiward code and hold the same words. The command is
# claude_settings.INSTALL_STEP's (core cannot import claude_settings: a cycle).
REWIRE_STEP = ("ask the operator to reinstall phiward or to run "
               "`(cd ~ && phiward install claude --user --write)` in their own terminal")

# Kinds of action an adapter can report.
SHELL = "shell"
FILE_READ = "file_read"
FILE_SEARCH = "file_search"
FILE_WRITE = "file_write"
OTHER = "other"  # any other tool (MCP and the like): only its text is checked

ALLOW, ASK, DENY = "allow", "ask", "deny"
_RANK = {ALLOW: 0, ASK: 1, DENY: 2}


@dataclass(frozen=True)
class Action:
    """What an agent tool is about to do, in a form every guard understands.

    `paths` are the paths a file tool names, as given (the guard resolves them against `cwd`).
    `text` is every other string in the tool's input, for tools the core does not know.
    """

    kind: str
    cwd: str
    command: str = ""
    paths: Tuple[str, ...] = ()
    text: Tuple[str, ...] = ()
    tool: str = ""
    # Whether the tool can show an "ask" prompt to the operator for this action. An adapter
    # sets it False when the tool has no ask reply or runs in a mode that skips prompts.
    can_ask: bool = True
    # Whether the tool's shell commands run with the protected roots denied by the kernel
    # (Claude Code's sandbox). The shell text guard then refuses less: the kernel is the
    # boundary. File tools are never covered by a shell sandbox.
    confined: bool = False
    # why the shell is not confined, as the confinement check says it (the refusal names it)
    unconfined_why: str = ""
    unconfined_step: str = ""
    # a shell call that is not confined only because `sandbox.excludedCommands` is not empty:
    # it gets the text check of an unsandboxed call (as with `[shell] best_effort`), not the
    # blanket refusal (unconfined_why and unconfined_step then name the entry's file and step)
    text_checked: bool = False
    # For a shell tool other than Bash and Monitor: why its input is not the one exact form of
    # a command (adapters/claude.exact_command), or "" when it is
    shape: str = ""
    # an MCP tool of a remote server (it runs nothing on this machine): only its text is checked
    remote: bool = False
    # an app tool that starts the project's own code outside the sandbox (the preview server, a
    # build): what it starts, for the prompt or the refusal; "" for any other tool
    starts: str = ""
    # paths a tool names by its path fields (`adapters/claude._named_paths`): judged as a
    # search, in addition to every other check of the action (it can only add a refusal)
    searches: Tuple[str, ...] = ()
    # For such a tool: what the refusal tells the agent to do instead (it depends on the server)
    advice: str = ""
    # Claude Code's own payload (not Copilot's): its file tools' writes are held to the folders
    # its sandbox lets the shell write
    claude_code: bool = False


@dataclass(frozen=True)
class Decision:
    verdict: str
    reason: str = ""
    guard: str = ""

    @property
    def allowed(self) -> bool:
        return self.verdict == ALLOW


ALLOWED = Decision(ALLOW)

Guard = Callable[[Action, "object"], Decision]


def strictest(decisions: List[Decision]) -> Decision:
    """The strictest of several decisions: deny over ask over allow. The first one wins a tie."""
    best: Optional[Decision] = None
    for d in decisions:
        if best is None or _RANK[d.verdict] > _RANK[best.verdict]:
            best = d
    return best or ALLOWED


def settle(decision: Decision, action: Action) -> Decision:
    """An ask the tool cannot show becomes a deny, so it never turns into a silent allow."""
    if decision.verdict == ASK and not action.can_ask:
        return Decision(DENY, decision.reason + " (This tool cannot ask here, so it is refused.)",
                        decision.guard)
    return decision


def dispatch(action: Action, config, guards: Dict[str, Guard]) -> Decision:
    """Run every guard on the action and return the strictest decision.

    A guard that raises denies the action (fail closed): a bug must not open a hole.
    """
    results = []
    for name, guard in guards.items():
        try:
            d = guard(action, config)
        except Exception as exc:  # noqa: BLE001 - fail closed on any fault
            d = Decision(DENY, f"The guard '{name}' failed ({type(exc).__name__}), so the action "
                         "is refused. Report this as a bug.", name)
        results.append(d)
    return settle(strictest(results), action)
