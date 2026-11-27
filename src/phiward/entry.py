"""Start phiward from this file: `<python> -I -S <PKG>/phiward/entry.py ARGS...`.

The hooks under `phiward launch` run this way: no inline code, no site start (`-S`: no `.pth`
file runs, and the start is quick), and the folder above the package first on `sys.path`, so a
source checkout works under PHIWARD_DEV=1 too. When phiward's code cannot be loaded, it exits 2,
which blocks the tool call or the prompt.
"""

import os
import sys


def _start() -> int:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from phiward.cli import main
    except Exception as exc:  # a moved or broken package: a refusal, never a pass
        # the words of core.REWIRE_STEP (phiward's code cannot be loaded here)
        sys.stderr.write(f"phiward: its code cannot be loaded ({type(exc).__name__}); every "
                         "tool call is refused: ask the operator to reinstall phiward or to run "
                         "`(cd ~ && phiward install claude --user --write)` in their own "
                         "terminal\n")
        return 2
    return main()


if __name__ == "__main__":
    sys.exit(_start())
