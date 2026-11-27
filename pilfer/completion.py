"""pilfer completion: print or install a bash or zsh completion script.

The script comes from shtab, which reads pilfer's argparse parser, so it
completes commands, options and file paths. It never completes key names:
that would mean decrypting every vault on each Tab.
"""

import os
from pathlib import Path

import shtab

from pilfer.errors import PilferError
from pilfer.publish import write_atomic

SHELLS = ("bash", "zsh")
_ZSH_FPATH_NOTE = "Add this line above 'compinit' in ~/.zshrc:\n  fpath=(~/.zfunc $fpath)"


def mark_file(action) -> None:
    """Have the completion script offer file paths for this argument."""
    action.complete = shtab.FILE


def _resolve_shell(name):
    shell = name or os.path.basename(os.environ.get("SHELL", ""))
    if shell not in SHELLS:
        which = f"'{shell}'" if shell else "your shell"
        raise PilferError(
            f"completion supports {' and '.join(SHELLS)}, not {which}. "
            "Name one: pilfer completion bash"
        )
    return shell


def _install(shell: str, script: str) -> int:
    home = Path.home()
    note = ""
    if shell == "bash":
        data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
        target = data / "bash-completion" / "completions" / "pilfer"
    else:
        target = home / ".zfunc" / "_pilfer"
        note = _ZSH_FPATH_NOTE
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
        # A dangling symlink (or a file) where the directory should be, such as
        # a ~/.zfunc link whose target is gone.
        raise PilferError(
            f"cannot create {target.parent}: something that is not a directory is there"
        ) from None
    # write_atomic replaces the path itself, not what a symlink at it points to, and
    # refuses a symlink target; 0o644 so the shell can read it.
    write_atomic(target, script.encode("utf-8"), mode=0o644, action="completion install")
    print(f"Wrote {target}")
    if note:
        print(note)
    print("Open a new shell to use it.")
    return 0


def run_completion(args, parser) -> int:
    shell = _resolve_shell(args.shell)
    script = shtab.complete(parser, shell=shell)
    if args.install:
        return _install(shell, script)
    print(script)
    return 0
