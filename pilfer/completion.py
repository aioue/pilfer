"""pilfer completion: print or install a bash or zsh completion script.

The script comes from shtab, which reads pilfer's argparse parser, so it
completes commands, options and file paths. It never completes key names:
that would mean decrypting every vault on each Tab.
"""

import os
import subprocess
from pathlib import Path

from pilfer.errors import PilferError

SHELLS = ("bash", "zsh")
_ZSH_FPATH_NOTE = "Add this line above 'compinit' in ~/.zshrc:\n  fpath=(~/.zfunc $fpath)"


def mark_file(action) -> None:
    """Have the completion script offer file paths for this argument."""
    try:
        import shtab
    except ImportError:  # a checkout without the dependency still runs
        return
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


def _zsh_fpath_dir(home: Path):
    """First writable directory under home on zsh's fpath, or None.

    Asks an interactive zsh because fpath is usually built in ~/.zshrc. Its
    other output (prompts, banners) is ignored, and any failure falls back.
    """
    try:
        probe = subprocess.run(
            ["zsh", "-ic", "print -l $fpath"],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for line in probe.stdout.splitlines():
        path = Path(line.strip())
        under_home = path.is_absolute() and path.is_relative_to(home)
        if under_home and path.is_dir() and os.access(path, os.W_OK):
            return path
    return None


def _install(shell: str, script: str) -> int:
    home = Path.home()
    note = ""
    if shell == "bash":
        data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local" / "share")
        target = data / "bash-completion" / "completions" / "pilfer"
    else:
        found = _zsh_fpath_dir(home)
        target = (found or home / ".zfunc") / "_pilfer"
        note = "" if found else _ZSH_FPATH_NOTE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(script, encoding="utf-8")
    print(f"Wrote {target}")
    if note:
        print(note)
    print("Open a new shell to use it.")
    return 0


def run_completion(args, parser) -> int:
    import shtab

    shell = _resolve_shell(args.shell)
    script = shtab.complete(parser, shell=shell)
    if args.install:
        return _install(shell, script)
    print(script)
    return 0
