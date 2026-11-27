"""pilfer agent-guide: prints the packaged SKILL.md, and the guide matches the real CLI."""

import argparse
import contextlib
import io
import os
import re
import sys
import unittest
from importlib import resources

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Before anything imports ansible: see _ansible_isolation.
import _ansible_isolation  # noqa: F401

from pilfer.cli import _build_argument_parser, main

GUIDE = resources.files("pilfer").joinpath("agent_guide", "SKILL.md").read_text(encoding="utf-8")


def _parsers():
    """The top-level parser and one parser per subcommand."""
    top = _build_argument_parser()
    subparsers = next(a for a in top._actions if isinstance(a, argparse._SubParsersAction))
    return top, dict(subparsers.choices)


def _body() -> str:
    return GUIDE.split("\n---\n", 1)[1]


def _code(text: str) -> str:
    """Fenced blocks and inline code spans: where the guide shows commands."""
    fenced = re.findall(r"```.*?\n(.*?)```", text, re.S)
    without = re.sub(r"```.*?```", "", text, flags=re.S)
    return "\n".join(fenced + re.findall(r"`([^`\n]+)`", without))


class AgentGuideTests(unittest.TestCase):
    def test_prints_the_packaged_file(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = main(["agent-guide"])
        self.assertEqual(status, 0)
        self.assertEqual(out.getvalue(), GUIDE)

    def test_frontmatter(self):
        import yaml

        self.assertTrue(GUIDE.startswith("---\n"))
        front = yaml.safe_load(GUIDE.split("\n---\n", 1)[0][4:])
        self.assertEqual(front["name"], "pilfer")
        description = front["description"]
        self.assertIsInstance(description, str)
        self.assertTrue(description.strip())
        self.assertLessEqual(len(description), 1024)

    def test_every_command_mentioned_exists(self):
        _, commands = _parsers()
        mentioned = set(re.findall(r"\bpilfer ([a-z][a-z-]*)", _code(_body())))
        self.assertTrue(mentioned)
        for name in mentioned:
            self.assertIn(name, commands, f"SKILL.md mentions 'pilfer {name}'")

    def test_every_flag_mentioned_exists(self):
        top, commands = _parsers()

        def options(parser):
            return {o for action in parser._actions for o in action.option_strings}

        everything = options(top).union(*(options(p) for p in commands.values()))
        flag_re = re.compile(r"(?<![\w-])--?[A-Za-z][\w-]*")
        checked = 0
        for line in _code(_body()).splitlines():
            flags = {m for m in flag_re.findall(line) if m.startswith("--") or len(m) == 2}
            # A line that starts `pilfer <cmd>` is checked against that command only.
            start = re.match(r"\s*pilfer ([a-z][a-z-]*)", line)
            known = (
                options(commands[start[1]]) | options(top)
                if start and start[1] in commands
                else everything
            )
            for flag in flags:
                checked += 1
                self.assertIn(flag, known, f"SKILL.md mentions {flag} in: {line.strip()}")
        self.assertTrue(checked)

    def test_guide_is_listed_for_completion(self):
        import shtab

        for shell in ("bash", "zsh"):
            self.assertIn("agent-guide", shtab.complete(_build_argument_parser(), shell=shell))


if __name__ == "__main__":
    unittest.main()
