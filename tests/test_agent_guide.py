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
        known = {
            option
            for parser in (top, *commands.values())
            for action in parser._actions
            for option in action.option_strings
        }
        mentioned = set(re.findall(r"(?<![\w-])--?[A-Za-z][\w-]*", _code(_body())))
        flags = {m for m in mentioned if m.startswith("--") or len(m) == 2}
        self.assertTrue(flags)
        for flag in flags:
            self.assertIn(flag, known, f"SKILL.md mentions {flag}")

    def test_guide_is_listed_for_completion(self):
        import shtab

        for shell in ("bash", "zsh"):
            self.assertIn("agent-guide", shtab.complete(_build_argument_parser(), shell=shell))


if __name__ == "__main__":
    unittest.main()
