"""pilfer find-keys, update and nested set paths: key names only, never values."""

import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_vault_set import PASSWORD, VaultSetBase, _vault

from pilfer.cli import PilferError, main
from pilfer.key_paths import parse_key_path, render_key_path
from pilfer.vault_set import set_keys

SECRETS = ("sv-one-do-not-print", "sv-two-do-not-print", "sv-three-do-not-print")
NESTED = (
    "# keep this comment\n"
    "aws:\n"
    "  prod:\n"
    f"    secret_key: {SECRETS[0]}  # prod note\n"
    "    region: eu-west-1\n"
    "users:\n"
    "  - name: alice\n"
    f"    password: {SECRETS[1]}\n"
    "  - name: bob\n"
    f"    password: {SECRETS[2]}\n"
    "tail: done\n"
)
INLINE_SECRET = "inline-secret-do-not-print"


class FindKeysBase(VaultSetBase):
    def setUp(self) -> None:
        super().setUp()
        self.vault = self._encrypt(NESTED)
        self.before = self.vault.read_bytes()

    def _inline(self, name: str = "inline.yml", label: str | None = "prod") -> Path:
        secret = VaultSecret(PASSWORD.encode())
        cipher = VaultLib([]).encrypt(INLINE_SECRET.encode(), secret=secret, vault_id=label)
        body = "".join(f"          {line}\n" for line in cipher.decode().splitlines())
        path = self.directory / name
        path.write_text(f"plain: visible\napi:\n  token: !vault |\n{body}", encoding="utf-8")
        return path

    def _main(self, *argv: str):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([*argv])
        return code, out.getvalue(), err.getvalue()

    def _find(self, *args: str):
        return self._main("find-keys", "-p", str(self.password), *args)

    def _plain(self, path: Path | None = None) -> dict:
        return yaml.safe_load(_vault().decrypt((path or self.vault).read_bytes()))


class TestKeyPaths(unittest.TestCase):
    def test_parse_and_render_round_trip(self) -> None:
        for text, path in (
            ("a", ["a"]),
            ("aws.prod.secret_key", ["aws", "prod", "secret_key"]),
            ("users[0].password", ["users", 0, "password"]),
            ("aws['key.with.dots']", ["aws", "key.with.dots"]),
            ('aws["it\'s"]', ["aws", "it's"]),
        ):
            with self.subTest(text=text):
                self.assertEqual(parse_key_path(text), path)
                self.assertEqual(parse_key_path(render_key_path(path)), path)

    def test_bad_paths_are_refused_without_echoing_them(self) -> None:
        for text in ("", "a..b", "1a", "a[", "a['x'", "[0]", "a b", "a.b-c"):
            with self.subTest(text=text), self.assertRaises(PilferError) as caught:
                parse_key_path(text)
            if text:
                self.assertNotIn(text, str(caught.exception))


class TestFindKeys(FindKeysBase):
    def test_lists_paths_and_never_prints_values(self) -> None:
        self._encrypt('"odd.key": ' + SECRETS[0] + "\n", "odd.yml")
        for extra in ((), ("--json",), ("-l",)):
            with self.subTest(extra=extra):
                code, out, err = self._find(*extra)
                self.assertEqual(code, 0, err)
                for secret in (*SECRETS, INLINE_SECRET):
                    self.assertNotIn(secret, out + err)
        code, out, _ = self._find()
        lines = out.splitlines()
        self.assertIn("secrets.yml: aws.prod.secret_key", lines)
        self.assertIn("secrets.yml: users[1].password", lines)
        self.assertIn("odd.yml: ['odd.key']", lines)

    def test_matching_rules(self) -> None:
        def paths(*args: str) -> list[str]:
            code, out, _ = self._find(*args)
            self.assertIn(code, (0, 1))
            return [line.split(": ", 1)[1] for line in out.splitlines()]

        self.assertEqual(paths("secret_key"), ["aws.prod.secret_key"])
        self.assertEqual(paths("secret"), [])  # a plain word is an exact match
        self.assertEqual(paths("*_key"), ["aws.prod.secret_key"])
        self.assertEqual(paths("SECRET_KEY"), [])
        self.assertEqual(paths("-i", "SECRET_KEY"), ["aws.prod.secret_key"])
        self.assertEqual(paths("-E", "ecret"), ["aws.prod.secret_key"])
        self.assertEqual(sorted(paths("tail", "region")), ["aws.prod.region", "tail"])
        self.assertEqual(
            paths("--path", "aws.*"), ["aws.prod", "aws.prod.region", "aws.prod.secret_key"]
        )
        self.assertEqual(len(paths()), 10)  # no pattern: every key

    def test_exit_status(self) -> None:
        self.assertEqual(self._find("nonexistent")[0], 1)
        code, _, err = self._find("-E", "(")
        self.assertEqual(code, 2)
        self.assertIn("regular expression", err)

    def test_json_lines(self) -> None:
        code, out, _ = self._find("--json", "password")
        self.assertEqual(code, 0)
        records = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(
            [r["path"] for r in records], [["users", 0, "password"], ["users", 1, "password"]]
        )
        first = records[0]
        self.assertEqual(set(first), {"file", "key", "path", "kind", "open", "vault_id"})
        self.assertEqual(
            (first["file"], first["key"], first["kind"], first["open"]),
            ("secrets.yml", "password", "file", False),
        )

    def test_files_with_matches(self) -> None:
        self._encrypt("password: x\n", "other.yml")
        code, out, _ = self._find("-l", "password")
        self.assertEqual((code, out.splitlines()), (0, ["other.yml", "secrets.yml"]))

    def test_inline_values_need_the_flag(self) -> None:
        self._inline()
        self.assertEqual(self._find("token")[0], 1)
        code, out, err = self._find("--include-encrypted-vars", "--json", "token")
        self.assertEqual(code, 0, err)
        record = json.loads(out)
        self.assertEqual(
            (record["kind"], record["path"], record["vault_id"]),
            ("inline", ["api", "token"], "prod"),
        )
        self.assertNotIn(INLINE_SECRET, out + err)
        _, out, _ = self._find("--include-encrypted-vars", "token")
        self.assertEqual(out.strip(), "inline.yml: api.token  (inline)")

    def test_open_session_reads_plaintext_and_tags_open(self) -> None:
        self._inline()
        code, _, err = self._main("open", "-p", str(self.password), "--include-encrypted-vars")
        self.assertEqual(code, 0, err)
        code, out, err = self._find("--include-encrypted-vars", "--json")
        self.assertEqual(code, 0, err)
        records = [json.loads(line) for line in out.splitlines()]
        self.assertTrue(all(r["open"] for r in records))
        by_path = {tuple(r["path"]): r for r in records}
        self.assertEqual(by_path[("api", "token")]["kind"], "inline")
        self.assertEqual(by_path[("api", "token")]["vault_id"], "prod")
        self.assertEqual(by_path[("aws", "prod", "secret_key")]["kind"], "file")
        _, text, _ = self._find("secret_key")
        self.assertEqual(text.strip(), "secrets.yml: aws.prod.secret_key  (open)")
        self.assertEqual(self._main("close", "-p", str(self.password))[0], 0)


class TestNestedSet(FindKeysBase):
    def test_replaces_nested_and_indexed_values_keeping_comments(self) -> None:
        set_keys(
            self.vault,
            {"aws.prod.secret_key": "new1", "users[1].password": "new2"},
            str(self.password),
        )
        data = self._plain()
        self.assertEqual(data["aws"]["prod"]["secret_key"], "new1")
        self.assertEqual(data["users"][1]["password"], "new2")
        self.assertEqual(data["users"][0]["password"], SECRETS[1])
        text = _vault().decrypt(self.vault.read_bytes()).decode()
        self.assertIn("# keep this comment", text)
        self.assertIn("# prod note", text)

    def test_creates_missing_mappings(self) -> None:
        actions = set_keys(
            self.vault,
            {
                "aws.staging.key": "k1",
                "aws.prod.extra": "k2",
                "fresh.a.b": "k3",
                "aws['x.y']": "k4",
            },
            str(self.password),
        )
        self.assertEqual(set(actions.values()), {"added"})
        data = self._plain()
        self.assertEqual(data["aws"]["staging"], {"key": "k1"})
        self.assertEqual(data["aws"]["prod"]["extra"], "k2")
        self.assertEqual(data["fresh"], {"a": {"b": "k3"}})
        self.assertEqual(data["aws"]["x.y"], "k4")
        self.assertEqual(data["tail"], "done")

    def test_refusals_leave_the_file_alone(self) -> None:
        for key in (
            "tail.child",  # parent is a scalar
            "users.name",  # parent is a list
            "aws[0]",  # parent is a mapping
            "users[5].password",  # index out of range
            "aws.prod",  # target is a mapping, not a scalar
            "users[7]",
            "fresh[0].x",  # would need a new list
        ):
            with self.subTest(key=key), self.assertRaises(PilferError) as caught:
                set_keys(self.vault, {key: "v"}, str(self.password))
            self.assertNotIn("sv-", str(caught.exception))
        self.assertEqual(self._plain()["users"][0]["password"], SECRETS[1])

    def test_top_level_names_must_be_identifiers(self) -> None:
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"['a.b']": "v"}, str(self.password))

    def test_create_false_refuses_a_missing_key(self) -> None:
        with self.assertRaises(PilferError):
            set_keys(self.vault, {"aws.prod.nope": "v"}, str(self.password), create=False)
        self.assertEqual(
            set_keys(self.vault, {"tail": "x"}, str(self.password), create=False),
            {"tail": "updated"},
        )


class TestUpdate(FindKeysBase):
    def _update(self, *args: str):
        return self._main("update", "-p", str(self.password), *args)

    def test_updates_the_one_file_that_has_the_key(self) -> None:
        self._encrypt("other: 1\n", "other.yml")
        code, out, err = self._update("aws.prod.secret_key", "brand-new-value")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines()[0], "updated aws.prod.secret_key in secrets.yml")
        self.assertNotIn("brand-new-value", out + err)
        self.assertEqual(self._plain()["aws"]["prod"]["secret_key"], "brand-new-value")

    def test_value_from_stdin(self) -> None:
        stdin = io.TextIOWrapper(io.BytesIO(b"from-stdin\n"))
        original = sys.stdin
        sys.stdin = stdin
        self.addCleanup(setattr, sys, "stdin", original)
        self.assertEqual(self._update("tail")[0], 0)
        self.assertEqual(self._plain()["tail"], "from-stdin")

    def test_missing_key_points_to_set(self) -> None:
        code, _, err = self._update("nope.key", "v")
        self.assertEqual(code, 1)
        self.assertIn("pilfer set FILE nope.key", err)
        self._assert_untouched()

    def test_ambiguous_key_lists_files_and_file_picks_one(self) -> None:
        other = self._encrypt("tail: other\n", "other.yml")
        code, _, err = self._update("tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("--file", err)
        self.assertIn("secrets.yml", err)
        self.assertIn("other.yml", err)
        self.assertEqual(self._plain()["tail"], "done")
        code, _, err = self._update("--file", "other.yml", "tail", "v")
        self.assertEqual(code, 0, err)
        self.assertEqual(self._plain(other)["tail"], "v")
        self.assertEqual(self._plain()["tail"], "done")

    def test_inline_needs_the_flag_and_keeps_its_label(self) -> None:
        inline = self._inline()
        before = inline.read_bytes()
        code, _, err = self._update("api.token", "v")
        self.assertEqual(code, 1)
        self.assertIn("--include-encrypted-vars", err)
        self.assertEqual(inline.read_bytes(), before)
        code, out, err = self._update("--include-encrypted-vars", "api.token", "inline-new")
        self.assertEqual(code, 0, err)
        self.assertNotIn("inline-new", out + err)
        after = inline.read_bytes()
        self.assertIn(b"$ANSIBLE_VAULT;1.2;AES256;prod", after)
        self.assertTrue(after.startswith(b"plain: visible\napi:\n  token: !vault |\n"))
        loaded = yaml.load(after, Loader=_VaultLoader)
        self.assertEqual(_vault().decrypt(loaded["api"]["token"].encode()).decode(), "inline-new")

    def test_refuses_a_file_open_in_a_session(self) -> None:
        self.assertEqual(self._main("open", "-p", str(self.password))[0], 0)
        code, _, err = self._update("tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("open in a pilfer session", err)
        self.assertEqual(self._main("close", "-p", str(self.password))[0], 0)


class _VaultLoader(yaml.SafeLoader):
    pass


_VaultLoader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))

if __name__ == "__main__":
    unittest.main()
