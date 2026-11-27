"""pilfer find-keys, update and nested set paths: key names only, never values."""

import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_vault_set import PASSWORD, VaultSetBase, _vault

from pilfer import cli
from pilfer.cli import PilferError, main
from pilfer.key_paths import parse_key_path, render_key_path, walk_keys
from pilfer.vault_set import DRY_RUN_UNCHECKED, set_keys

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

    def _session(self, *entries: dict) -> None:
        Path(cli.temp_vault_file_list_path).write_text(
            json.dumps({"version": cli.SESSION_VERSION, "entries": list(entries)}),
            encoding="utf-8",
        )

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
            ("['']", [""]),  # what render_key_path prints for an empty key
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


class TestWalkKeys(unittest.TestCase):
    @staticmethod
    def _paths(text: str) -> list:
        return [found.path for found in walk_keys(yaml.compose(text))]

    def test_merge_keys_are_skipped_and_anchor_keys_listed_where_defined(self) -> None:
        paths = self._paths("base: &b {secret: x}\nc:\n  <<: *b\n  own: 1\n")
        self.assertEqual(paths, [["base"], ["base", "secret"], ["c"], ["c", "own"]])

    def test_repeated_keys_are_all_listed_and_compared_by_text(self) -> None:
        self.assertEqual(self._paths("tok: a\ntok: !vault x\n"), [["tok"], ["tok"]])
        self.assertEqual(self._paths("yes: 1\ntrue: 2\n"), [["yes"], ["true"]])

    def test_an_alias_is_walked_once_so_a_loop_or_a_bomb_ends(self) -> None:
        self.assertEqual(self._paths("a: &a [*a]\n"), [["a"]])
        bomb = ["a0: &a0 [{k: v}]"] + [f"a{n}: &a{n} [*a{n - 1}, *a{n - 1}]" for n in range(1, 31)]
        self.assertEqual(len(self._paths("\n".join(bomb) + "\n")), 32)


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
            (first["file"], first["key"], first["kind"], first["open"], first["vault_id"]),
            ("secrets.yml", "password", "file", False, "default"),
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
        for secret in (*SECRETS, INLINE_SECRET):
            self.assertNotIn(secret, out + err)
        records = [json.loads(line) for line in out.splitlines()]
        self.assertTrue(all(r["open"] for r in records))
        by_path = {tuple(r["path"]): r for r in records}
        self.assertEqual(by_path[("api", "token")]["kind"], "inline")
        self.assertEqual(by_path[("api", "token")]["vault_id"], "prod")
        self.assertEqual(by_path[("aws", "prod", "secret_key")]["kind"], "file")
        _, text, terr = self._find("--include-encrypted-vars")
        for secret in (*SECRETS, INLINE_SECRET):
            self.assertNotIn(secret, text + terr)
        _, text, _ = self._find("secret_key")
        self.assertRegex(text.strip(), r"^secrets\.yml:\s+aws\.prod\.secret_key\s+\(open\)$")
        self.assertEqual(self._main("close", "-p", str(self.password))[0], 0)


class TestFindKeysHardening(FindKeysBase):
    def test_planted_session_symlink_inside_the_project_is_not_followed(self) -> None:
        target = self.directory / "real.yml"
        target.write_text("inside_secret_name: x\n", encoding="utf-8")
        evil = self.directory / "evil.yml"
        evil.symlink_to(target)
        Path(str(evil) + cli.OPEN_SIDECAR_SUFFIX).write_text("{}", encoding="utf-8")
        self._session({"kind": "file", "path": str(evil)})
        code, out, err = self._find()
        self.assertEqual(code, 2)
        self.assertNotIn("inside_secret_name", out + err)

    def test_oversized_file_keeps_its_marker_and_is_reported_too_large(self) -> None:
        limit = 2**20
        big = (self.directory / "big.yml").resolve()
        big.write_bytes(cli.MARKER_PREFIX.encode() + b"x" * limit)
        with mock.patch.object(cli, "MAX_READ_BYTES", limit):
            scan = cli.scan_project(announce_skips=False)
            code, _, err = self._find("tail")
        self.assertIn(str(big), scan.marker_files)
        self.assertNotIn(str(big), [t["path"] for t in scan.targets])
        self.assertIn((str(big), "too large (over 1 MiB)"), scan.unreadable)
        self.assertEqual(code, 2)
        self.assertIn("big.yml: too large (over 1 MiB)", err)

    def test_oversized_non_vault_without_marker_is_skipped_silently(self) -> None:
        for name in ("big.log", "big.json", "big.csv", "big"):
            (self.directory / name).write_bytes(b"x" * (2**20 + 1))
        with mock.patch.object(cli, "MAX_READ_BYTES", 2**20):
            scan = cli.scan_project(announce_skips=False)
            code, _, err = self._find("tail")
        self.assertEqual((scan.unreadable, scan.unreadable_other), ([], []))
        self.assertEqual(code, 0, err)
        self.assertNotIn("too large", err)

    def test_skipped_vault_values_are_listed_in_path_order(self) -> None:
        paths = [str(self.directory / f"{name}.yml") for name in "fedcbag"]
        scan = cli.ProjectScan(skipped_vault_values=[(path, 1) for path in paths])
        text = cli._describe_skipped_vault_values(scan)
        positions = [text.index(f"{name}.yml (1)") for name in "abcde"]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("f.yml", text)
        self.assertNotIn("g.yml", text)

    def test_whole_file_vault_with_a_tab_comment_lists_its_keys(self) -> None:
        # Ansible reads `5432<TAB># default`; PyYAML rejects it. Listing is read-only.
        self._encrypt("db_port: 5432\t# default\nother: 1\n", "tabbed.yml")
        code, out, err = self._find("db_port")
        self.assertEqual(code, 0, err)
        self.assertIn("db_port", out)

    def test_inline_file_with_a_tab_comment_lists_its_keys(self) -> None:
        inline = self._inline("tabbed_inline.yml")
        inline.write_text(
            "port: 80\t# http\n" + inline.read_text(encoding="utf-8"), encoding="utf-8"
        )
        code, out, err = self._find("--include-encrypted-vars", "token")
        self.assertEqual(code, 0, err)
        self.assertIn("token", out)

    def test_a_non_yaml_file_does_not_hide_the_rest(self) -> None:
        self._encrypt("\x00\x01 not yaml \x02" * 20, "blob.yml")
        code, out, err = self._find("tail")
        self.assertIn("secrets.yml: tail", out)
        self.assertEqual(code, 2, err)
        self.assertIn("does not parse as YAML", err)

    def test_malformed_envelope_is_reported_as_format_error(self) -> None:
        (self.directory / "bad.yml").write_bytes(b"$ANSIBLE_VAULT;1.1\nzz\n")
        _code, _out, err = self._find("tail")
        self.assertIn("vault format error (the file is damaged)", err)

    def test_corrupt_body_is_reported_as_format_error(self) -> None:
        (self.directory / "bad.yml").write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\nnot-hex!\n")
        _code, _out, err = self._find("tail")
        self.assertIn("vault format error (the file is damaged)", err)
        self.assertNotIn("could not decrypt with this vault password", err)

    def test_find_keys_notes_unsupported_vault_values(self) -> None:
        (self.directory / "odd.yml").write_text(
            "k: !vault |-\n  $ANSIBLE_VAULT;1.1;AES256\n  3030\n", encoding="utf-8"
        )
        _, _, err = self._find("--include-encrypted-vars", "tail")
        self.assertIn("pilfer: warning: 1 !vault value(s)", err)
        self.assertIn("odd.yml (1)", err)
        self.assertIn("their keys are not searched", err)

    def test_prompt_without_a_terminal_is_refused_once(self) -> None:
        (self.directory / "second.yml").write_bytes(self.before)
        for argv in (("find-keys", "-J"), ("update", "-J", "tail", "v")):
            with self.subTest(argv=argv[0]):
                with mock.patch("pilfer.vault_secrets._can_prompt", return_value=False):
                    code, _, err = self._main(*argv)
                self.assertEqual(code, 2 if argv[0] == "find-keys" else 1)
                self.assertEqual(err.count("asks for the password on a terminal"), 1, err)
                self.assertNotIn("not found", err)
                self.assertNotIn("no key matched", err)

    def test_fifo_does_not_block_the_scan(self) -> None:
        os.mkfifo(self.directory / "pipe.yml")
        self._guard()
        code, out, err = self._find("tail")
        self.assertEqual(code, 0, err)
        self.assertIn("secrets.yml", out)

    def test_text_output_escapes_control_characters(self) -> None:
        self._encrypt('"a\\e[31mb": 1\n', "we\x1bird.yml")
        code, out, err = self._find()
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)
        code, out, _ = self._find("--json", "-E", "mb$")
        self.assertIn("\\u001b", out)  # JSON keeps its own escaping

    def test_safe_text_escapes_what_is_not_printable(self) -> None:
        for raw, escaped in (("\x1b", "\\x1b"), ("\n", "\\n"), ("\u202e", "\\u202e")):
            with self.subTest(raw=raw):
                self.assertEqual(cli.safe_text(f"a{raw}b"), f"a{escaped}b")
        self.assertEqual(cli.safe_text("caf\u00e9 \u65e5\u672c"), "caf\u00e9 \u65e5\u672c")

    def test_path_match_treats_brackets_literally(self) -> None:
        code, out, err = self._find("--path", "users[0].password")
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("users[0].password", out)

    def test_unreadable_vault_file_is_an_error(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        blocked = self._encrypt("x: 1\n", "blocked.yml")
        blocked.chmod(0)
        try:
            code, _, err = self._find("tail")
        finally:
            blocked.chmod(0o600)
        self.assertEqual(code, 2)
        self.assertIn("blocked.yml: Permission denied", err)

    def test_wrong_password_names_the_file_once(self) -> None:
        self._encrypt("other: 1\n", "other.yml")
        wrong = self._password_file("wrong", "not-the-password")
        code, _, err = self._main("find-keys", "-p", str(wrong))
        self.assertEqual(code, 2)
        self.assertEqual(err.count("secrets.yml"), 1, err)
        self.assertEqual(err.count("other.yml"), 1, err)

    def test_decrypt_failure_names_the_vault_id(self) -> None:
        secret = VaultSecret(PASSWORD.encode())
        cipher = VaultLib([]).encrypt(b"x: 1\n", secret=secret, vault_id="prod")
        (self.directory / "labelled.yml").write_bytes(cipher)
        wrong = self._password_file("wrong", "not-the-password")
        code, _, err = self._main("find-keys", "-p", str(wrong))
        self.assertEqual(code, 2)
        self.assertIn(
            "could not decrypt with the loaded vault passwords (file uses vault id 'prod')", err
        )

    def test_files_with_matches_and_json_are_exclusive(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self._find("-l", "--json")


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
            self._assert_untouched()

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

    def test_dry_run_with_the_stored_value_says_unchanged(self) -> None:
        code, out, err = self._update("--dry-run", "tail", "done")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines()[0], "unchanged tail in secrets.yml")
        code, out, _ = self._update("--dry-run", "tail", "other")
        self.assertEqual(out.splitlines()[0], "would update tail in secrets.yml")

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
        self.assertIn("pilfer set FILE KEY", err)
        self._assert_untouched()

    def test_ambiguous_listing_is_capped_and_names_are_escaped(self) -> None:
        for number in range(7):
            self._encrypt("tail: other\n", f"o{number}.yml")
        self._encrypt("tail: other\n", "ev\nil.yml")
        code, _, err = self._update("tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("is in 9 files", err)
        self.assertIn("  ... and 4 more", err)
        lines = err.splitlines()
        start = next(i for i, line in enumerate(lines) if "is in 9 files" in line) + 1
        listed = []
        for line in lines[start:]:
            if not line.startswith("  "):
                break
            listed.append(line)
        self.assertEqual(len(listed), 6, err)
        self.assertNotIn("ev\nil", err)

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

    def test_oversized_file_is_a_failed_file(self) -> None:
        with mock.patch("pilfer.cli.MAX_READ_BYTES", 2**20):
            big = (self.directory / "big.yml").resolve()
            big.write_text("$ANSIBLE_VAULT;1.1;AES256\n" + "x" * 2**20, encoding="utf-8")
            code, _, err = self._find("tail")
            self.assertEqual(code, 2)
            self.assertIn("big.yml: too large", err)
            # open ignores unreadable files.
            self.assertEqual(self._main("open", "-p", str(self.password))[0], 0, err)

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


class TestUpdateHardening(FindKeysBase):
    def _update(self, *args: str):
        return self._main("update", "-p", str(self.password), *args)

    def _stdin(self, data: bytes) -> None:
        original = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(data))
        self.addCleanup(setattr, sys, "stdin", original)

    def test_file_that_failed_is_not_reported_as_not_found(self) -> None:
        other = self.directory / "other.yml"
        other.write_bytes(_vault("a-different-password").encrypt(b"tail: stale\n"))
        before = other.read_bytes()
        code, _, err = self._update("--file", "other.yml", "tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("other.yml could not be read (see above); nothing was changed", err)
        self.assertNotIn("not found", err)
        self.assertEqual(other.read_bytes(), before)

    def test_failing_password_script_runs_once_and_is_fatal(self) -> None:
        (self.directory / "second.yml").write_bytes(self.before)
        count = self.directory / "count"
        script = self.directory / "fail.sh"
        script.write_text(f"#!/bin/sh\necho x >> {count}\nexit 1\n", encoding="utf-8")
        script.chmod(0o700)
        before = self.vault.read_bytes()
        for argv in (("find-keys",), ("update", "tail", "v")):
            count.unlink(missing_ok=True)
            with self.subTest(argv=argv[0]):
                code, _, err = self._main(argv[0], "-p", str(script), *argv[1:])
                self.assertEqual(code, 2 if argv[0] == "find-keys" else 1, err)
                self.assertEqual(count.read_text().count("x"), 1, err)
                self.assertEqual(err.count("vault password:"), 1, err)
                self.assertNotIn("not found", err)
        self.assertEqual(self.vault.read_bytes(), before)

    def test_refuses_when_another_file_could_not_be_read(self) -> None:
        other = self.directory / "other.yml"
        other.write_bytes(_vault("a-different-password").encrypt(b"tail: stale\n"))
        other_before = other.read_bytes()
        code, _, err = self._update("tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("could not be read", err)
        self.assertIn("other.yml", err)
        self.assertIn("--file", err)
        self._assert_untouched()
        self.assertEqual(other.read_bytes(), other_before)
        self.assertEqual(self._update("--file", "secrets.yml", "tail", "v")[0], 0)

    def test_dry_run_checks_the_given_value(self) -> None:
        code, _, err = self._update("--dry-run", "tail", "")
        self.assertEqual(code, 1)
        self.assertIn("empty value", err)
        code, out, err = self._update("--dry-run", "tail", "fine")
        self.assertEqual(code, 0, err)
        self.assertNotIn("not checked", out)
        self._assert_untouched()
        with self._no_value_read():
            code, out, _ = self._update("--dry-run", "tail")
        self.assertEqual(code, 0)
        self.assertIn(DRY_RUN_UNCHECKED, out)
        self._assert_untouched()

    def test_stdin_crlf_is_stripped(self) -> None:
        self._stdin(b"v\r\n")
        self.assertEqual(self._update("tail")[0], 0)
        self.assertEqual(self._plain()["tail"], "v")


class _VaultLoader(yaml.SafeLoader):
    pass


_VaultLoader.add_constructor("!vault", lambda loader, node: loader.construct_scalar(node))

if __name__ == "__main__":
    unittest.main()
