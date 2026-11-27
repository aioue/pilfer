"""pilfer find-keys, update and nested set paths: key names only, never values."""

import contextlib
import io
import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import yaml
from ansible.parsing.vault import VaultLib, VaultSecret

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_vault_set import PASSWORD, VaultSetBase, _vault

from pilfer import cli, inline
from pilfer.cli import PilferError, main
from pilfer.find_keys import MAX_FAILURE_LINES
from pilfer.inline import TOO_LARGE_TO_PARSE
from pilfer.key_paths import parse_key_path, render_key_path, walk_keys
from pilfer.vault_set import DRY_RUN_UNCHECKED, MAX_STDIN_VALUE_BYTES, set_keys

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
    def test_merge_key_value_is_walked_without_yielding_the_merge_key(self) -> None:
        root = yaml.compose("c:\n  <<: &b {secret: x}\n  own: 1\n")
        paths = [found.path for found in walk_keys(root)]
        self.assertIn(["c", "secret"], paths)
        self.assertIn(["c", "own"], paths)
        self.assertNotIn(["c", "<<"], paths)

    def test_merge_semantics_follow_yaml(self) -> None:
        cases = {
            "sequence": (
                "c:\n  <<: [&a {x: 1}, &b {y: 1}]\n",
                [["c", "x"], ["c", "y"]],
            ),
            "own overrides merged": (
                "c:\n  k: own\n  <<: &b {k: {deep: 1}, m: 1}\n",
                [["c", "k"], ["c", "m"]],
            ),
            "inline mapping": ("c:\n  <<: {p: 1, q: 2}\n", [["c", "p"], ["c", "q"]]),
        }
        for name, (text, expected) in cases.items():
            with self.subTest(name):
                paths = [found.path for found in walk_keys(yaml.compose(text))]
                for path in expected:
                    self.assertEqual(paths.count(path), 1, paths)
                self.assertFalse(any(isinstance(p, int) for path in paths for p in path))
        paths = [f.path for f in walk_keys(yaml.compose(cases["own overrides merged"][0]))]
        self.assertNotIn(["c", "k", "deep"], paths)
        # An already-walked anchor is skipped: its keys are listed once, under base.
        paths = [f.path for f in walk_keys(yaml.compose("a: &a {x: 1}\nc:\n  <<: *a\n"))]
        self.assertIn(["a", "x"], paths)
        self.assertNotIn(["c", "x"], paths)


class TestWalkKeysMerges(unittest.TestCase):
    @staticmethod
    def _found(text: str) -> list:
        return list(walk_keys(yaml.compose(text)))

    def test_repeated_own_keys_are_all_listed(self) -> None:
        for text, expected in (
            ("tok: placeholder\ntok: !vault x\n", [["tok"], ["tok"]]),
            ("d: 1\nd: {x: 1}\n", [["d"], ["d"], ["d", "x"]]),
        ):
            with self.subTest(text=text):
                self.assertEqual([f.path for f in self._found(text)], expected)

    def test_a_key_from_several_merge_sources_is_listed_once(self) -> None:
        # Loaders disagree on which source wins, so only the count is asserted.
        for name, text in (
            ("sequence", "c:\n  <<: [{k: !vault x}, {k: plain}]\n"),
            ("separate keys", "c:\n  <<: {k: plain}\n  <<: {k: !vault x}\n"),
            ("transitive", "m:\n  <<: [{<<: {z: 1}, p: 1}, {z: 2}]\n"),
        ):
            with self.subTest(name):
                paths = [f.path for f in self._found(text)]
                for path in paths:
                    self.assertEqual(paths.count(path), 1, paths)
        paths = [f.path for f in self._found("m:\n  <<: [{<<: {z: 1}, p: 1}, {z: 2}]\n")]
        self.assertEqual(sorted(paths[1:]), [["m", "p"], ["m", "z"]])

    def test_many_merge_sources_do_not_go_quadratic(self) -> None:
        # Each source adds a name: copying the taken set per source took 69 s at 40k.
        count = 40_000
        anchors = ", ".join(f"&a{i} {{k{i}: 1}}" for i in range(count))
        merges = "".join(f"  <<: *a{i}\n" for i in range(count))
        text = f"? [{anchors}]\n: x\nc:\n{merges}"
        previous = signal.signal(signal.SIGALRM, lambda *_: self.fail("walk_keys is too slow"))
        self.addCleanup(signal.signal, signal.SIGALRM, previous)
        self.addCleanup(signal.alarm, 0)
        signal.alarm(30)
        found = self._found(text)
        self.assertEqual(len(found), count + 1)

    def test_custom_merge_tag_is_a_normal_key(self) -> None:
        found = self._found("c:\n  !x:merge <<: 1\n  own: 2\n")
        self.assertEqual([f.path for f in found], [["c"], ["c", "<<"], ["c", "own"]])

    def test_keys_are_compared_by_text(self) -> None:
        paths = [f.path for f in self._found("yes: 1\ntrue: 2\n")]
        self.assertEqual(paths, [["yes"], ["true"]])


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
    def test_planted_session_symlink_is_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "creds.yml"
            target.write_text("outside_secret_name: x\n", encoding="utf-8")
            evil = self.directory / "evil.yml"
            evil.symlink_to(target)
            Path(str(evil) + cli.OPEN_SIDECAR_SUFFIX).write_text("{}", encoding="utf-8")
            entries = [{"kind": "file", "path": str(evil)}]
            Path(cli.temp_vault_file_list_path).write_text(
                json.dumps({"version": cli.SESSION_VERSION, "entries": entries}), encoding="utf-8"
            )
            code, out, err = self._find()
        self.assertEqual(code, 2)
        self.assertNotIn("outside_secret_name", out + err)
        self.assertIn("outside the project", err)

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

    def test_session_entry_outside_the_project_is_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "creds.yml"
            target.write_text("outside_secret_name: x\n", encoding="utf-8")
            Path(str(target) + cli.OPEN_SIDECAR_SUFFIX).write_text("{}", encoding="utf-8")
            entries = [{"kind": "file", "path": str(target)}]
            Path(cli.temp_vault_file_list_path).write_text(
                json.dumps({"version": cli.SESSION_VERSION, "entries": entries}), encoding="utf-8"
            )
            code, out, err = self._find()
        self.assertEqual(code, 2)
        self.assertNotIn("outside_secret_name", out + err)

    def test_alias_bomb_finishes(self) -> None:
        lines = ["a0: &a0 [{k: v}]"]
        lines += [f"a{n}: &a{n} [*a{n - 1}, *a{n - 1}]" for n in range(1, 31)]
        self._encrypt("\n".join(lines) + "\n", "bomb.yml")
        self._guard()
        started = time.monotonic()
        code, out, err = self._find("-l", "k")
        self.assertEqual(code, 0, err)
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("bomb.yml", out)

    def test_could_hold_vault_by_name(self) -> None:
        for name, expected in (
            ("a.yml", True),
            ("a.YAML", True),
            ("a.json", True),
            ("all", True),
            (".vault.yml", True),
            (".env", False),
            (".hidden", False),
            ("key.pem", False),
            ("notes.txt", False),
        ):
            with self.subTest(name=name):
                self.assertEqual(cli._could_hold_vault(name), expected)

    def test_is_regular_file(self) -> None:
        self.assertTrue(cli._is_regular_file(str(self.vault)))
        self.assertFalse(cli._is_regular_file(str(self.directory)))
        self.assertFalse(cli._is_regular_file(str(self.directory / "missing")))
        link = self.directory / "link.yml"
        link.symlink_to(self.vault)
        self.assertFalse(cli._is_regular_file(str(link)))

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

    def test_oversized_file_is_skipped_by_size_without_reading(self) -> None:
        big = self.directory / "big.json"
        big.write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\n" + b"x" * (2**20 + 1))
        real_open = open

        def guarded(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            if str(path).endswith("big.json"):
                real_read = handle.read

                def read(size=-1):
                    # Chunks only, never the whole file.
                    if size is None or size < 0 or size > 1_048_576:
                        raise AssertionError("read")
                    return real_read(size)

                handle.read = read
            return handle

        with (
            mock.patch.object(cli, "MAX_READ_BYTES", 2**20),
            mock.patch("builtins.open", guarded),
        ):
            scan = cli.scan_project(announce_skips=False)
        self.assertIn((str(big.resolve()), "too large (over 1 MiB)"), scan.unreadable)

    def test_marker_split_across_chunks_is_found(self) -> None:
        marker = cli.MARKER_PREFIX.encode()
        chunk = 2**20
        for k in range(1, len(marker)):
            with self.subTest(bytes_before_boundary=k):
                data = b"x" * (chunk - k) + marker + b"y" * chunk
                self.assertEqual(cli._file_finds(io.BytesIO(data), [marker]), {marker})
        self.assertEqual(cli._file_finds(io.BytesIO(b"x" * (2 * chunk)), [marker]), set())

    def test_two_needles_are_found_in_one_pass_across_chunks(self) -> None:
        chunk = 2**20
        short, long = b"$ANSIBLE_VAULT;", cli.MARKER_PREFIX.encode()
        data = b"x" * (chunk - 3) + short + b"y" * (chunk - 5) + long + b"z"
        self.assertEqual(cli._file_finds(io.BytesIO(data), [short, long]), {short, long})

    def test_oversized_file_with_an_inline_vault_block_is_too_large(self) -> None:
        big = (self.directory / "big.yml").resolve()
        # The header is far from the start, so only the chunked search sees it.
        big.write_text("x: 1\n" * 2**18 + "key: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n")
        with mock.patch.object(cli, "MAX_READ_BYTES", 2**20):
            scan = cli.scan_project(announce_skips=False)
            code, _, err = self._find("tail")
        self.assertIn((str(big), "too large (over 1 MiB)"), scan.unreadable)
        self.assertEqual(code, 2)
        self.assertIn("big.yml: too large", err)

    def test_oversized_non_vault_without_marker_is_skipped_silently(self) -> None:
        for name in ("big.log", "big.json", "big.csv", "big"):
            (self.directory / name).write_bytes(b"x" * (2**20 + 1))
        with mock.patch.object(cli, "MAX_READ_BYTES", 2**20):
            scan = cli.scan_project(announce_skips=False)
            code, _, err = self._find("tail")
        self.assertEqual((scan.unreadable, scan.unreadable_other), ([], []))
        self.assertEqual(code, 0, err)
        self.assertNotIn("too large", err)

    def test_oversized_header_file_is_still_unreadable(self) -> None:
        big = (self.directory / "big.json").resolve()
        big.write_bytes(b"\n  $ANSIBLE_VAULT;1.1;AES256\n" + b"x" * (2**20))
        with mock.patch.object(cli, "MAX_READ_BYTES", 2**20):
            scan = cli.scan_project(announce_skips=False)
        self.assertIn((str(big), "too large (over 1 MiB)"), scan.unreadable)

    def test_skipped_vault_value_names_are_escaped(self) -> None:
        scan = cli.ProjectScan(skipped_vault_values=[("we\x1bird.yml", 2)])
        text = cli._describe_skipped_vault_values(scan)
        self.assertNotIn("\x1b", text)
        self.assertIn("we\\x1bird.yml (2)", text)

    def test_skipped_vault_value_paths_are_relative(self) -> None:
        absolute = str((self.directory / "sub" / "odd.yml").resolve())
        scan = cli.ProjectScan(skipped_vault_values=[(absolute, 1)])
        text = cli._describe_skipped_vault_values(scan)
        self.assertIn(os.path.join("sub", "odd.yml") + " (1)", text)
        self.assertNotIn(absolute, text)

    def test_big_file_with_only_the_word_vault_is_not_unreadable(self) -> None:
        # A tokenizer.json or a file list names "vault" and quotes "!<" but
        # holds no tag, so Ansible reads no vault value from it.
        words = "vault vault '\"!<\"' vault-ids"
        (self.directory / "tok.json").write_text(
            json.dumps({"words": [words] * 20}), encoding="utf-8"
        )
        (self.directory / "list.yml").write_text(f"- {words}\n" * 20, encoding="utf-8")
        # include_encrypted_vars=True runs the gate; the False branch (no inline
        # scan, so no gate) has its own test below.
        with mock.patch.object(cli, "MAX_COMPOSE_BYTES", 64):
            scan = cli.scan_project(include_encrypted_vars=True, announce_skips=False)
        self.assertEqual(scan.unreadable, [])

    def test_big_plaintext_with_a_vault_word_is_not_gated_without_inline_values(self) -> None:
        # Without include_encrypted_vars there is no inline scan, so the size gate
        # must not run: a ~1.1 MB file that only quotes "!vault" in prose is readable.
        big = self.directory / "prose.yml"
        big.write_text('note: "see !vault docs"\n' + "# pad\n" * 190_000, encoding="utf-8")
        self.assertGreater(big.stat().st_size, 1_100_000)
        # Guards the include_encrypted_vars gate, at the real 1 MiB cap.
        scan = cli.scan_project(include_encrypted_vars=False, announce_skips=False)
        self.assertEqual(scan.unreadable, [])

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

    def test_big_file_with_an_escaped_vault_tag_is_unreadable(self) -> None:
        big = (self.directory / "esc.yml").resolve()
        big.write_text("a: !v%61ult |\n  x\n" + "# pad\n" * 40, encoding="utf-8")
        with mock.patch.object(cli, "MAX_COMPOSE_BYTES", 64):
            scan = cli.scan_project(include_encrypted_vars=True, announce_skips=False)
        self.assertIn((str(big), TOO_LARGE_TO_PARSE), scan.unreadable)

    def test_inline_file_over_the_parse_cap_is_unreadable_and_not_loaded(self) -> None:
        inline = self._inline("big.yml")

        # The two rekey/loader calls must never run on text over the cap.
        def guarded(data):
            self.assertLessEqual(len(data), 64, "loader called on text over the cap")
            return 0

        with (
            mock.patch.object(cli, "MAX_COMPOSE_BYTES", 64),
            mock.patch.object(cli, "vault_values_pilfer_skips", guarded),
        ):
            scan = cli.scan_project(include_encrypted_vars=True, announce_skips=False)
            code, _, err = self._find("--include-encrypted-vars", "tail")
            new = self._password_file("new-password", "new-password-value")
            rekey = self._main(
                "rekey",
                "--yes",
                "--include-encrypted-vars",
                "--old-vault-password-file",
                str(self.password),
                "--new-vault-password-file",
                str(new),
            )
        self.assertIn((str(inline.resolve()), TOO_LARGE_TO_PARSE), scan.unreadable)
        self.assertEqual(code, 2)
        self.assertIn("big.yml: file is too large to parse", err)
        self.assertEqual(rekey[0], 1, rekey)
        self.assertIn("Rekey refused", rekey[2])

    def test_whole_file_plaintext_over_the_parse_cap_is_still_searched(self) -> None:
        self._encrypt("\x00\x01 not yaml \x02" * 20, "blob.yml")
        with mock.patch.object(inline, "MAX_COMPOSE_BYTES", 8):
            _code, out, err = self._find("tail")
        self.assertIn("secrets.yml: tail", out)
        # The non-YAML blob fails as it always did (a parse error), never as a
        # size refusal.
        self.assertEqual(_code, 2, err)
        self.assertIn("does not parse as YAML", err)
        self.assertNotIn("too large", err)

    def test_plain_files_over_the_cap_with_no_vault_text_are_not_unreadable(self) -> None:
        (self.directory / "data.yml").write_text("a: " + "x" * 200 + "\n", encoding="utf-8")
        (self.directory / "big.csv").write_text("x," * 200 + "\n", encoding="utf-8")
        with mock.patch.object(cli, "MAX_COMPOSE_BYTES", 64):
            scan = cli.scan_project(include_encrypted_vars=True, announce_skips=False)
            code, _, err = self._find("--include-encrypted-vars", "tail")
        self.assertEqual(scan.unreadable, [])
        self.assertEqual(code, 0, err)

    def test_open_whole_file_session_over_the_cap_is_still_searched(self) -> None:
        self.assertEqual(self._main("open", "-p", str(self.password))[0], 0)
        with mock.patch.object(inline, "MAX_COMPOSE_BYTES", 8):
            code, out, err = self._find("tail")
        self.assertEqual(code, 0, err)
        self.assertIn("secrets.yml: tail", out)
        self._main("close", "-p", str(self.password))

    def test_malformed_envelope_is_reported_as_format_error(self) -> None:
        (self.directory / "bad.yml").write_bytes(b"$ANSIBLE_VAULT;1.1\nzz\n")
        _code, _out, err = self._find("tail")
        self.assertIn("vault format error (the file is damaged)", err)

    def test_corrupt_body_is_reported_as_format_error(self) -> None:
        (self.directory / "bad.yml").write_bytes(b"$ANSIBLE_VAULT;1.1;AES256\nnot-hex!\n")
        _code, _out, err = self._find("tail")
        self.assertIn("vault format error (the file is damaged)", err)
        self.assertNotIn("could not decrypt with this vault password", err)

    def test_unreadable_other_warnings_are_capped_and_sorted(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        logs = [self.directory / f"l{number}.log" for number in range(8)]
        for log in logs:
            log.write_text("x\n", encoding="utf-8")
            log.chmod(0)
        try:
            code, _, err = self._find("tail")
        finally:
            for log in logs:
                log.chmod(0o600)
        self.assertEqual(code, 0, err)
        warnings = [line for line in err.splitlines() if line.startswith("pilfer: warning:")]
        self.assertEqual(len(warnings), MAX_FAILURE_LINES, err)
        self.assertEqual(warnings, sorted(warnings))
        self.assertIn("... and 3 more warning(s)", err)

    def test_find_keys_notes_unsupported_vault_values(self) -> None:
        (self.directory / "odd.yml").write_text(
            "k: !vault |-\n  $ANSIBLE_VAULT;1.1;AES256\n  3030\n", encoding="utf-8"
        )
        _, _, err = self._find("--include-encrypted-vars", "tail")
        self.assertIn("pilfer: warning: 1 !vault value(s)", err)
        self.assertIn("odd.yml (1)", err)
        self.assertIn("their keys are not searched", err)

    def test_update_create_hint_clips_a_long_key(self) -> None:
        _, _, err = self._main("update", "-p", str(self.password), "k" * 1000, "v")
        self.assertNotIn("k" * 81, err)

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

    def test_nested_repo_name_is_escaped_in_the_skip_message(self) -> None:
        nested = self.directory / "we\x1bird"
        (nested / ".git").mkdir(parents=True)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.scan_project()
        self.assertNotIn("\x1b", out.getvalue())
        self.assertIn("we\\x1bird", out.getvalue())

    def test_oversized_extensionless_other_file_is_a_warning(self) -> None:
        big = (self.directory / "key.pem").resolve()
        big.write_bytes(b"  \n$ANSIBLE_VAULT;1.1;AES256\n" + b"x" * (2**20 + 1))
        with mock.patch.object(cli, "MAX_READ_BYTES", 2**20):
            scan = cli.scan_project(announce_skips=False)
        self.assertEqual(scan.unreadable_other, [(str(big), "too large (over 1 MiB)")])
        self.assertEqual(scan.unreadable, [])

    def test_read_rechecks_the_size(self) -> None:
        # Only reachable by a race (the scan has the same limit), so patch just
        # find_keys' copy to see the re-check fire.
        self.vault.write_bytes(self.before + b"\n" * (2**20))
        with (
            mock.patch("pilfer.find_keys.MAX_READ_BYTES", 2**20),
            mock.patch("pilfer.cli.MAX_READ_BYTES", 2**20),
        ):
            code, _, err = self._find("tail")
        self.assertEqual(code, 2)
        self.assertIn("secrets.yml: too large (over 1 MiB)", err)

    def test_error_text_from_find_keys_is_escaped(self) -> None:
        bad = PilferError("no such source we\x1b[31mird")
        with mock.patch("pilfer.find_keys.load_vault", side_effect=bad):
            code, _, err = self._find("tail")
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err)
        self.assertIn("we\\x1b[31mird", err)
        with mock.patch("pilfer.find_keys.collect_keys", side_effect=bad):
            code, _, err = self._find("tail")
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", err)
        self.assertIn("we\\x1b[31mird", err)

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
        for raw, escaped in (
            ("\x1b", "\\x1b"),
            ("\x85", "\\x85"),
            ("\u202e", "\\u202e"),
            ("\u2028", "\\u2028"),
            ("\u200b", "\\u200b"),
            ("\ud800", "\\ud800"),
            ("\n", "\\n"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(cli.safe_text(f"a{raw}b"), f"a{escaped}b")
        self.assertEqual(cli.safe_text("caf\u00e9 \u65e5\u672c"), "caf\u00e9 \u65e5\u672c")

    def test_json_escapes_c1_characters_and_round_trips_the_key(self) -> None:
        self._encrypt('"a\\x85b": 1\n', "c1.yml")
        code, out, err = self._find("--json", "-E", "b$")
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x85", out)
        self.assertIn("\\u0085", out)
        self.assertEqual(json.loads(out.splitlines()[0])["key"], "a\x85b")

    def test_stderr_file_names_are_escaped(self) -> None:
        self._encrypt("x: 1\n", "we\u202eird.yml")
        wrong = self._password_file("wrong", "not-the-password")
        code, _, err = self._main("find-keys", "-p", str(wrong))
        self.assertEqual(code, 2)
        self.assertNotIn("\u202e", err)
        self.assertIn("\\u202e", err)

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

    def test_wrong_password_failure_lines_are_capped(self) -> None:
        for number in range(7):
            self._encrypt("x: 1\n", f"extra{number}.yml")
        wrong = self._password_file("wrong", "not-the-password")
        code, _, err = self._main("find-keys", "-p", str(wrong))
        self.assertEqual(code, 2)
        self.assertEqual(err.count("could not decrypt"), 5, err)
        self.assertIn("pilfer: 3 more file(s) could not be read", err)

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

    def test_fifo_session_entry_does_not_hang(self) -> None:
        pipe = self.directory / "pipe.yml"
        os.mkfifo(pipe)
        Path(str(pipe) + cli.OPEN_SIDECAR_SUFFIX).write_text("{}", encoding="utf-8")
        self._session({"kind": "file", "path": str(pipe)})
        self._guard()
        code, _, err = self._find("tail")
        self.assertEqual(code, 2)
        self.assertIn("not a regular file", err)

    def test_fifo_backup_does_not_hang(self) -> None:
        plain = self.directory / "plain.yml"
        plain.write_text("open_key: 1\n", encoding="utf-8")
        Path(str(plain) + cli.OPEN_SIDECAR_SUFFIX).write_text("{}", encoding="utf-8")
        backup = Path(cli._encrypted_backup_path(str(plain)))
        backup.parent.mkdir(parents=True, exist_ok=True)
        os.mkfifo(backup)
        self._session({"kind": "file", "path": str(plain)})
        self._guard()
        code, out, err = self._find("open_key")
        self.assertEqual(code, 0, err)
        self.assertIn("(open)", out)

    def test_unreadable_non_vault_file_is_a_warning(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        pem = self.directory / "key.pem"
        pem.write_text("not a vault\n", encoding="utf-8")
        pem.chmod(0)
        try:
            code, out, err = self._find("tail")
            self.assertEqual(code, 0, err)
            self.assertIn("secrets.yml", out)
            self.assertIn("key.pem: Permission denied", err)
            code, _, err = self._main("update", "-p", str(self.password), "tail", "v")
            self.assertEqual(code, 0, err)
        finally:
            pem.chmod(0o600)

    def test_unreadable_directory_is_an_error(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        sub = self.directory / "sub"
        sub.mkdir()
        sub.chmod(0)
        try:
            code, _, err = self._find("tail")
            self.assertEqual(code, 2)
            self.assertIn("sub: Permission denied", err)
            code, _, err = self._main("update", "-p", str(self.password), "tail", "v")
            self.assertEqual(code, 1)
            self.assertIn("could not be read", err)
        finally:
            sub.chmod(0o700)

    def test_session_containment_with_root_as_cwd(self) -> None:
        with mock.patch("os.getcwd", return_value="/"):
            cli._check_session_path("/etc/hosts")  # must not raise
        with self.assertRaises(PilferError):
            cli._check_session_path("/etc/hosts")  # cwd is the temp project

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
        self.assertIn("pilfer set FILE nope.key", err)
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

    def test_long_key_is_clipped_in_not_found(self) -> None:
        code, _, err = self._update("k" * 1000, "v")
        self.assertEqual(code, 1)
        # The echoed name is clipped; the create hint keeps a runnable form by
        # naming KEY instead of a clipped key.
        self.assertNotIn("k" * 81, err)
        self.assertIn("k" * 80 + "\u2026 not found", err)
        self.assertIn("pilfer set FILE KEY", err)

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

    def test_update_messages_escape_names(self) -> None:
        self._encrypt("tail: other\n", "we\x1b[31mird.yml")
        code, _, err = self._update("tail", "v")
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", err)
        self.assertIn("\\x1b", err)
        code, out, err = self._update("--file", "we\x1b[31mird.yml", "tail", "v")
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out + err)

    def test_oversized_file_is_a_failed_file(self) -> None:
        with (
            mock.patch("pilfer.find_keys.MAX_READ_BYTES", 2**20),
            mock.patch("pilfer.cli.MAX_READ_BYTES", 2**20),
        ):
            big = (self.directory / "big.yml").resolve()
            big.write_text("$ANSIBLE_VAULT;1.1;AES256\n" + "x" * 2**20, encoding="utf-8")
            code, _, err = self._find("tail")
            self.assertEqual(code, 2)
            self.assertIn("big.yml: too large", err)
            # open ignores unreadable files.
            self.assertEqual(self._main("open", "-p", str(self.password))[0], 0, err)

    def test_unreadable_dotfile_is_a_warning(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("root reads everything")
        env = self.directory / ".env"
        env.write_text("A=1\n", encoding="utf-8")
        env.chmod(0)
        try:
            code, _, err = self._find("tail")
            self.assertEqual(code, 0, err)
            self.assertIn("warning", err)
            self.assertIn(".env: Permission denied", err)
        finally:
            env.chmod(0o600)

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

    def test_not_found_with_failed_files_suggests_file(self) -> None:
        other = self.directory / "other.yml"
        other.write_bytes(_vault("a-different-password").encrypt(b"tail: stale\n"))
        code, _, err = self._update("nosuchkey", "v")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)
        self.assertIn("pass --file FILE to update one you know holds it", err)

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

    def test_anchor_refusal_names_the_file_by_its_shown_name(self) -> None:
        self._encrypt("a: &x {k: v}\nb: *x\n", "anchored.yml")
        code, _, err = self._update("--file", "anchored.yml", "a.k", "v")
        self.assertEqual(code, 1)
        self.assertIn("elsewhere in anchored.yml", err)
        self.assertNotIn(str(self.directory), err)

    def test_not_found_drops_the_create_hint_when_set_would_refuse(self) -> None:
        # tail is a scalar, so set cannot create tail.sub inside it.
        code, _, err = self._update("tail.sub", "v")
        self.assertEqual(code, 1)
        self.assertIn("not found", err)
        self.assertNotIn("to create it run", err)
        self.assertIn("set cannot create it in secrets.yml", err)
        code, _, err = self._update("brandnew", "v")
        self.assertIn("to create it run: pilfer set FILE brandnew", err)

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

    def test_key_twice_in_one_file_is_not_two_files(self) -> None:
        dup = self._encrypt("dup: 1\ndup: 2\n", "dup.yml")
        before = dup.read_bytes()
        code, _, err = self._update("dup", "v")
        self.assertEqual(code, 1)
        self.assertNotIn("2 files", err)
        self._assert_untouched(dup, before)

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

    def test_update_messages_escape_control_characters_in_names(self) -> None:
        self._encrypt("tail: 1\n", "we\x1bird.yml")
        once = "we\\x1bird.yml"
        code, _, err = self._update("tail", "v")
        self.assertEqual(code, 1)
        self.assertIn(f"  {once}\n", err + "\n")
        self.assertNotIn("\x1b", err)
        code, out, err = self._update("--dry-run", "--file", "we\x1bird.yml", "tail", "v")
        self.assertEqual(code, 0, err)
        self.assertIn(f"would update tail in {once}", out)
        code, _, err = self._update("--file", "we\x1bmissing.yml", "tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("we\\x1bmissing.yml does not exist", err)
        self.assertNotIn("\\\\x1b", err)
        code, _, err = self._update("--file", "we\x1bird.yml", "nope", "v")
        self.assertEqual(code, 1)
        self.assertNotIn("\\\\x1b", err)

    def test_printed_key_paths_paste_back(self) -> None:
        odd = {"it's": "1", "back\\slash": "2", "plain": "3"}
        self._encrypt(yaml.safe_dump(odd), "odd.yml")
        code, out, err = self._find("-E", "(it's|slash)$")
        self.assertEqual(code, 0, err)
        printed = [line.split(": ", 1)[1] for line in out.splitlines()]
        self.assertEqual(sorted(parse_key_path(p)[0] for p in printed), ["back\\slash", "it's"])
        for text in printed:
            with self.subTest(text=text):
                code, out, err = self._update("--dry-run", "--file", "odd.yml", text, "v")
                self.assertEqual(code, 0, err)

    def test_file_must_be_a_regular_file(self) -> None:
        code, _, err = self._update("--file", "missing.yml", "tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("missing.yml does not exist", err)
        self.assertNotIn("pilfer set", err)
        os.mkdir(self.directory / "adir.yml")
        code, _, err = self._update("--file", "adir.yml", "tail", "v")
        self.assertEqual(code, 1)
        self.assertIn("adir.yml is not a regular file", err)

    def test_no_create_hint_for_a_list_index_or_unreadable_files(self) -> None:
        code, _, err = self._update("users[9].password", "v")
        self.assertEqual(code, 1)
        self.assertNotIn("pilfer set", err)
        code, _, err = self._update("nope.key", "v")
        self.assertIn("pilfer set FILE nope.key", err)
        (self.directory / "other.yml").write_bytes(_vault("another").encrypt(b"a: 1\n"))
        code, _, err = self._update("nope.key", "v")
        self.assertEqual(code, 1)
        self.assertNotIn("pilfer set", err)
        self.assertIn("could not be read", err)

    def test_stdin_over_the_limit_is_refused(self) -> None:
        self._stdin(b"x" * (MAX_STDIN_VALUE_BYTES + 1))
        code, _, err = self._update("tail")
        self.assertEqual(code, 1)
        self.assertIn("over", err)
        self._assert_untouched()

    def test_stdin_not_utf8_is_refused_without_echo(self) -> None:
        self._stdin(b"\xff\n")
        code, out, err = self._update("tail")
        self.assertEqual(code, 1)
        self.assertIn("not UTF-8", err)
        self.assertNotIn("\xff", out + err)
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
