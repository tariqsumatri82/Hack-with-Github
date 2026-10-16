"""The CLI contract: exit codes, the documented JSON shape, filters, determinism.

Nothing here touches the network — and the last test proves it by reading the
package's own imports.
"""

import ast
import io
import json
import os
import shutil
import tempfile
import unittest

from ghaudit import AUDIT_VERSION, __version__, cli

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "workflows")
CLEAN = os.path.join(FIXTURES, "gha01-fixed.yml")
FLAGGED = os.path.join(FIXTURES, "gha01-bad.yml")
BROKEN = os.path.join(HERE, "fixtures", "broken", "tabs.yml")
PACKAGE = os.path.dirname(os.path.abspath(cli.__file__))

# Modules that would mean the tool can reach the network.
NETWORK_IMPORTS = {
    "socket",
    "ssl",
    "urllib",
    "http",
    "requests",
    "ftplib",
    "smtplib",
    "telnetlib",
    "xmlrpc",
}
# ...and the one that would mean it can run something.
EXEC_IMPORTS = {"subprocess"}

DOCUMENTED_TOP_KEYS = {"tool", "version", "audit_version", "root", "files", "totals"}
DOCUMENTED_FILE_KEYS = {"path", "parsed", "jobs", "steps", "findings"}
DOCUMENTED_FINDING_KEYS = {"id", "line", "context", "message", "fix", "anchor"}
DOCUMENTED_TOTAL_KEYS = {
    "files",
    "files_parsed",
    "files_unparsed",
    "jobs",
    "steps",
    "findings",
    "by_pattern",
}


def run(argv):
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def run_json(argv):
    code, out, err = run(list(argv) + ["--format", "json"])
    return code, json.loads(out), err


def imported_modules(path):
    """Root module names imported by the Python file at ``path``."""
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


class TestExitCodes(unittest.TestCase):
    def test_exit_0_when_nothing_is_flagged(self):
        code, out, err = run([CLEAN])
        self.assertEqual(code, 0, out + err)
        self.assertIn("No flags for review", out)

    def test_exit_1_when_something_is_flagged(self):
        code, out, err = run([FLAGGED])
        self.assertEqual(code, 1, out + err)
        self.assertIn("reason to look, not a proven exploit", out)

    def test_exit_1_for_a_directory_of_fixtures(self):
        code, out, _ = run([FIXTURES])
        self.assertEqual(code, 1)
        self.assertIn("GHA01", out)

    def test_exit_2_without_a_target(self):
        code, out, err = run([])
        self.assertEqual(code, 2, out + err)
        self.assertIn("target path is required", err)

    def test_exit_2_on_an_unknown_pattern_id(self):
        code, out, err = run([FIXTURES, "--only", "GHA99"])
        self.assertEqual(code, 2)
        self.assertIn("GHA99", err)
        self.assertEqual(out, "")

    def test_exit_2_on_a_target_that_does_not_exist(self):
        missing = os.path.join(HERE, "no-such-directory")
        code, _, err = run([missing])
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_exit_3_when_a_workflow_cannot_be_parsed(self):
        code, out, err = run([BROKEN])
        self.assertEqual(code, 3, out + err)
        # The file and the reason are both named, and it is not audited.
        self.assertIn("tabs.yml", out)
        self.assertIn("NOT AUDITED", out)
        self.assertIn("tab", out.lower())
        self.assertIn("not audited", out.lower())

    def test_exit_3_outranks_a_clean_file(self):
        # Unparsed even alongside a clean file: CI must be able to tell
        # "audited clean" from "part of the set was not read".
        code, out, _ = run([os.path.join(HERE, "fixtures", "broken")])
        self.assertEqual(code, 3)
        self.assertIn("tabs.yml", out)


class TestJsonShape(unittest.TestCase):
    def test_documented_keys(self):
        code, data, err = run_json([FIXTURES])
        self.assertEqual(code, 1, err)
        self.assertEqual(set(data), DOCUMENTED_TOP_KEYS)
        self.assertEqual(data["tool"], "ghaudit")
        self.assertEqual(data["version"], __version__)
        self.assertEqual(data["audit_version"], AUDIT_VERSION)
        self.assertTrue(data["files"])
        for file_result in data["files"]:
            self.assertEqual(set(file_result), DOCUMENTED_FILE_KEYS)
            self.assertIsInstance(file_result["parsed"], bool)
            for finding in file_result["findings"]:
                self.assertEqual(set(finding), DOCUMENTED_FINDING_KEYS)
                self.assertRegex(finding["id"], r"^GHA0[1-7]$")
                self.assertIsInstance(finding["line"], int)
                self.assertTrue(finding["message"])
                self.assertTrue(finding["fix"])

    def test_totals_agree_with_the_files(self):
        _, data, _ = run_json([FIXTURES])
        totals = data["totals"]
        self.assertEqual(set(totals), DOCUMENTED_TOTAL_KEYS)
        self.assertEqual(totals["files"], len(data["files"]))
        self.assertEqual(
            totals["findings"], sum(len(f["findings"]) for f in data["files"])
        )
        self.assertEqual(
            totals["files_parsed"] + totals["files_unparsed"], totals["files"]
        )
        counted = {}
        for file_result in data["files"]:
            for finding in file_result["findings"]:
                counted[finding["id"]] = counted.get(finding["id"], 0) + 1
        self.assertEqual(totals["by_pattern"], dict(sorted(counted.items())))

    def test_files_and_findings_are_ordered(self):
        _, data, _ = run_json([FIXTURES])
        paths = [f["path"] for f in data["files"]]
        self.assertEqual(paths, sorted(paths))
        for file_result in data["files"]:
            keys = [(f["line"], f["id"]) for f in file_result["findings"]]
            self.assertEqual(keys, sorted(keys))

    def test_json_reports_an_unparsed_file(self):
        code, data, _ = run_json([BROKEN])
        self.assertEqual(code, 3)
        unparsed = [f for f in data["files"] if not f["parsed"]]
        self.assertEqual(len(unparsed), 1)
        self.assertIn("tabs.yml", unparsed[0]["path"])
        self.assertIn("tab", unparsed[0]["error"].lower())


class TestFiltersAndOutput(unittest.TestCase):
    def test_only_keeps_one_pattern(self):
        _, data, _ = run_json([FIXTURES, "--only", "GHA01"])
        ids = {f["id"] for file_result in data["files"] for f in file_result["findings"]}
        self.assertEqual(ids, {"GHA01"})

    def test_only_accepts_several_patterns(self):
        _, data, _ = run_json([FIXTURES, "--only", "GHA01,GHA02"])
        ids = {f["id"] for file_result in data["files"] for f in file_result["findings"]}
        self.assertTrue(ids)
        self.assertTrue(ids <= {"GHA01", "GHA02"})

    def test_exclude_drops_one_pattern(self):
        _, everything, _ = run_json([FIXTURES])
        _, data, _ = run_json([FIXTURES, "--exclude", "GHA01"])
        ids = {f["id"] for file_result in data["files"] for f in file_result["findings"]}
        self.assertNotIn("GHA01", ids)
        self.assertTrue(ids)
        self.assertLess(data["totals"]["findings"], everything["totals"]["findings"])

    def test_only_and_exclude_combine(self):
        _, data, _ = run_json([FIXTURES, "--only", "GHA01,GHA02,GHA03", "--exclude", "GHA02"])
        ids = {f["id"] for file_result in data["files"] for f in file_result["findings"]}
        self.assertTrue(ids)
        self.assertTrue(ids <= {"GHA01", "GHA03"})

    def test_list_patterns_prints_seven_ids(self):
        code, out, err = run(["--list-patterns"])
        self.assertEqual(code, 0, err)
        ids = [line.split()[0] for line in out.strip().splitlines()]
        self.assertEqual(ids, ["GHA0%d" % n for n in range(1, 8)])

    def test_write_report_matches_stdout(self):
        tmp = tempfile.mkdtemp(prefix="ghaudit-cli-")
        self.addCleanup(shutil.rmtree, tmp, True)
        target = os.path.join(tmp, "nested", "report.json")
        code, out, err = run([FIXTURES, "--format", "json", "--write-report", target])
        self.assertIn(code, (0, 1), err)
        with open(target, "r", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), out)


class TestDeterminism(unittest.TestCase):
    def test_two_runs_are_byte_identical(self):
        _, first, _ = run([FIXTURES, "--format", "json"])
        _, second, _ = run([FIXTURES, "--format", "json"])
        self.assertEqual(first, second)

    def test_two_runs_of_the_table_are_byte_identical(self):
        _, first, _ = run([FIXTURES])
        _, second, _ = run([FIXTURES])
        self.assertEqual(first, second)


class TestNoNetworkAndNoExecution(unittest.TestCase):
    def test_no_network_module_is_imported_anywhere_in_the_package(self):
        offenders = {}
        for name in sorted(os.listdir(PACKAGE)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(PACKAGE, name)
            bad = imported_modules(path) & NETWORK_IMPORTS
            if bad:
                offenders[name] = sorted(bad)
        self.assertEqual(offenders, {}, "ghaudit must never reach the network: %r" % offenders)

    def test_nothing_in_the_package_can_run_a_subprocess(self):
        offenders = {}
        for name in sorted(os.listdir(PACKAGE)):
            if not name.endswith(".py"):
                continue
            bad = imported_modules(os.path.join(PACKAGE, name)) & EXEC_IMPORTS
            if bad:
                offenders[name] = sorted(bad)
        self.assertEqual(offenders, {}, "ghaudit must never execute anything: %r" % offenders)


if __name__ == "__main__":
    unittest.main()
