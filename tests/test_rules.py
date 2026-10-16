"""Per-pattern fixtures: the bad file fires, the fixed file produces nothing."""

import os
import unittest

from ghaudit.parser import parse
from ghaudit.rules import GHA_IDS, audit_workflow, load_rules

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "workflows")

# pattern id -> (fixture, expected line numbers)
BAD = {
    "GHA01": ("gha01-bad.yml", [11, 12]),
    "GHA02": ("gha02-bad.yml", [3]),
    "GHA03": ("gha03-bad.yml", [12, 14]),
    "GHA04": ("gha04-bad.yml", [5]),
    "GHA05": ("gha05-bad.yml", [8]),
    # GHA06 expects the persist-credentials finding (13) and the secret written
    # into the run: text (17). Line 16 is a secret passed through a step-level
    # `env:` in the same job; the shipped rule does not flag that shape yet, and
    # it is recorded as a known gap in CHANGELOG.md rather than asserted here.
    "GHA06": ("gha06-bad.yml", [13, 17]),
    "GHA07": ("gha07-bad.yml", [3, 12, 15]),
}

FIXED = {
    "GHA01": "gha01-fixed.yml",
    "GHA02": "gha02-fixed.yml",
    "GHA03": "gha03-fixed.yml",
    "GHA04": "gha04-fixed.yml",
    "GHA05": "gha05-fixed.yml",
    "GHA06": "gha06-fixed.yml",
    "GHA07": "gha07-fixed.yml",
}

RULES = load_rules()


def audit(name, selected=None):
    path = os.path.join(FIXTURES, name)
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    return audit_workflow(parse(text), text, name, RULES, selected=selected)


class TestPatternFixtures(unittest.TestCase):
    def test_bad_fixture_fires_with_expected_lines(self):
        for pattern_id, (name, lines) in sorted(BAD.items()):
            with self.subTest(pattern=pattern_id):
                found = audit(name, selected={pattern_id})
                self.assertEqual([f.pattern for f in found], [pattern_id] * len(lines))
                self.assertEqual([f.line for f in found], lines)

    def test_fixed_fixture_produces_no_findings_at_all(self):
        for name in sorted(FIXED.values()):
            with self.subTest(fixture=name):
                self.assertEqual([f.to_dict() for f in audit(name)], [], name)

    def test_extra_bad_fixture_for_the_missing_permissions_heuristic(self):
        found = audit("gha04-nopermissions-bad.yml", selected={"GHA04"})
        self.assertEqual([f.line for f in found], [6])
        self.assertIn("gh release create", found[0].context)


class TestCombinations(unittest.TestCase):
    def test_gha02_needs_the_trigger(self):
        text = open(os.path.join(FIXTURES, "gha02-fixed.yml"), encoding="utf-8").read()
        self.assertEqual(audit_workflow(parse(text), text, "x", RULES, selected={"GHA02"}), [])

    def test_gha02_needs_the_head_checkout(self):
        text = open(os.path.join(FIXTURES, "gha02-trigger-only.yml"), encoding="utf-8").read()
        self.assertEqual(audit_workflow(parse(text), text, "x", RULES, selected={"GHA02"}), [])

    def test_gha02_fires_only_when_both_are_present(self):
        found = audit("gha02-bad.yml", selected={"GHA02"})
        self.assertEqual(len(found), 1)
        self.assertIn("pull_request_target", found[0].context)
        self.assertIn("head", found[0].context)

    def test_gha03_reports_unquoted_before_quoted_on_the_same_block(self):
        text = "on: issues\njobs:\n  a:\n    steps:\n      - run: |\n          echo ${{ github.event.issue.title }}\n          echo \"${{ github.event.issue.body }}\"\n"
        found = audit_workflow(parse(text), text, "x", RULES, selected={"GHA03"})
        self.assertEqual([f.line for f in found], [6, 7])

    def test_gha01_accepts_a_docker_digest_and_flags_a_tag(self):
        digest = "jobs:\n  a:\n    steps:\n      - uses: docker://alpine@sha256:abc\n"
        self.assertEqual(audit_workflow(parse(digest), digest, "x", RULES, selected={"GHA01"}), [])
        tagged = "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3\n"
        self.assertEqual(len(audit_workflow(parse(tagged), tagged, "x", RULES, selected={"GHA01"})), 1)

    def test_gha01_ignores_local_actions(self):
        text = "jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/build\n"
        self.assertEqual(audit_workflow(parse(text), text, "x", RULES, selected={"GHA01"}), [])


class TestRuleMetadata(unittest.TestCase):
    def test_rule_ids_and_order(self):
        self.assertEqual([rule["id"] for rule in RULES], list(GHA_IDS))

    def test_every_rule_carries_wording_a_human_can_act_on(self):
        for rule in RULES:
            with self.subTest(rule=rule["id"]):
                self.assertTrue(rule["why"])
                self.assertTrue(rule["fix"])
                self.assertIn("FLAG for review", rule["message"])

    def test_no_rule_claims_a_proven_vulnerability(self):
        banned = ("vulnerable", "exploitable", "exploit is", "critical severity", "guaranteed")
        for rule in RULES:
            blob = " ".join(str(value) for value in rule.values()).lower()
            for word in banned:
                self.assertNotIn(word, blob, "%s uses %r" % (rule["id"], word))

    def test_readme_count_docs_count_and_rules_count_agree(self):
        import subprocess
        import sys

        repo_root = os.path.dirname(HERE)
        result = subprocess.run(
            [sys.executable, os.path.join(repo_root, "tools", "check_sync.py")],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("%d patterns" % len(RULES), result.stdout)


if __name__ == "__main__":
    unittest.main()
