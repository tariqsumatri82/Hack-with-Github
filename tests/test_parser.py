"""The parser must preserve line numbers, or findings are not actionable."""

import unittest

from ghaudit.parser import Map, ParseError, Scalar, Seq, parse, runs, steps_of, triggers

NESTED = """name: nested
on:
  push:
    branches: [main]
jobs:
  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Test
        run: pytest -q
"""


class TestBlockStructure(unittest.TestCase):
    def test_nested_jobs_and_steps(self):
        doc = parse(NESTED)
        self.assertIsInstance(doc, Map)
        self.assertEqual(doc.line, 1)
        self.assertIn("build", doc["jobs"])
        job = doc["jobs"]["build"]
        self.assertEqual(doc["jobs"].key_line("build"), 6)
        self.assertEqual(job.key_line("runs-on"), 8)
        steps = steps_of(job)
        self.assertEqual(len(steps), 2)
        self.assertEqual(steps[0].key_line("name"), 10)
        self.assertEqual(steps[0].key_line("uses"), 11)
        self.assertEqual(str(steps[0]["uses"]), "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")
        self.assertEqual(steps[1].key_line("run"), 13)

    def test_sequence_of_mappings_line_numbers(self):
        doc = parse("jobs:\n  a:\n    steps:\n      - uses: x@1\n      - uses: y@2\n")
        steps = steps_of(doc["jobs"]["a"])
        self.assertEqual([s.key_line("uses") for s in steps], [4, 5])

    def test_on_as_string_list_and_mapping(self):
        self.assertEqual(triggers(parse("on: push\n")), {"push"})
        self.assertEqual(triggers(parse("on: [push, pull_request]\n")), {"push", "pull_request"})
        self.assertEqual(triggers(parse("on:\n  pull_request_target:\n    types: [opened]\n")), {"pull_request_target"})

    def test_empty_value_is_empty_scalar(self):
        doc = parse("on:\njobs:\n  a:\n    runs-on: ubuntu-latest\n")
        self.assertEqual(str(doc["on"]), "")

    def test_document_markers_and_comments_ignored(self):
        doc = parse("---\n# a comment\nname: x\n---\n")
        self.assertEqual(str(doc["name"]), "x")
        self.assertEqual(doc.key_line("name"), 3)


class TestScalars(unittest.TestCase):
    def test_quoted_string_with_colon(self):
        doc = parse('run: "echo a: b"\nname: "quoted"\n')
        self.assertEqual(str(doc["run"]), "echo a: b")
        self.assertEqual(str(doc["name"]), "quoted")

    def test_trailing_comment_removed_from_plain_scalar(self):
        doc = parse("uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2\n")
        self.assertEqual(str(doc["uses"]), "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683")

    def test_hash_inside_quotes_is_kept(self):
        doc = parse('run: echo "a # b"\n')
        self.assertEqual(str(doc["run"]), 'echo "a # b"')

    def test_crlf_input(self):
        doc = parse("name: x\r\non: push\r\njobs:\r\n  a:\r\n    runs-on: ubuntu-latest\r\n")
        self.assertEqual(str(doc["name"]), "x")
        self.assertEqual(doc["jobs"].key_line("a"), 4)

    def test_unicode_is_preserved(self):
        doc = parse('name: "café — test"\n')
        self.assertEqual(str(doc["name"]), "café — test")


class TestBlockScalars(unittest.TestCase):
    LITERAL = "jobs:\n  a:\n    steps:\n      - run: |\n          line one\n          line two\n        name: after\n"

    def test_literal_block_keeps_newlines_and_line_number(self):
        doc = parse(self.LITERAL)
        step = steps_of(doc["jobs"]["a"])[0]
        text, first_line = list(runs(step))[0]
        self.assertEqual(first_line, 5)
        self.assertIn("line one\nline two", text)
        self.assertTrue(step["run"].block)

    def test_folded_block_joins_lines(self):
        doc = parse("run: >\n  one\n  two\n\n  three\n")
        self.assertEqual(str(doc["run"]), "one two\nthree\n")

    def test_strip_chomping(self):
        doc = parse("run: |-\n  echo hi\n")
        self.assertEqual(str(doc["run"]), "echo hi")

    def test_block_scalar_followed_by_sibling_key(self):
        doc = parse("run: |\n  echo hi\ntimeout-minutes: 5\n")
        self.assertEqual(str(doc["timeout-minutes"]), "5")
        self.assertEqual(doc.key_line("timeout-minutes"), 3)


class TestFlowAndErrors(unittest.TestCase):
    def test_flow_sequence(self):
        doc = parse("runs-on: [self-hosted, linux, x64]\npermissions: {}\n")
        self.assertIsInstance(doc["runs-on"], Seq)
        self.assertEqual(list(doc["runs-on"]), ["self-hosted", "linux", "x64"])
        self.assertEqual(dict(doc["permissions"]), {})

    def test_tab_indentation_is_a_parse_error(self):
        with self.assertRaises(ParseError) as caught:
            parse("name: tabs\non: push\njobs:\n\tbuild:\n")
        self.assertIn("tab", caught.exception.reason)
        self.assertEqual(caught.exception.line, 4)

    def test_anchor_is_refused_not_guessed(self):
        with self.assertRaises(ParseError) as caught:
            parse("jobs: &defaults\n  a:\n    runs-on: ubuntu-latest\n")
        self.assertIn("anchors", caught.exception.reason)

    def test_unterminated_quote_is_a_parse_error(self):
        with self.assertRaises(ParseError):
            parse('name: "unterminated\n')

    def test_line_without_colon_is_a_parse_error(self):
        with self.assertRaises(ParseError):
            parse("name: x\nnot a mapping line\n")

    def test_scalar_lines_keep_their_line(self):
        doc = parse("run: echo hi\n")
        self.assertIsInstance(doc["run"], Scalar)
        self.assertEqual(doc["run"].line, 1)


if __name__ == "__main__":
    unittest.main()
