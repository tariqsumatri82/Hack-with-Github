"""Discovery: `--repo` finds `.github/workflows`, and an empty target is not a failure.

A directory with no workflow files is a legitimate answer: the tool says so and
exits 0. Only a file that could not be parsed is a failure (exit 3, covered in
`test_cli.py`).
"""

import io
import os
import shutil
import tempfile
import unittest

from ghaudit import cli
from ghaudit.discovery import WORKFLOW_DIR, find_workflows, resolve_target

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "workflows")
SAMPLE = os.path.join(FIXTURES, "gha01-bad.yml")

# A workflow with nothing to flag: every action pinned, no interpolation, a
# single job that only reads the repository.
CLEAN = """name: sample
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""


def write(path, text=CLEAN):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def run(argv, cwd=None):
    """Run the CLI in-process and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    previous = os.getcwd()
    if cwd:
        os.chdir(cwd)
    try:
        code = cli.main(argv, stdout=out, stderr=err)
    finally:
        os.chdir(previous)
    return code, out.getvalue(), err.getvalue()


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ghaudit-discovery-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def root(self, name="repo"):
        return os.path.join(self.tmp, name)

    def test_repo_flag_resolves_to_the_workflow_directory(self):
        root = self.root()
        write(os.path.join(root, WORKFLOW_DIR, "sample.yml"))
        write(os.path.join(root, "README.md"), "# a repository\n")
        self.assertEqual(
            resolve_target(root, repo=True), (os.path.join(root, WORKFLOW_DIR), None)
        )

    def test_repo_flag_finds_workflows_and_exits_zero(self):
        root = self.root()
        write(os.path.join(root, WORKFLOW_DIR, "sample.yml"))
        code, out, err = run(["--repo", root])
        self.assertEqual(code, 0, out + err)
        self.assertIn("1 workflow file", out)
        self.assertIn("No flags for review", out)

    def test_repo_without_a_path_uses_the_working_directory(self):
        root = self.root()
        write(os.path.join(root, WORKFLOW_DIR, "sample.yml"))
        code, out, err = run(["--repo"], cwd=root)
        self.assertEqual(code, 0, out + err)
        self.assertIn("1 workflow file", out)

    def test_repository_root_is_recognised_without_the_flag(self):
        root = self.root()
        write(os.path.join(root, WORKFLOW_DIR, "sample.yml"))
        write(os.path.join(root, "README.md"), "# a repository\n")
        self.assertEqual(find_workflows(os.path.join(root, WORKFLOW_DIR)), [os.path.join(root, WORKFLOW_DIR, "sample.yml")])
        code, out, err = run([root])
        self.assertEqual(code, 0, out + err)
        self.assertIn("1 workflow file", out)

    def test_directory_without_workflow_files_is_not_a_failure(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        code, out, err = run([empty])
        self.assertEqual(code, 0, out + err)
        self.assertIn("no workflow files found", out.lower())
        self.assertNotEqual(code, 3)
        self.assertEqual(err, "")

    def test_directory_without_workflow_files_but_with_other_files(self):
        plain = os.path.join(self.tmp, "plain")
        os.makedirs(plain)
        write(os.path.join(plain, "notes.md"), "not a workflow\n")
        code, out, _ = run([plain])
        self.assertEqual(code, 0)
        self.assertIn("no workflow files found", out.lower())

    def test_repo_flag_on_a_repository_with_no_workflows_is_not_a_failure(self):
        root = self.root()
        write(os.path.join(root, "README.md"), "# no workflows here\n")
        code, out, err = run(["--repo", root])
        self.assertEqual(code, 0, out + err)
        self.assertIn("no workflow files found", out.lower())

    def test_a_single_workflow_file_is_audited_on_its_own(self):
        # The CLI documents "a workflow directory, a repository root, or one
        # workflow file" as valid targets.
        code, out, err = run([SAMPLE])
        self.assertEqual(code, 1, out + err)
        self.assertIn("gha01-bad.yml", out)
        # Only the named file: the rest of the fixture directory is untouched.
        self.assertNotIn("gha02-bad.yml", out)

    def test_subdirectories_are_searched_when_the_root_has_no_workflows(self):
        root = os.path.join(self.tmp, "organised")
        write(os.path.join(root, "jobs", "deploy.yml"))
        code, out, err = run([root])
        self.assertEqual(code, 0, out + err)
        self.assertIn("1 workflow file", out)

    def test_hidden_directories_are_not_searched(self):
        root = os.path.join(self.tmp, "dotty")
        os.makedirs(root)
        write(os.path.join(root, ".hidden", "buried.yml"))
        code, out, _ = run([root])
        self.assertEqual(code, 0)
        self.assertIn("no workflow files found", out.lower())


if __name__ == "__main__":
    unittest.main()
