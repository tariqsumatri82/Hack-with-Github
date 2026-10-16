"""Command line: argument handling, the audit loop, output selection, exit codes.

Exit codes:
    0  no flags for review
    1  at least one flag for review
    2  usage error (bad arguments, missing target, unknown pattern id)
    3  a workflow file could not be parsed and was not audited
"""

from __future__ import annotations

import argparse
import os
import sys

from . import AUDIT_VERSION, __version__
from .discovery import WORKFLOW_DIR, find_workflows, resolve_target
from .findings import AuditResult, FileResult
from .parser import ParseError, jobs, parse, steps_of, triggers
from .report import RENDERERS, render
from .rules import GHA_IDS, audit_workflow, load_rules

TOOL = "ghaudit"

EPILOG = """examples:
  python3 ghaudit.py .github/workflows          audit a workflow directory
  python3 ghaudit.py --repo .                   find .github/workflows from a repo root
  python3 ghaudit.py --repo . --format json     machine-readable report
  python3 ghaudit.py --repo . --only GHA02,GHA03
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="ghaudit.py",
        description="Audit GitHub Actions workflow files for the patterns that cause supply-chain and script-injection incidents. Reads text only: no network, no action resolution, no workflow execution.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?", default=None, help="a workflow directory, a repository root, or a workflow file")
    parser.add_argument("--repo", action="store_true", help="treat the target as a repository root and audit its .github/workflows")
    parser.add_argument("--format", choices=sorted(RENDERERS), default="table", help="report format (default: table)")
    parser.add_argument("--only", default=None, help="comma-separated pattern ids to run, e.g. GHA02,GHA03")
    parser.add_argument("--exclude", default=None, help="comma-separated pattern ids to skip")
    parser.add_argument("--fail-on-unparsed", action="store_true", help="state explicitly that an unparsed workflow is a failure (exit code 3, which is also the default)")
    parser.add_argument("--write-report", metavar="OUT", default=None, help="also write the rendered report to OUT")
    parser.add_argument("--yaml-cross-check", action="store_true", help="when PyYAML is importable, load the file with it first and fail loudly on disagreement")
    parser.add_argument("--list-patterns", action="store_true", help="print the pattern ids and titles, then exit")
    parser.add_argument("-V", "--version", action="version", version="%s %s (audit %s)" % (TOOL, __version__, AUDIT_VERSION))
    return parser


def _resolve_selection(args, all_ids, stderr):
    selected = set(all_ids)
    if args.only:
        wanted = [part.strip() for part in args.only.split(",") if part.strip()]
        unknown = [w for w in wanted if w not in all_ids]
        if unknown:
            stderr.write("ghaudit: unknown pattern id(s) in --only: %s\n" % ", ".join(unknown))
            return None
        selected = set(wanted)
    if args.exclude:
        unwanted = [part.strip() for part in args.exclude.split(",") if part.strip()]
        unknown = [w for w in unwanted if w not in all_ids]
        if unknown:
            stderr.write("ghaudit: unknown pattern id(s) in --exclude: %s\n" % ", ".join(unknown))
            return None
        selected -= set(unwanted)
    return selected


def _cross_check(text, node):
    """Return a disagreement description, or None when the two agree."""
    try:
        import yaml  # noqa: F401  (optional, never required)
    except ImportError:
        return "no-pyyaml"
    try:
        data = yaml.safe_load(text)
    except Exception as exc:  # any PyYAML failure is a disagreement we report
        return "PyYAML rejected the file: %s" % exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        return "PyYAML read the document as %s, not a mapping" % type(data).__name__

    def shape_ours(workflow):
        out = {"jobs": {}, "uses": set(), "triggers": set(triggers(workflow))}
        for name, job in jobs(workflow).items():
            out["jobs"][str(name)] = len(steps_of(job))
            for step in steps_of(job):
                if "uses" in step:
                    out["uses"].add(str(step["uses"]).strip())
        return out

    def shape_theirs(document):
        out = {"jobs": {}, "uses": set(), "triggers": set()}
        raw_on = document.get("on", document.get(True))
        if isinstance(raw_on, str):
            out["triggers"].add(raw_on)
        elif isinstance(raw_on, list):
            out["triggers"].update(str(item) for item in raw_on)
        elif isinstance(raw_on, dict):
            out["triggers"].update(str(key) for key in raw_on)
        raw_jobs = document.get("jobs") or {}
        if isinstance(raw_jobs, dict):
            for name, job in raw_jobs.items():
                steps = (job or {}).get("steps") if isinstance(job, dict) else None
                steps = steps if isinstance(steps, list) else []
                out["jobs"][str(name)] = len(steps)
                for step in steps:
                    if isinstance(step, dict) and step.get("uses"):
                        out["uses"].add(str(step["uses"]).strip())
        return out

    mine = shape_ours(node)
    theirs = shape_theirs(data)
    for key in ("jobs", "triggers", "uses"):
        if mine[key] != theirs[key]:
            return "disagreement on %s: ghaudit parsed %r, PyYAML parsed %r" % (key, mine[key], theirs[key])
    return None


def audit_path(target, repo=False, selected=None, cross_check=False, rules=None, stderr=None):
    """Audit everything under ``target`` and return an AuditResult."""
    stderr = stderr or sys.stderr
    rules = rules if rules is not None else load_rules()
    root, error = resolve_target(target, repo=repo)
    if error:
        return None, error
    base = root
    if os.path.isfile(root):
        # One workflow file: report it under its own name, not as ".".
        base = os.path.dirname(root)
    elif os.path.basename(root.rstrip(os.sep)) == "workflows" and os.path.basename(
        os.path.dirname(root.rstrip(os.sep))
    ) == ".github":
        base = os.path.dirname(os.path.dirname(root.rstrip(os.sep)))
    display_root = os.path.relpath(root, os.getcwd())
    files = find_workflows(root)
    results = []
    for path in files:
        rel = os.path.relpath(path, base).replace(os.sep, "/")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as exc:
            results.append(FileResult(rel, parsed=False, error="could not read file: %s" % exc.strerror))
            continue
        try:
            workflow = parse(text)
        except ParseError as exc:
            results.append(FileResult(rel, parsed=False, error="%s" % exc))
            continue
        if cross_check:
            disagreement = _cross_check(text, workflow)
            if disagreement == "no-pyyaml":
                stderr.write("ghaudit: PyYAML is not importable here — --yaml-cross-check skipped\n")
            elif disagreement:
                results.append(FileResult(rel, parsed=False, error="yaml cross-check %s" % disagreement))
                continue
        findings = audit_workflow(workflow, text, rel, rules, selected=selected)
        results.append(
            FileResult(
                rel,
                parsed=True,
                jobs=len(jobs(workflow)),
                steps=sum(len(steps_of(job)) for _, job in jobs(workflow).items()),
                findings=findings,
            )
        )
    return AuditResult(TOOL, __version__, AUDIT_VERSION, display_root, results), None


def main(argv=None, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)

    rules = load_rules()

    if args.list_patterns:
        for rule in rules:
            stdout.write("%s  %s\n" % (rule["id"], rule["title"]))
        return 0

    target = args.path if args.path is not None else ("." if args.repo else None)
    if target is None:
        stderr.write("ghaudit: a target path is required (or pass --repo with a repository root)\n")
        return 2

    selected = _resolve_selection(args, [rule["id"] for rule in rules], stderr)
    if selected is None:
        return 2

    result, error = audit_path(
        target, repo=args.repo, selected=selected, cross_check=args.yaml_cross_check, rules=rules, stderr=stderr
    )
    if error:
        stderr.write("ghaudit: %s\n" % error)
        return 2

    output = render(result, args.format)
    stdout.write(output)
    if args.write_report:
        try:
            directory = os.path.dirname(os.path.abspath(args.write_report))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(args.write_report, "w", encoding="utf-8") as handle:
                handle.write(output)
        except OSError as exc:
            stderr.write("ghaudit: could not write report to %s: %s\n" % (args.write_report, exc))
            return 2

    if args.format == "table" and not result.files:
        stdout.write("No workflow files found under %s — nothing was audited.\n" % result.root)
    return result.exit_code
