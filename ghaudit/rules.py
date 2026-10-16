"""The seven audit patterns.

Six are structural — where a key sits and what it contains — so they are
checked by small functions with no cleverness. Pattern metadata (title, why,
fix, wording) lives in rules.json so the count in the README is machine
checkable and a change to a pattern is a diff, not a code review puzzle.

Every finding is a pattern match in the workflow text. Nothing here proves an
exploit; each line is a reason for a human to look.
"""

from __future__ import annotations

import json
import os
import re

from .findings import Finding
from .parser import Map, Scalar, Seq, iter_jobs, iter_steps, is_true, jobs, runs, trigger_line, triggers

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

REQUIRED_FIELDS = ("id", "title", "slug", "why", "fix", "message", "anchor")

# Triggers a pull request author, a commenter or another workflow can drive.
UNTRUSTED_TRIGGERS = frozenset(
    [
        "pull_request",
        "pull_request_target",
        "issue_comment",
        "discussion_comment",
        "workflow_run",
        "repository_dispatch",
    ]
)

HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref|label)"
    r"|github\.head_ref"
    r"|pull_request\.head\.(sha|ref)"
)

UNTRUSTED_INPUT = (
    re.compile(r"github\.event\.issue\.(title|body)"),
    re.compile(r"github\.event\.comment\.body"),
    re.compile(r"github\.event\.review(_comment)?(\.comment)?\.body"),
    re.compile(r"github\.event\.pull_request\.(title|body)"),
    re.compile(r"github\.event\.pull_request\.head\.(ref|label|sha)"),
    re.compile(r"github\.head_ref"),
    re.compile(r"github\.event\.discussion(_comment)?\.(title|body)"),
    re.compile(r"github\.event\.(pages|commits)\b"),
    re.compile(r"github\.event\.workflow_run\.head_branch"),
    re.compile(r"github\.event\.client_payload"),
    re.compile(r"github\.event\.[A-Za-z_]+\.(message|body|title)"),
    re.compile(r"github\.event\.commits\["),
)

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)

CURL_PIPE = re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b")

REPO_CODE = re.compile(
    r"(?m)^\s*(?:[A-Za-z_][\w]*=\S*\s+)*"
    r"(?:npm|npx|yarn|pnpm|make|pytest|python3?|pip3?|bash|sh|node|go|cargo|mvn|gradle|dotnet|"
    r"composer|bundle|\./|\.github/[\w./-]+\.[a-z]+)\b"
)

WRITE_COMMANDS = (
    re.compile(r"git\s+push\b"),
    re.compile(r"gh\s+release\s+create\b"),
    re.compile(r"gh\s+pr\s+create\b"),
    re.compile(r"npm\s+publish\b"),
    re.compile(r"twine\s+upload\b"),
    re.compile(r"docker\s+push\b"),
)

PR_CREATING_ACTIONS = (
    "peter-evans/create-pull-request",
    "softprops/action-gh-release",
    "actions/create-release",
    "JS-DevTools/npm-publish",
    "pypa/gh-action-pypi-publish",
)

GHA_IDS = ("GHA01", "GHA02", "GHA03", "GHA04", "GHA05", "GHA06", "GHA07")


def load_rules(path=RULES_PATH):
    """Load and validate the pattern metadata."""
    with open(path, "r", encoding="utf-8") as handle:
        rules = json.load(handle)
    if not isinstance(rules, list) or not rules:
        raise ValueError("rules.json must be a non-empty list, got %r" % type(rules).__name__)
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("every rule must be a JSON object")
        for field in REQUIRED_FIELDS:
            if not rule.get(field):
                raise ValueError("rule %r is missing the field %r" % (rule.get("id", "?"), field))
        if rule["id"] in seen:
            raise ValueError("duplicate rule id %r in rules.json" % rule["id"])
        seen.add(rule["id"])
    return rules


def rules_by_id(path=RULES_PATH):
    return {rule["id"]: rule for rule in load_rules(path)}


def _clip(text, limit=120):
    text = " ".join(str(text).split())
    if len(text) > limit:
        return text[: limit - 3].rstrip() + "..."
    return text


def _line_of(text, offset, base):
    return base + text[:offset].count("\n")


def _step_label(job_name, step):
    name = step.get("name")
    if isinstance(name, Scalar) and str(name).strip():
        return "step '%s' in job '%s'" % (_clip(name, 40), job_name)
    return "a step in job '%s'" % job_name


# -- GHA01 ------------------------------------------------------------------


def check_gha01(workflow, text, path):
    out = []
    for job_name, _job, step in iter_steps(workflow):
        uses = step.get("uses")
        if not isinstance(uses, Scalar):
            continue
        value = str(uses).strip()
        line = step.key_line("uses", uses.line)
        where = "a step in job '%s'" % job_name
        if value.startswith("./") or value.startswith(".\\"):
            continue
        if value.startswith("docker://"):
            if "@sha256:" in value:
                continue
            out.append((line, "%s uses %s — a docker:// image pinned by tag; only @sha256: pins the content" % (where, _clip(value, 60))))
            continue
        if "@" in value:
            ref = value.rsplit("@", 1)[1]
            if re.match(r"^[0-9a-fA-F]{40}$", ref):
                continue
            kind = "tag" if re.match(r"^v?\d", ref) else "branch"
            out.append((line, "%s uses %s — pinned by %s %s, not a commit SHA" % (where, _clip(value, 60), kind, ref)))
        else:
            out.append((line, "%s uses %s with no ref at all" % (where, _clip(value, 60))))
    return out


# -- GHA02 ------------------------------------------------------------------


def _head_checkouts(job):
    """(line, ref) for every actions/checkout step checking out the PR head."""
    hits = []
    for step in job.get("steps") if isinstance(job, Map) else []:
        if not isinstance(step, Map):
            continue
        uses = step.get("uses")
        if not isinstance(uses, Scalar) or not str(uses).startswith("actions/checkout"):
            continue
        with_block = step.get("with")
        if not isinstance(with_block, Map):
            continue
        ref = with_block.get("ref")
        if isinstance(ref, Scalar) and HEAD_REF.search(str(ref)):
            hits.append((with_block.key_line("ref", step.line), str(ref).strip()))
    return hits


def check_gha02(workflow, text, path):
    if "pull_request_target" not in triggers(workflow):
        return []
    out = []
    for job_name, job in iter_jobs(workflow):
        hits = _head_checkouts(job)
        if not hits:
            continue
        line, ref = hits[0]
        executes = _first_repo_code_line(job)
        tail = ""
        if executes:
            tail = "; line %d then runs code from that checkout" % executes[0]
        out.append(
            (
                trigger_line(workflow, "pull_request_target"),
                "on: pull_request_target with a checkout of the PR head (line %d, %s) in job '%s'%s"
                % (line, _clip(ref, 40), job_name, tail),
            )
        )
    return out


# -- GHA03 ------------------------------------------------------------------


def check_gha03(workflow, text, path):
    names = triggers(workflow)
    patterns = list(UNTRUSTED_INPUT)
    if names & {"workflow_call", "workflow_dispatch"}:
        patterns.append(re.compile(r"\binputs\.[A-Za-z_][\w-]*"))
    found = []
    for job_name, _job, step in iter_steps(workflow):
        for run_text, base in runs(step):
            for match in EXPRESSION.finditer(run_text):
                expression = match.group(1)
                if not any(p.search(expression) for p in patterns):
                    continue
                quoted = match.start() > 0 and run_text[match.start() - 1] in "\"'"
                line = _line_of(run_text, match.start(), base)
                physical = run_text[: match.start()].count("\n")
                excerpt = run_text.split("\n")[physical].strip() if run_text.split("\n")[physical:] else ""
                found.append(
                    (
                        1 if quoted else 0,
                        line,
                        "%s: %s%s"
                        % (
                            _step_label(job_name, step),
                            _clip(excerpt, 80) or "${{ %s }}" % _clip(expression, 40),
                            " (inside shell quotes)" if quoted else "",
                        ),
                    )
                )
    found.sort(key=lambda item: (item[1], item[0]))
    return [(line, context) for _q, line, context in found]


# -- GHA04 ------------------------------------------------------------------


def _write_evidence(job):
    for step in job.get("steps") if isinstance(job, Map) else []:
        if not isinstance(step, Map):
            continue
        uses = step.get("uses")
        if isinstance(uses, Scalar):
            for action in PR_CREATING_ACTIONS:
                if str(uses).startswith(action):
                    return "uses %s" % action
        for run_text, _line in runs(step):
            for pattern in WRITE_COMMANDS:
                match = pattern.search(run_text)
                if match:
                    return "runs `%s`" % match.group(0)
    return None


def check_gha04(workflow, text, path):
    out = []
    workflow_perm = workflow.get("permissions")
    if isinstance(workflow_perm, Scalar) and str(workflow_perm).strip() == "write-all":
        out.append((workflow.key_line("permissions"), "workflow-level `permissions: write-all`"))
    names = triggers(workflow)
    untrusted = sorted(names & UNTRUSTED_TRIGGERS)
    for job_name, job in iter_jobs(workflow):
        job_line = jobs(workflow).key_line(job_name, job.line)
        perm = job.get("permissions")
        if isinstance(perm, Scalar) and str(perm).strip() == "write-all":
            out.append((job.key_line("permissions"), "job '%s': `permissions: write-all`" % job_name))
        elif perm is None and workflow_perm is None:
            evidence = _write_evidence(job)
            if evidence:
                out.append(
                    (
                        job_line,
                        "job '%s' %s with no `permissions:` declared anywhere" % (job_name, evidence),
                    )
                )
        if isinstance(perm, Map) and str(perm.get("contents", "")).strip() == "write" and untrusted:
            out.append(
                (
                    perm.key_line("contents", job.line),
                    "job '%s': `contents: write` on a job triggered by %s" % (job_name, ", ".join(untrusted)),
                )
            )
    return out


# -- GHA05 ------------------------------------------------------------------


def _self_hosted(node):
    if isinstance(node, Scalar):
        return "self-hosted" in str(node)
    if isinstance(node, Seq):
        return any(str(item).strip() == "self-hosted" for item in node)
    return False


def check_gha05(workflow, text, path):
    names = sorted(triggers(workflow) & {"pull_request", "pull_request_target"})
    if not names:
        return []
    out = []
    for job_name, job in iter_jobs(workflow):
        runs_on = job.get("runs-on")
        if _self_hosted(runs_on):
            out.append(
                (
                    job.key_line("runs-on", job.line),
                    "job '%s': runs-on includes self-hosted and the workflow is triggered by %s"
                    % (job_name, ", ".join(names)),
                )
            )
    return out


# -- GHA06 ------------------------------------------------------------------


def check_gha06(workflow, text, path):
    out = []
    names = sorted(triggers(workflow) & UNTRUSTED_TRIGGERS)
    for job_name, job in iter_jobs(workflow):
        head = bool(_head_checkouts(job))
        environment = job.get("env")
        if head and isinstance(environment, Map):
            for key, value in environment.items():
                if "secrets." in str(value):
                    out.append(
                        (
                            environment.key_line(key, job.line),
                            "job '%s': env %s is a secret and the job checks out PR head code" % (job_name, key),
                        )
                    )
        for step in job.get("steps") if isinstance(job, Map) else []:
            if not isinstance(step, Map):
                continue
            with_block = step.get("with")
            if isinstance(with_block, Map):
                if is_true(with_block.get("persist-credentials")):
                    out.append(
                        (
                            with_block.key_line("persist-credentials", step.line),
                            "checkout leaves the token in .git/config for every later step (persist-credentials: true)",
                        )
                    )
                if head:
                    for key, value in with_block.items():
                        if "secrets." in str(value):
                            out.append(
                                (
                                    with_block.key_line(key, step.line),
                                    "job '%s': %s is a secret in a job that checks out PR head code" % (job_name, key),
                                )
                            )
            for run_text, base in runs(step):
                offset = run_text.find("secrets.")
                if offset != -1:
                    out.append(
                        (
                            _line_of(run_text, offset, base),
                            "%s interpolates a secret into the shell text, which can reach the job log"
                            % _step_label(job_name, step),
                        )
                    )
        called_secrets = job.get("secrets")
        if isinstance(called_secrets, Scalar) and str(called_secrets).strip() == "inherit" and names:
            out.append(
                (
                    job.key_line("secrets", job.line),
                    "job '%s': `secrets: inherit` on a job reachable from %s" % (job_name, ", ".join(names)),
                )
            )
    return out


# -- GHA07 ------------------------------------------------------------------

OUTSIDER_TRIGGERS = ("issue_comment", "workflow_run", "discussion_comment")


def _first_repo_code_line(job, after=0):
    for step in job.get("steps") if isinstance(job, Map) else []:
        if not isinstance(step, Map):
            continue
        for run_text, base in runs(step):
            match = REPO_CODE.search(run_text)
            if match:
                return (_line_of(run_text, match.start(), base), " ".join(run_text[match.start() :].split())[:60])
    return None


def check_gha07(workflow, text, path):
    names = triggers(workflow)
    outsider = sorted(names & set(OUTSIDER_TRIGGERS))
    if not outsider:
        return []
    out = []
    for job_name, job in iter_jobs(workflow):
        checkouts = []
        for step in job.get("steps") if isinstance(job, Map) else []:
            if not isinstance(step, Map):
                continue
            uses = step.get("uses")
            if isinstance(uses, Scalar) and str(uses).startswith("actions/checkout"):
                checkouts.append(step.key_line("uses", step.line))
        for step in job.get("steps") if isinstance(job, Map) else []:
            if not isinstance(step, Map):
                continue
            uses = step.get("uses")
            if isinstance(uses, Scalar):
                value = str(uses)
                if "download-artifact" in value:
                    out.append(
                        (
                            step.key_line("uses", step.line),
                            "job '%s' pulls an artefact the upstream run produced (%s)" % (job_name, _clip(value, 50)),
                        )
                    )
            for run_text, base in runs(step):
                match = CURL_PIPE.search(run_text)
                if match:
                    out.append(
                        (
                            _line_of(run_text, match.start(), base),
                            "job '%s' downloads a script and pipes it into a shell on trigger %s"
                            % (job_name, ", ".join(outsider)),
                        )
                    )
                offset = run_text.find("gh run download")
                if offset != -1:
                    out.append(
                        (
                            _line_of(run_text, offset, base),
                            "job '%s' downloads artefacts from the upstream run" % job_name,
                        )
                    )
        if checkouts:
            executed = _first_repo_code_line(job)
            if executed:
                out.append(
                    (
                        executed[0],
                        "job '%s' checks out the repository (line %d) and runs `%s` on trigger %s"
                        % (job_name, checkouts[0], _clip(executed[1], 40), ", ".join(outsider)),
                    )
                )
    if "workflow_run" in names and "workflow_run.conclusion" not in text:
        out.append(
            (
                trigger_line(workflow, "workflow_run"),
                "on: workflow_run without any check of the upstream run's conclusion",
            )
        )
    return out


CHECKERS = {
    "GHA01": check_gha01,
    "GHA02": check_gha02,
    "GHA03": check_gha03,
    "GHA04": check_gha04,
    "GHA05": check_gha05,
    "GHA06": check_gha06,
    "GHA07": check_gha07,
}


def audit_workflow(workflow, text, path, rules, selected=None):
    """Run the selected patterns over one parsed workflow. Returns findings."""
    findings = []
    for rule in rules:
        rule_id = rule["id"]
        if selected is not None and rule_id not in selected:
            continue
        hits = CHECKERS[rule_id](workflow, text, path)
        seen = set()
        for line, context in sorted(hits, key=lambda item: (item[0], item[1])):
            key = (int(line), context)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    pattern=rule_id,
                    file=path,
                    line=int(line),
                    context=context,
                    message=rule["message"],
                    fix=rule["fix"],
                    anchor=rule["anchor"],
                )
            )
    return findings
