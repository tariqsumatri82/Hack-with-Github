"""Table, JSON and Markdown renderers over an AuditResult.

Two runs over the same files produce byte-identical output in every format:
findings are ordered by file, then line, then pattern id, and nothing in the
output depends on filesystem iteration order or on the current time.
"""

from __future__ import annotations

import json

FOOTER = (
    "Every line above is a pattern in the workflow text — a reason to look, "
    "not a proven exploit."
)


def _plural(count, singular, plural=None):
    return "%d %s" % (count, singular if count == 1 else (plural or singular + "s"))


def _header(result):
    totals = result.totals
    return "%s %s — %s, %s, %s" % (
        result.tool,
        result.version,
        _plural(totals["files"], "workflow file"),
        _plural(totals["jobs"], "job"),
        _plural(totals["steps"], "step"),
    )


def render_table(result):
    totals = result.totals
    out = [_header(result), ""]
    for file_result in result.files:
        if file_result.parsed and not file_result.findings:
            continue
        out.append(file_result.path)
        if not file_result.parsed:
            out.append("  NOT AUDITED  %s" % file_result.error)
            out.append("")
            continue
        for finding in sorted(file_result.findings, key=lambda f: f.sort_key):
            out.append("  %s  line %-4d %s  %s" % (finding.pattern, finding.line, finding.context, finding.flag_text))
            out.append("         %s" % finding.message)
            out.append("         fix: %s" % finding.fix)
        out.append("")
    if totals["files"] == 0:
        out.append("No workflow files found — nothing was audited.")
    elif totals["findings"] == 0 and not totals["files_unparsed"]:
        out.append("No flags for review in %s." % _plural(totals["files"], "workflow file"))
    elif totals["findings"]:
        out.append("%s for review. %s" % (_plural(totals["findings"], "flag"), FOOTER))
    if totals["files_unparsed"]:
        out.append(
            "%s could not be parsed and %s not audited — the file's contents were not guessed at."
            % (
                _plural(totals["files_unparsed"], "workflow file"),
                "was" if totals["files_unparsed"] == 1 else "were",
            )
        )
    return "\n".join(out).rstrip() + "\n"


def render_json(result):
    return json.dumps(result.to_dict(), indent=2, sort_keys=False) + "\n"


def _cell(text):
    return " ".join(str(text).split()).replace("|", "\\|")


def render_md(result):
    totals = result.totals
    out = ["# ghaudit report", "", "`%s %s` (audit %s) — %s, %s, %s" % (
        result.tool,
        result.version,
        result.audit_version,
        _plural(totals["files"], "workflow file"),
        _plural(totals["jobs"], "job"),
        _plural(totals["steps"], "step"),
    ), ""]
    for file_result in result.files:
        if not file_result.parsed:
            out.append("## %s" % file_result.path)
            out.append("")
            out.append("**Not audited:** %s" % file_result.error)
            out.append("")
            continue
        if not file_result.findings:
            continue
        out.append("## %s" % file_result.path)
        out.append("")
        out.append("| Pattern | Line | What matched | Why it is flagged | Fix |")
        out.append("|---|---|---|---|---|")
        for finding in sorted(file_result.findings, key=lambda f: f.sort_key):
            out.append(
                "| %s | %d | %s | %s | %s |"
                % (
                    finding.pattern,
                    finding.line,
                    _cell(finding.context),
                    _cell(finding.message),
                    _cell(finding.fix),
                )
            )
        out.append("")
    if totals["files"] == 0:
        out.append("No workflow files found — nothing was audited.")
    elif totals["findings"]:
        out.append("%s for review. %s" % (_plural(totals["findings"], "flag"), FOOTER))
    else:
        out.append("No flags for review.")
    if totals["files_unparsed"]:
        out.append("")
        out.append(
            "%s could not be parsed and %s not audited."
            % (
                _plural(totals["files_unparsed"], "workflow file"),
                "was" if totals["files_unparsed"] == 1 else "were",
            )
        )
    return "\n".join(out).rstrip() + "\n"


RENDERERS = {"table": render_table, "json": render_json, "md": render_md}


def render(result, fmt="table"):
    try:
        renderer = RENDERERS[fmt]
    except KeyError:
        raise ValueError("unknown format %r" % fmt)
    return renderer(result)
