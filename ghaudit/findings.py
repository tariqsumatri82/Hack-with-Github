"""The finding model and the stable ordering every renderer relies on."""

from __future__ import annotations


class Finding(object):
    """One pattern match at one line of one workflow file."""

    __slots__ = ("pattern", "file", "line", "context", "message", "fix", "anchor", "flag_text")

    def __init__(self, pattern, file, line, context, message, fix, anchor, flag_text="FLAG for review"):
        self.pattern = pattern
        self.file = file
        self.line = int(line)
        self.context = context
        self.message = message
        self.fix = fix
        self.anchor = anchor
        self.flag_text = flag_text

    @property
    def sort_key(self):
        return (self.file, self.line, self.pattern)

    def to_dict(self):
        return {
            "id": self.pattern,
            "line": self.line,
            "context": self.context,
            "message": self.message,
            "fix": self.fix,
            "anchor": self.anchor,
        }

    def __repr__(self):  # pragma: no cover - debugging helper
        return "Finding(%s, %s:%d)" % (self.pattern, self.file, self.line)


class FileResult(object):
    """One workflow file: whether it could be read, and what was found."""

    __slots__ = ("path", "parsed", "error", "jobs", "steps", "findings")

    def __init__(self, path, parsed=True, error=None, jobs=0, steps=0, findings=None):
        self.path = path
        self.parsed = parsed
        self.error = error
        self.jobs = jobs
        self.steps = steps
        self.findings = findings or []

    def to_dict(self):
        data = {
            "path": self.path,
            "parsed": self.parsed,
            "jobs": self.jobs,
            "steps": self.steps,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: f.sort_key)],
        }
        if self.error is not None:
            data["error"] = self.error
        return data


class AuditResult(object):
    """Everything one run produced. Renderers take this and nothing else."""

    __slots__ = ("tool", "version", "audit_version", "root", "files")

    def __init__(self, tool, version, audit_version, root, files):
        self.tool = tool
        self.version = version
        self.audit_version = audit_version
        self.root = root
        self.files = sorted(files, key=lambda f: f.path)

    @property
    def findings(self):
        out = []
        for f in self.files:
            out.extend(f.findings)
        return sorted(out, key=lambda f: f.sort_key)

    @property
    def unparsed(self):
        return [f for f in self.files if not f.parsed]

    @property
    def totals(self):
        counts = {}
        for f in self.findings:
            counts[f.pattern] = counts.get(f.pattern, 0) + 1
        return {
            "files": len(self.files),
            "files_parsed": len([f for f in self.files if f.parsed]),
            "files_unparsed": len(self.unparsed),
            "jobs": sum(f.jobs for f in self.files),
            "steps": sum(f.steps for f in self.files),
            "findings": len(self.findings),
            "by_pattern": {k: counts[k] for k in sorted(counts)},
        }

    @property
    def exit_code(self):
        if self.unparsed:
            return 3
        if self.findings:
            return 1
        return 0

    def to_dict(self):
        return {
            "tool": self.tool,
            "version": self.version,
            "audit_version": self.audit_version,
            "root": self.root,
            "files": [f.to_dict() for f in self.files],
            "totals": self.totals,
        }
