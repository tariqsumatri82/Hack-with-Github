"""A line-preserving reader for the workflow subset of YAML.

This is deliberately not a YAML implementation. Workflow files use a narrow
subset — block mappings, block sequences, block scalars, quoted and plain
strings, flow sequences — and this reader understands exactly that subset and
records the physical line of every key and every value, because a finding is
only actionable if it names the line it came from.

Anything outside the subset raises ParseError naming the line and the reason.
The caller reports that file as unparsed and does not audit it. Guessing at a
file we cannot read would be worse than saying we could not read it.
"""

from __future__ import annotations

import re

_PLAIN_KEY = re.compile(r"^[A-Za-z_$\"'][\w.$-]*$")


class ParseError(Exception):
    """The file is outside the supported workflow subset."""

    def __init__(self, line, reason):
        Exception.__init__(self, "line %s: %s" % (line, reason))
        self.line = int(line)
        self.reason = reason


class Scalar(str):
    """A string value that remembers the line it started on."""

    def __new__(cls, value, line=0, quoted=False, block=False, style=None):
        obj = str.__new__(cls, value)
        obj.line = int(line)
        obj.quoted = bool(quoted)
        obj.block = bool(block)
        obj.style = style
        return obj

    def __repr__(self):  # pragma: no cover - debugging helper
        return "Scalar(%r, line=%d)" % (str(self), self.line)


class Map(dict):
    """A block mapping. ``key_lines`` maps each key to its 1-based line."""

    def __init__(self, line=0):
        dict.__init__(self)
        self.line = int(line)
        self.key_lines = {}

    def key_line(self, key, default=0):
        return self.key_lines.get(key, default or self.line)


class Seq(list):
    """A block or flow sequence."""

    def __init__(self, line=0):
        list.__init__(self)
        self.line = int(line)

    @property
    def item_lines(self):
        return [getattr(item, "line", self.line) for item in self]


def is_true(node):
    return isinstance(node, Scalar) and str(node).strip().lower() == "true"


_REPO_CODE = re.compile(
    r"(?m)^\s*(?:[A-Za-z_][\w]*=\S*\s+)*(?:"
    r"npm|npx|yarn|pnpm|make|pytest|python3?|pip3?|bash|sh|node|go|cargo|mvn|gradle|dotnet|"
    r"composer|bundle|\./|/tmp/|\.github/[\w./-]+\.[a-z]+"
    r")\b"
)
"""Commands that would run code from the checked-out repository."""


def strip_comment(text):
    """Remove a trailing YAML comment, respecting quotes."""
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text


def triggers(workflow):
    """Trigger names from ``on:`` in string, list or mapping form."""
    names = set()
    node = workflow.get("on") if isinstance(workflow, Map) else None
    if isinstance(node, Scalar):
        if str(node).strip():
            names.add(str(node).strip())
    elif isinstance(node, Seq):
        for item in node:
            if isinstance(item, Scalar) and str(item).strip():
                names.add(str(item).strip())
    elif isinstance(node, Map):
        names.update(str(k) for k in node.keys())
    return names


def trigger_line(workflow, name):
    """Line of ``on:`` — or of the named trigger key in mapping form."""
    node = workflow.get("on")
    if isinstance(node, Map) and name in node.key_lines:
        return node.key_lines[name]
    return workflow.key_line("on", 1)


def jobs(workflow):
    node = workflow.get("jobs")
    return node if isinstance(node, Map) else Map()


def iter_jobs(workflow):
    for name, job in jobs(workflow).items():
        if isinstance(job, Map):
            yield name, job


def steps_of(job):
    node = job.get("steps") if isinstance(job, Map) else None
    if isinstance(node, Seq):
        return [s for s in node if isinstance(s, Map)]
    return []


def iter_steps(workflow):
    """Yield (job_name, job, step) in file order."""
    for name, job in iter_jobs(workflow):
        for step in steps_of(job):
            yield name, job, step


def runs(step):
    """Yield (text, first_line) for every ``run:`` value in a step."""
    node = step.get("run")
    if isinstance(node, Scalar):
        yield str(node), node.line


class Parser(object):
    def __init__(self, text):
        self.raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.lines = []  # (physical index, indent, text) for significant lines
        for index, line in enumerate(self.raw):
            if line.strip() == "":
                continue
            lead = line[: len(line) - len(line.lstrip(" \t"))]
            if "\t" in lead:
                raise ParseError(
                    index + 1,
                    "tab used in indentation (GitHub Actions rejects tabs in workflow YAML)",
                )
            indent = len(lead)
            body = line[indent:]
            if body.startswith("#") or body in ("---", "..."):
                continue
            self.lines.append((index, indent, body))

    def parse(self):
        if not self.lines:
            return Map(line=1)
        node, index = self._block(0, self.lines[0][1])
        if index < len(self.lines):
            physical, _, _ = self.lines[index]
            raise ParseError(physical + 1, "unexpected indentation")
        return node

    # -- internals ---------------------------------------------------------

    def _block(self, index, indent):
        _, actual, text = self.lines[index]
        if text == "-" or text.startswith("- "):
            return self._seq(index, actual)
        return self._map(index, actual)

    def _split_key(self, text, line):
        if text[0] in "'\"":
            quote = text[0]
            out = []
            i = 1
            while i < len(text):
                ch = text[i]
                if quote == '"' and ch == "\\":
                    out.append(text[i : i + 2])
                    i += 2
                    continue
                if ch == quote:
                    if quote == "'" and text[i + 1 : i + 2] == "'":
                        out.append("'")
                        i += 2
                        continue
                    break
                out.append(ch)
                i += 1
            else:
                raise ParseError(line, "unterminated quoted key")
            if text[i + 1 : i + 2] != ":":
                raise ParseError(line, "expected ':' after quoted key")
            return "".join(out), text[i + 2 :].strip()
        colon = text.find(":")
        if colon == -1:
            raise ParseError(line, "expected a 'key: value' entry, found %r" % text[:40])
        return text[:colon].strip(), text[colon + 1 :].strip()

    def _map(self, index, indent, first=None):
        mapping = Map(line=(first[1] + 1) if first else (self.lines[index][0] + 1))
        pending = first
        while True:
            if pending is not None:
                text, physical = pending
                pending = None
            else:
                if index >= len(self.lines):
                    break
                physical, actual, text = self.lines[index]
                if actual < indent:
                    break
                if actual > indent:
                    raise ParseError(
                        physical + 1, "unexpected indentation (expected %d spaces)" % indent
                    )
                if text == "-" or text.startswith("- "):
                    break
            key, rest = self._split_key(text, physical + 1)
            if not key:
                raise ParseError(physical + 1, "empty key")
            mapping.key_lines[key] = physical + 1
            if rest == "" or rest.startswith("#"):
                nxt = self.lines[index + 1] if index + 1 < len(self.lines) else None
                if nxt is not None and nxt[1] > indent:
                    value, index = self._block(index + 1, nxt[1])
                else:
                    # An empty value with nothing nested under it: the key is
                    # the entry, and the next line is the next entry. Not
                    # advancing here would re-read this line forever.
                    value = Scalar("", physical + 1)
                    index += 1
            elif rest[0] in "|>":
                value, index = self._block_scalar(rest, physical, indent)
            else:
                value = self._value(rest, physical + 1)
                index += 1
            mapping[key] = value
        return mapping, index

    def _seq(self, index, indent):
        items = Seq(line=self.lines[index][0] + 1)
        while index < len(self.lines):
            physical, actual, text = self.lines[index]
            if actual < indent:
                break
            if actual > indent:
                raise ParseError(
                    physical + 1, "unexpected indentation (expected %d spaces)" % indent
                )
            if not (text == "-" or text.startswith("- ")):
                break
            item_line = physical + 1
            rest = text[1:].strip() if text != "-" else ""
            if rest == "":
                nxt = self.lines[index + 1] if index + 1 < len(self.lines) else None
                if nxt is not None and nxt[1] > indent:
                    node, index = self._block(index + 1, nxt[1])
                else:
                    node = Scalar("", item_line)
                    index += 1
            elif self._is_map_entry(rest):
                column = indent + text.find(rest)
                node, index = self._map(index, column, first=(rest, physical))
            else:
                node = self._value(rest, item_line)
                index += 1
            items.append(node)
        return items, index

    @staticmethod
    def _is_map_entry(rest):
        if rest[0] in "'\"[{" or rest.startswith("- "):
            return False
        colon = rest.find(":")
        if colon == -1:
            return False
        if not (colon + 1 == len(rest) or rest[colon + 1] in " \t" or rest[colon + 1] == "#"):
            return False
        return bool(_PLAIN_KEY.match(rest[:colon].strip()))

    def _value(self, rest, line):
        if rest[0] in "'\"":
            quote = rest[0]
            out = []
            i = 1
            while i < len(rest):
                ch = rest[i]
                if quote == '"' and ch == "\\":
                    out.append(rest[i + 1 : i + 2])
                    i += 2
                    continue
                if ch == quote:
                    if quote == "'" and rest[i + 1 : i + 2] == "'":
                        out.append("'")
                        i += 2
                        continue
                    break
                out.append(ch)
                i += 1
            else:
                raise ParseError(line, "unterminated quoted value")
            tail = strip_comment(rest[i + 1 :]).strip()
            if tail:
                raise ParseError(line, "unexpected text after quoted value: %r" % tail)
            return Scalar("".join(out), line, quoted=True)
        if rest[0] in "[{":
            return self._flow(rest, line)
        if rest[0] == "&" or re.match(r"^\*[A-Za-z_]", rest):
            raise ParseError(line, "YAML anchors and aliases are outside the supported subset")
        return Scalar(strip_comment(rest), line)

    def _flow(self, rest, line):
        close = "]" if rest[0] == "[" else "}"
        quote = None
        depth = 0
        inner = None
        i = 0
        while i < len(rest):
            ch = rest[i]
            if quote:
                if quote == '"' and ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
                if depth == 0:
                    inner = rest[1:i]
                    break
            i += 1
        if inner is None:
            raise ParseError(line, "unterminated flow %s" % ("sequence" if close == "]" else "mapping"))
        tail = strip_comment(rest[i + 1 :]).strip()
        if tail:
            raise ParseError(line, "unexpected text after flow value: %r" % tail)
        parts = self._flow_parts(inner)
        if close == "]":
            node = Seq(line=line)
            for part in parts:
                node.append(self._value(part, line))
            return node
        node = Map(line=line)
        for part in parts:
            if ":" not in part:
                raise ParseError(line, "flow mapping entry without ':' : %r" % part)
            key, value = part.split(":", 1)
            key = key.strip()
            value = value.strip()
            node.key_lines[key] = line
            node[key] = self._value(value, line) if value else Scalar("", line)
        return node

    @staticmethod
    def _flow_parts(inner):
        if not inner.strip():
            return []
        parts = []
        current = []
        quote = None
        depth = 0
        i = 0
        while i < len(inner):
            ch = inner[i]
            if quote:
                current.append(ch)
                if quote == '"' and ch == "\\":
                    current.append(inner[i + 1 : i + 2])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
                current.append(ch)
            elif ch in "[{":
                depth += 1
                current.append(ch)
            elif ch in "]}":
                depth -= 1
                current.append(ch)
            elif ch == "," and depth == 0:
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
            i += 1
        parts.append("".join(current).strip())
        return [p for p in parts if p != ""]

    def _block_scalar(self, header, physical, indent):
        style = header[0]
        match = re.match(r"^([+-]?)(\d*)\s*(#.*)?$", header[1:])
        if not match:
            raise ParseError(physical + 1, "unsupported block scalar header %r" % header)
        chomp = match.group(1)
        collected = []
        first_content = None
        j = physical + 1
        while j < len(self.raw):
            line = self.raw[j]
            if line.strip() == "":
                collected.append("")
                j += 1
                continue
            line_indent = len(line) - len(line.lstrip(" "))
            if line_indent <= indent:
                break
            if first_content is None:
                first_content = j + 1
            collected.append(line)
            j += 1
        while collected and collected[-1] == "":
            collected.pop()
        if not collected or first_content is None:
            body = ""
            content_line = physical + 1
        else:
            widths = [len(l) - len(l.lstrip(" ")) for l in collected if l.strip()]
            base = min(widths)
            out = [l[base:] if l.strip() else "" for l in collected]
            if style == "|":
                body = "\n".join(out)
            else:
                chunks = []
                blank = True
                for line in out:
                    if line == "":
                        chunks.append("\n")
                        blank = True
                    else:
                        chunks.append(line if blank else " " + line)
                        blank = False
                body = "".join(chunks)
            content_line = first_content
        if chomp != "-":
            body += "\n"
        node = Scalar(body, content_line, block=True, style=style)
        index = len(self.lines)
        for k in range(len(self.lines)):
            if self.lines[k][0] >= j:
                index = k
                break
        return node, index


def parse(text):
    """Parse workflow text into Map/Seq/Scalar, or raise ParseError."""
    return Parser(text).parse()


def parse_file(path):
    """Parse a file, returning (node, error_reason). Never raises."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return parse(handle.read()), None
    except ParseError as exc:
        return None, str(exc)
    except OSError as exc:
        return None, "could not read file: %s" % exc.strerror
