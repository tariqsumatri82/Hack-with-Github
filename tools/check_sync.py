#!/usr/bin/env python3
"""Fail when the pattern count disagrees with itself.

The README number, the length of ghaudit/rules.json and the number of sections
in docs/patterns.md must be the same number, and every rule's slug must have a
section. A pattern that exists only in prose, or a count that outlives the rule
it described, is exactly the kind of drift this project cannot afford.
"""

from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FENCE = re.compile(r"```.*?```", re.S)


def read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def heading_slugs(markdown):
    """GitHub-style anchors for every level-2 heading."""
    slugs = []
    for heading in re.findall(r"(?m)^##\s+(.+?)\s*$", markdown):
        text = FENCE.sub("", heading).lower()
        text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
        slugs.append(re.sub(r"\s", "-", text))
    return slugs


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    problems = []

    with open(os.path.join(ROOT, "ghaudit", "rules.json"), "r", encoding="utf-8") as handle:
        rules = json.load(handle)
    count = len(rules)
    ids = [rule["id"] for rule in rules]

    readme = read(os.path.join(ROOT, "README.md"))
    without_code = FENCE.sub("", readme)
    claims = sorted({int(match) for match in re.findall(r"\b(\d+)\s+patterns?\b", without_code, re.I)})
    if not claims:
        problems.append("README.md makes no '<n> patterns' claim to check")
    for claim in claims:
        if claim != count:
            problems.append("README.md claims %d patterns; rules.json has %d" % (claim, count))

    patterns_md = read(os.path.join(ROOT, "docs", "patterns.md"))
    slugs = heading_slugs(patterns_md)
    for rule in rules:
        if rule["slug"] not in slugs:
            problems.append("docs/patterns.md has no section for %s (expected anchor #%s)" % (rule["id"], rule["slug"]))
    if len(slugs) != count:
        problems.append("docs/patterns.md has %d pattern sections; rules.json has %d" % (len(slugs), count))

    if len(set(ids)) != count:
        problems.append("duplicate pattern ids in rules.json: %s" % ", ".join(sorted(ids)))

    if problems:
        for problem in problems:
            sys.stderr.write("check_sync: %s\n" % problem)
        return 1

    print("check_sync: OK — %d patterns, README and docs/patterns.md both agree with rules.json (%s)"
          % (count, ", ".join(ids)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
