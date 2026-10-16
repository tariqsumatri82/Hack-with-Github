# Contributing to ghaudit

Thanks for looking. The most useful contribution is **a new pattern backed by a
fixture**, and the second most useful is **a fixture that shows a pattern is
wrong** — a false positive is a bug here, because every finding is a claim that
a human should spend time on it.

Everything below applies to `ghaudit`, the auditor that ships in this
repository. The tool is deliberately small: Python 3.9+, standard library only,
no build step, no dependencies.

## Ground rules

- **Standard library only.** No new runtime dependency, ever. If a change needs
  PyYAML, it is optional and it must degrade clearly (`--yaml-cross-check`
  already behaves that way).
- **No network.** Not for tests, not for the tool. `tests/test_cli.py` walks the
  package's AST and fails if `socket`, `ssl`, `urllib`, `http`, `requests`,
  `ftplib`, `smtplib`, `telnetlib` or `xmlrpc` is imported anywhere under
  `ghaudit/`. Do not add one to a test either.
- **Never execute a workflow**, never resolve an action, never query GitHub. The
  tool reads YAML text from the local disk and compares it to the patterns. That
  is the whole design.
- **A finding is a reason to look, not a proven exploit.** Message wording must
  not claim an exploit, a vulnerability, or impact that the text alone cannot
  show. "This path can expose a secret to logged code — FLAG for review" is the
  register; "secret leak" is not.
- **Every claim in the README must be true of the shipped code.** If you cannot
  make a claim true, delete the claim.

## Local development

```bash
git clone https://github.com/tariqsumatri82/gha-security-auditor
cd gha-security-auditor
python3 ghaudit.py --repo .        # the dogfood self-audit; must exit 0
python3 tools/check_sync.py        # the pattern count must agree with itself
python3 -m unittest discover -s tests -v
```

Nothing to install. There is no `setup.py` on purpose: the tool is a script plus
a package you can copy.

## Adding a pattern

A pattern is **five small edits**. They are deliberately small so a reviewer can
see the whole change at once.

### 1. The rule object — `ghaudit/rules.json`

Append one object. Every field is required and is checked at load time
(`REQUIRED_FIELDS` in `ghaudit/rules.py`):

| Field | Meaning |
|---|---|
| `id` | `GHA0N`, unique, never reused. Ids are a stable API: CI configs filter on them. |
| `title` | Short human name, used by `--list-patterns`. |
| `slug` | The GitHub anchor of this pattern's section in `docs/patterns.md`. Must match that heading exactly — see the gotcha below. |
| `why` | Why this shape is dangerous, in one or two sentences. |
| `fix` | The fix, phrased as an instruction. This text is printed with every finding. |
| `message` | The finding sentence itself. |
| `anchor` | The line the finding points at (usually the matched key). |

### 2. The detection — `ghaudit/rules.py`

Add a small function that walks the parsed document and yields `Finding(...)`
objects, and register it in the list of checks. Keep it structural: look at
where a key sits and what it contains. Six of the seven shipped patterns are
"does this key hold this value in this position" and no cleverness is wanted —
a reader must be able to predict what fires by reading the function.

Notes that have bitten before:

- Line numbers come from the parser (`node.key_line(...)`, `scalar.line`). Report
  the line of the *matched* key or value — a finding that cannot name a line is
  not actionable. The fixtures assert exact lines, so a wrong line fails CI.
- Sort findings with the existing `sort_key` (file, line, pattern) rather than
  inventing an order.
- If the pattern needs a value from `on:` (a trigger), use the parser's
  `triggers()` / `trigger_line()` helpers so `on:` in string, list and mapping
  form all behave the same way.

### 3. The section — `docs/patterns.md`

Add one level-2 section, in pattern order, with the reasoning, a real workflow
shape and the fix:

```markdown
## GHA08: What it looks for

Why it matters …

```yaml
# the shape that fires it
```

**Fix:** what to do instead — and the one sentence to keep the "reason to look"
register.
```

**Gotcha:** `tools/check_sync.py` derives each heading's GitHub anchor and
requires it to equal the rule's `slug`, and requires the number of level-2
headings in this file to equal the number of rules. So:

- Keep the heading text and the `slug` in step. `## GHA04: Over-scoped workflow
  token` anchors to `#gha04-over-scoped-workflow-token`; add an extra word in
  one place and not the other and CI fails with "no section for GHA04".
- **Any other `##` heading counts as a pattern section.** Non-pattern prose
  ("Deliberately not shipped") must be `###`.

### 4. The fixtures — `tests/fixtures/workflows/`

Two files, always as a pair:

- `<pattern>-bad.yml` — the shape that must fire, at a known line.
- `<pattern>-fixed.yml` — the same workflow with the fix applied, which must
  produce **zero** findings from any pattern. This is the false-positive guard:
  a pattern that fires on the fixed file is a pattern that will cry wolf on real
  repositories.

Keep fixtures small and realistic. A fixture with three jobs and five steps is
fine; a fixture that is not a plausible workflow is not.

### 5. The expectation table — `tests/test_rules.py`

Add the id to `BAD` with the exact expected line numbers and to `FIXED` with the
file name. The line numbers are the point: they are what stops a later parser
change from silently shifting every finding in the report.

Then update the pattern table and the pattern count in `README.md`.

### 6. Check it

```bash
python3 tools/check_sync.py                        # README count == rules.json == docs sections
python3 -m unittest discover -s tests -v           # fixtures, exit codes, determinism
python3 ghaudit.py --repo .                        # dogfood: this repo must stay clean
```

`tools/check_sync.py` is the guard against the failure mode this project cannot
afford: a count in the README that outlives the rule it described. It fails if
the README claims *n* patterns and `rules.json` has a different number, if any
rule has no section in `docs/patterns.md`, or if the ids are duplicated.

The dogfood step is real: `.github/workflows/ci.yml` runs `python3 ghaudit.py
--repo .` and the job fails unless it exits 0. If your change makes, say, GHA01
fire on this repository's own workflow, the fix is to fix `ci.yml` — the
workflow here is SHA-pinned and `permissions: contents: read` on purpose.

## Retiring a pattern

Patterns rot. When one stops matching the shape it was written for, **remove
it** — do not keep it in the list to pad the count.

1. Delete the rule object, the detection function, the docs section and the
   fixture pair.
2. Bump `AUDIT_VERSION` in `ghaudit/__init__.py` (it tracks the pattern set, not
   the package — they move independently).
3. Record the removal in `CHANGELOG.md`, with the reason and the version.
4. Run the three commands above.

## Reporting a false positive

Open an issue with the workflow text (redacted), what ghaudit said, and what you
expected. A minimal reproduction is worth more than a description: the fixture
pair that would have caught it is usually the fix, and a PR that adds one is
welcome directly.

## Pull requests

- One pattern or one fix per PR, please. Small diffs get reviewed.
- Say in the PR body what the change does, what you ran, and whether the counts
  moved.
- CI runs Python 3.9 and 3.12, the sync check, the suite and the dogfood audit.
  All four must pass.

## Licence

Contributions are accepted under the MIT licence that covers this repository
(see `LICENSE`).
