# Changelog

All notable changes to this project are documented here. This project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.0 — initial release

First release of `ghaudit`, a GitHub Actions workflow security auditor that
reads YAML text and flags the patterns behind real supply-chain and
script-injection incidents.

### Added

- **Seven audit patterns**, `GHA01`–`GHA07`, each documented with its reasoning,
  a real workflow shape and the fix in [`docs/patterns.md`](docs/patterns.md):
  - `GHA01` unpinned third-party action (tag or branch ref instead of a commit SHA)
  - `GHA02` `pull_request_target` with a checkout of the PR head
  - `GHA03` untrusted event data interpolated into `run:`
  - `GHA04` over-scoped workflow token (`permissions: write-all`, or a pushing
    job with no `permissions:` declared)
  - `GHA05` self-hosted runner reached by `pull_request`/`pull_request_target`
  - `GHA06` secrets reachable by untrusted or logged code
  - `GHA07` outsider-drivable triggers (`issue_comment`, `workflow_run`,
    `discussion_comment`) whose job executes code
- **A line-preserving workflow YAML reader** in the standard library
  (`ghaudit/parser.py`): block mappings, block sequences, nested jobs → steps,
  quoted and plain strings, trailing comments, literal and folded block scalars,
  flow sequences and mappings, `on:` in string/list/mapping form, CRLF input.
  Every finding names the physical line it came from. A file outside the
  supported subset is reported as unparsed with the line and the reason and is
  not audited — never guessed at.
- **Report formats** `table`, `json` and `md` (`--format`), plus `--write-report`
  to keep a copy. The JSON object and its keys are documented as a stable
  contract; the table is for humans.
- **Exit codes built for CI**: `0` no flags, `1` at least one flag, `2` usage
  error, `3` a workflow file could not be parsed. `3` is separate from `1` so a
  pipeline can tell "audited clean" from "not audited". `--fail-on-unparsed`
  states that expectation explicitly. See [`docs/ci-recipes.md`](docs/ci-recipes.md).
- **Filters** `--only` / `--exclude` by pattern id, and `--list-patterns`, and
  `--yaml-cross-check` (optional, uses PyYAML when it happens to be installed and
  fails loudly on disagreement — PyYAML is never a dependency).
- **Fixtures and tests with no network access.** For every pattern a
  `<pattern>-bad.yml` fixture that must fire at a known line and a
  `<pattern>-fixed.yml` that must produce no findings — the false-positive
  guard. Plus parser tests, exit-code tests, JSON-shape tests, a determinism
  test, and an AST import scan that fails if any network or subprocess module is
  imported anywhere in `ghaudit/`.
- **`tools/check_sync.py`**, which fails when the pattern count in the README,
  the length of `ghaudit/rules.json` and the number of pattern sections in
  `docs/patterns.md` disagree — a count that outlives the rule it described is
  the failure mode this project cannot afford.
- **CI** (`.github/workflows/ci.yml`): Python 3.9 and 3.12, every action pinned
  by commit SHA, `permissions: contents: read`, the sync check, the test suite,
  and a **dogfood self-audit** — `python3 ghaudit.py --repo .` against this
  repository's own workflows, which must exit 0.
- **MIT licence**, `CONTRIBUTING.md`, and `docs/scope.md` describing exactly what
  the tool reads and what it never does.

### Notes

- **`AUDIT_VERSION`** (`ghaudit.AUDIT_VERSION`, printed by `-V` and included in
  the JSON report) tracks the **pattern set**, not the package. The two move
  independently: `__version__` changes for any release, `AUDIT_VERSION` changes
  when a pattern is added, altered or retired. Store it next to a stored report
  so you can tell which pattern set produced it.
- **Retiring a pattern is a deliberate, recorded act.** When a pattern stops
  matching the shape it was written for it is removed — never kept in the list to
  pad the count — and the removal is recorded here with its reason and the
  `AUDIT_VERSION` that dropped it.
- Patterns deliberately **not** shipped, and the reasoning, are listed at the end
  of [`docs/patterns.md`](docs/patterns.md): commenting on `pull_request_target`
  alone, judging `id-token`/OIDC usage, anything needing action contents or a
  network lookup, and general YAML linting.
- The tool reads YAML text only. It never executes a workflow, never resolves an
  action, never queries GitHub, and has no network code at all.
- **Known gap in `GHA06`.** A secret referenced in a *job-level* `env:` is
  flagged, and so is `persist-credentials: true` and a secret written into a
  `run:` step's text. A secret passed through a *step-level* `env:` in a job that
  also checks out the pull-request head is not flagged yet. The fixture for the
  pattern states this in a comment, so the gap is visible in the tests rather
  than hidden by them; closing it is a candidate for the next release.
