# ghaudit — GitHub Actions workflow security auditor

A standard-library Python tool that reads `.github/workflows/*.yml` and points at the workflow patterns that cause real supply-chain and script-injection incidents: unpinned actions, `pull_request_target` jobs that check out the pull request head, `${{ }}` interpolated into a shell step, over-scoped `GITHUB_TOKEN` permissions, self-hosted runners on untrusted triggers, secrets in reach of untrusted or logged code, and outsider-drivable triggers that execute code.

It reads YAML text. It never executes a workflow, never resolves an action, never calls the GitHub API and never touches the network.

## What it does

- Discovers workflow files (`--repo .` finds `.github/workflows`, or point it at a directory or a single file).
- Parses them with a small line-preserving reader, so every finding names the file and the exact line to edit.
- Runs **7 patterns** over each file and prints a finding per match: what matched, why it is a reason to look, and the fix.
- Reports as a table, JSON or Markdown; two runs over the same files are byte-identical.
- Exits 0 clean, 1 when there is something to look at, 2 on a usage error, 3 when a file could not be parsed and therefore was not audited.
- Audits its own repository in CI. The GitHub Actions workflow that tests this project is pinned by commit SHA and passes `python3 ghaudit.py --repo .` — the same rules applied to its own CI.

## Status

`0.1.0` — the first release. The parser, the 7 patterns, the report formats, the exit codes and the fixtures are in place and covered by tests. The pattern set is versioned separately (`AUDIT_VERSION`), and pattern coverage is expected to grow as the tool meets real workflows.

## Install

Nothing to install. Python 3.9 or newer and the standard library:

```bash
git clone https://github.com/tariqsumatri82/gha-security-auditor
cd gha-security-auditor
python3 ghaudit.py --repo .
```

No `pip install`, no `requirements.txt`, no PyYAML required. PyYAML is used only if `--yaml-cross-check` is requested and PyYAML happens to be importable.

## Usage

```
python3 ghaudit.py [PATH] [--repo] [--format table|json|md] [--only GHA02,GHA03]
                   [--exclude GHA01] [--fail-on-unparsed] [--write-report OUT]
                   [--yaml-cross-check] [--list-patterns] [-V] [-h]
```

| Flag | What it does |
|---|---|
| `PATH` | a workflow directory, a repository root, or one workflow file |
| `--repo` | treat `PATH` (default `.`) as a repository root and audit its `.github/workflows` |
| `--format table\|json\|md` | report format, default `table` |
| `--only GHA02,GHA03` | run only these patterns |
| `--exclude GHA01` | run everything but these |
| `--fail-on-unparsed` | state explicitly that an unparsed workflow is a failure (exit 3, which is also the default) |
| `--write-report OUT` | also write the rendered report to a file |
| `--yaml-cross-check` | when PyYAML is importable, load the file with it first and fail loudly on disagreement |
| `--list-patterns` | print the pattern ids and titles |
| `-V` | print the version and the pattern-set version |

Common invocations:

```bash
python3 ghaudit.py .github/workflows
python3 ghaudit.py --repo .
python3 ghaudit.py --repo . --format json --write-report ghaudit.json
```

## Example output

Real captured run, on the two example workflows committed in `examples/`
(reproduce it with `python3 ghaudit.py examples`):

```
$ python3 ghaudit.py examples
ghaudit 0.1.0 — 2 workflow files, 2 jobs, 4 steps

pr.yml
  GHA02  line 7    on: pull_request_target with a checkout of the PR head (line 19, ${{ github.event.pull_request.head.sh...) in job 'triage'; line 23 then runs code from that checkout  FLAG for review
         This runs untrusted pull-request code with a write-scoped token and secrets in scope — FLAG for review: confirm why pull_request_target is needed and whether the head checkout can go.
         fix: Use pull_request instead of pull_request_target, or drop the head checkout and work only from the base branch, or split the job so nothing from the fork runs in the privileged workflow.
  GHA01  line 17   a step in job 'triage' uses actions/checkout@v4 — pinned by tag v4, not a commit SHA  FLAG for review
         Action is pinned by tag or branch, not a commit SHA — FLAG for review: the tag can be moved to new code under you.
         fix: Pin the ref to a full 40-character commit SHA and keep the tag in a trailing comment, e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  GHA03  line 22   step 'Greet the contributor' in job 'triage': echo "PR title: ${{ github.event.pull_request.title }}"  FLAG for review
         Untrusted event data is interpolated directly into a shell step — FLAG for review: pass it through `env:` and quote the variable.
         fix: Pass the value through env: and reference the variable, quoting it in the shell: env: {TITLE: "${{ github.event.issue.title }}"} then run: echo "$TITLE"
release.yml
  GHA04  line 8    workflow-level `permissions: write-all`  FLAG for review
         The workflow token carries more scope than this job needs — FLAG for review: grant only the scopes this job needs.
         fix: Declare the scopes the job needs and nothing else — usually permissions: {contents: read} at workflow level, and contents: write only on the one job that has to write.
  GHA06  line 19   step 'Publish to the registry' in job 'release' interpolates a secret into the shell text, which can reach the job log  FLAG for review
         This path can expose a secret to untrusted or logged code — FLAG for review: check whether the secret has to be in scope here at all.
         fix: Keep secrets out of jobs that touch pull-request code, pass them by name through env: at the step that needs them, never echo them, and set persist-credentials: false when the checkout does not need to push.
5 flags for review. Every line above is a pattern in the workflow text — a reason to look, not a proven exploit.
```

Exit code: `1`.

## The 7 patterns

Every pattern is documented with the reasoning, a real workflow shape and the fix in [`docs/patterns.md`](docs/patterns.md).

| Pattern | Flags | Fix |
|---|---|---|
| [GHA01](docs/patterns.md#gha01-unpinned-third-party-action) | `uses:` pinned by tag or branch, not a commit SHA | pin the full 40-character SHA, keep the tag in a comment |
| [GHA02](docs/patterns.md#gha02-pull-request-target-with-head-checkout) | `pull_request_target` **and** a checkout of the PR head | use `pull_request`, or drop the head checkout |
| [GHA03](docs/patterns.md#gha03-interpolation-into-run) | `${{ }}` with untrusted event data inside `run:` | pass it through `env:` and quote `"$VAR"` |
| [GHA04](docs/patterns.md#gha04-over-scoped-token) | `permissions: write-all`, or a pushing job with no `permissions:` | declare per-job scopes, default `contents: read` |
| [GHA05](docs/patterns.md#gha05-self-hosted-runner-on-an-untrusted-trigger) | `self-hosted` runner plus `pull_request(_target)` | GitHub-hosted runner, or an ephemeral isolated host |
| [GHA06](docs/patterns.md#gha06-secrets-reachable-by-untrusted-or-logged-code) | secrets in `env:`/`with:`/`run:` next to untrusted code; `persist-credentials: true` | keep secrets out of that job, never echo them |
| [GHA07](docs/patterns.md#gha07-outsider-drivable-trigger-executing-code) | `issue_comment` / `discussion_comment` / `workflow_run` jobs that run code | gate on author and upstream conclusion, treat artefacts as untrusted |

The count is machine-checked: `tools/check_sync.py` fails CI if the README, `ghaudit/rules.json` and `docs/patterns.md` disagree about how many patterns there are.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no flags for review |
| 1 | at least one flag for review |
| 2 | usage error — bad arguments, unknown pattern id, target that does not exist |
| 3 | a workflow file could not be parsed and was **not** audited |

Exit 3 is separate from 1 on purpose: CI can tell "audited clean" from "not audited". A file ghaudit cannot parse is never guessed at — it is reported with the line and the reason.

## Using it in CI

```yaml
- name: Audit workflows
  run: python3 ghaudit.py --repo . --format md --write-report ghaudit.md
```

The exit code does the work: 1 means there is something to review, 3 means part of the set was not read. `--format json` writes a documented object (`tool`, `version`, `audit_version`, `root`, `files[]` with `path`, `parsed`, `jobs`, `steps`, `findings[]` of `id`, `line`, `context`, `message`, `fix`, `anchor`, plus `totals`) for a dashboard or a review comment. See [`docs/ci-recipes.md`](docs/ci-recipes.md).

## YAML parsing: what it supports, and what it does not

ghaudit ships its own reader for the workflow subset instead of depending on PyYAML, so it runs anywhere Python runs with no install step, and so every key and value carries the physical line it came from — a finding that cannot name a line is not actionable.

**Supported:** block mappings, block sequences, nested jobs → steps, quoted and plain strings, trailing comments, literal (`|`) and folded (`>`) block scalars with chomping, flow sequences and mappings (`runs-on: [self-hosted, x64]`, `permissions: {}`), `on:` in string, list and mapping form, CRLF input, and multi-document markers. Line numbers are preserved for every key and value; a block scalar reports the line of its first content line.

**Refused, not guessed:** tab characters in indentation (GitHub rejects them too), YAML anchors and aliases, unterminated quotes, and any line that is neither a mapping entry nor a sequence item. A refused file is reported as unparsed with its line and reason and is not audited.

**This is not a YAML validator.** It understands the subset workflow files actually use and stops at the edge of it. Run [actionlint](https://github.com/rhysd/actionlint) alongside it — actionlint validates syntax, expressions and runner labels; ghaudit looks for the 7 patterns above.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 tools/check_sync.py
```

No test touches the network. A test walks the package's AST and fails if `socket`, `ssl`, `urllib`, `http.client` or `requests` is imported anywhere in `ghaudit/`. Fixtures live in `tests/fixtures/`: for each pattern a `<pattern>-bad.yml` that must fire at a known line and a `<pattern>-fixed.yml` that must produce no findings at all — the false-positive guard.

## What this is not

- **A flag is a reason to look, not a proven exploit.** Every finding is a pattern match in the workflow text. Whether the workflow is exploitable depends on the repository, its token scopes, its secrets and its reviewers — none of which ghaudit can see.
- **A clean run proves nothing.** It means these 7 patterns were not found in the files that were read. It does not mean the workflows are safe.
- **It is a static text scanner.** It never executes a workflow, never resolves an action to its code, never queries GitHub and never calls anything over the network. Nothing about your repository leaves the machine it runs on.
- **It cannot see past the file.** Composite-action internals, reusable workflows defined in other repositories, runtime-resolved refs (`uses: ${{ … }}`), org-level secrets, organisation permissions policy and whether a runner is ephemeral are all outside what a text reader can know.
- **It flags `pull_request_target` only when the pull request head is checked out**, because the trigger alone has legitimate uses. It does not judge OIDC/`id-token` usage, because the policy that makes OIDC safe or unsafe lives in the cloud account, not in the workflow.
- **The threat model is mostly untrusted contributors.** Several patterns are far less interesting in a private repository with a handful of trusted contributors: GHA01's risk depends on who can move the tag, and GHA03 needs an event an outsider can write. A private-repo audit should weigh the findings accordingly, and the tool says so instead of scoring them.
- **Not a substitute for review or a pen test.** It is a checklist that never gets tired, pointed at one file type.
- **Patterns rot, and they are retired deliberately.** Patterns are dated and versioned (`AUDIT_VERSION`). When a pattern stops matching the shape it was written for, it is removed and the removal recorded in `CHANGELOG.md` — never kept in the list to pad the count.

## Contributing

Adding a pattern is four small edits: one object in `ghaudit/rules.json`, one section in `docs/patterns.md`, a `<pattern>-bad.yml` / `<pattern>-fixed.yml` fixture pair, and a line in the test's expectation table. Then run `python3 tools/check_sync.py` and the test suite. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Roadmap

- More real-world workflow shapes as fixtures, especially reusable workflows and matrix-heavy release pipelines.
- An optional SARIF output for GitHub code scanning.
- A `--baseline FILE` mode so a team can adopt the tool on an existing repository without fixing everything at once.

Nothing on this list is a promise about a date; the pattern set and the honesty rules above constrain what gets added.

## Licence

MIT — see [LICENSE](LICENSE).
