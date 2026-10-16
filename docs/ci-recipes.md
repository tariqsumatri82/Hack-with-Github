# Using ghaudit in CI

The exit code does the work, so the recipe is short. This page is about the part
people get wrong: telling *"audited clean"* apart from *"part of the set was not
audited"*.

## Exit codes

| Code | Meaning | What a pipeline should do |
|---|---|---|
| `0` | No flags for review in the files that were read. | Pass. |
| `1` | At least one flag for review. | Fail the build, or publish the report and review it — your call. |
| `2` | Usage error: bad arguments, unknown pattern id, target that does not exist. | Fail loudly. This is a broken pipeline, not a finding. |
| `3` | At least one workflow file could not be parsed and was **not** audited. | Treat as failure. The tool did not see part of the set, so `0` would be a lie. |

`3` is deliberately separate from `1`: a file ghaudit cannot read is reported
with its line and the reason and then skipped, never guessed at. A pipeline that
collapses `1` and `3` into "non-zero" throws that distinction away, and a
pipeline that swallows `3` reports a clean audit it did not perform.

`--fail-on-unparsed` states that expectation explicitly. It changes no
behaviour — `3` is already the exit code — and it exists so the intent is
visible in the workflow file rather than remembered.

## Copy-paste step

```yaml
- name: Audit workflows
  run: python3 ghaudit.py --repo . --format md --write-report ghaudit.md --fail-on-unparsed
```

Full example, with the report kept as an artifact either way:

```yaml
name: workflow audit
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  ghaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Audit workflows
        run: python3 ghaudit.py --repo . --format md --write-report ghaudit.md --fail-on-unparsed
      - name: Keep the report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: ghaudit-report
          path: ghaudit.md
```

(`actions/upload-artifact` is above as a SHA-pinned example too — GHA01 is the
pattern that would otherwise flag it.)

There is nothing to install: check out the repository, or vendor `ghaudit.py`
and the `ghaudit/` package into yours and call it. Standard library only,
Python 3.9+.

## Recipes

**Fail only when a file could not be read, and publish findings as a warning.**
Useful when you adopt the tool on a repository with existing findings and do not
want to block every PR on day one:

```bash
set +e
python3 ghaudit.py --repo . --format json --write-report ghaudit.json
code=$?
set -e
case "$code" in
  0) echo "ghaudit: clean" ;;
  1) echo "::warning::ghaudit found patterns worth reviewing — see ghaudit.json" ;;
  3) echo "::error::ghaudit could not parse a workflow file; part of the set was not audited" ; exit 3 ;;
  *) echo "::error::ghaudit failed to run (exit $code)" ; exit "$code" ;;
esac
```

**Fail on anything that is not `0`** — the strict default:

```bash
python3 ghaudit.py --repo . --format md --write-report ghaudit.md --fail-on-unparsed
# a non-zero exit fails the step; nothing else needed
```

**Audit only one workflow directory** (a monorepo, or a single service):

```bash
python3 ghaudit.py services/api/.github/workflows --only GHA01,GHA02,GHA03,GHA07
```

**Feed a dashboard.** `--format json` is the documented object — `tool`,
`version`, `audit_version`, `root`, `files[]` (each with `path`, `parsed`,
`jobs`, `steps`, `findings[]` of `id`, `line`, `context`, `message`, `fix`,
`anchor`) and `totals`. Parse it rather than the table: the table is for humans
and may be reworded, the JSON keys are the contract. `audit_version` names the
pattern set that produced the report, which is what you want to store next to
the result when the pattern set changes later.

**Not GitHub Actions.** Any pipeline that reads exit codes works the same way:

```bash
if ! python3 ghaudit.py --repo . --format md --write-report ghaudit.md; then
  status=$?
  [ "$status" -eq 3 ] && echo "ghaudit: a workflow could not be parsed" >&2
  exit "$status"
fi
```

## What to do with a finding

Read the line it names, in the file it names, and decide whether the shape is
real for your repository. Each finding prints the reasoning and the fix. The
report is a review queue, not a verdict — that is the whole design.
