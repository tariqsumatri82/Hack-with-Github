# The 7 audit patterns

Pattern set version: **0.1.0** (2026-10).

Every pattern below is a shape in the workflow text. A match is a reason to look
at the workflow with the change in mind — it is never a statement that the
workflow is exploitable. Line numbers come from the file as written, so a
finding points at something you can open and edit.

Each section header is the anchor the tool prints in its report
(`docs/patterns.md#<slug>`), and `tools/check_sync.py` fails the build if this
file, `ghaudit/rules.json` and the README stop agreeing on the count.

---

## GHA01: Unpinned third-party action

**Why it matters.** `uses: actions/checkout@v4` is a promise about a string, not
about code. Tags and branches are movable: the action's owner can repoint `v4`,
and so can anyone who compromises that repository. Nothing in your workflow
changes when the code under the tag does. A full 40-character commit SHA names
one revision, and GitHub resolves that revision only.

**Detected.** A `uses:` value in a job step whose ref is not a 40-character hex
SHA: `@v4`, `@v4.2.2`, `@main`, a missing ref, or a `docker://image:tag`
reference (where the content pin is `@sha256:<digest>`, not the tag). Local
actions (`./path`) are excluded — they are the repository's own code.

**Fix.**

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

Dependabot can keep pinned SHAs current with a comment naming the tag.

**Real shape.** Every "action not found after a change that shipped nothing"
incident report starts with a tag that moved. The pattern is cheap to fix and
cheap to check for in review; that is the whole reason it is first.

---

## GHA02: Pull-request-target with head checkout

**Why it matters.** `pull_request_target` runs in the context of the **base**
repository, so the job receives a read/write `GITHUB_TOKEN` and can read
repository secrets — and it is triggered by pull requests, including from forks.
Adding a checkout of the pull request's own head puts attacker-authored files on
disk inside that privileged context. This combination is the shape behind the
published attacks on CI workflows.

**Detected.** A workflow triggered by `pull_request_target` **and** a step using
`actions/checkout` whose `with.ref` references
`github.event.pull_request.head.sha`, `...head.ref`, `...head.label` or
`github.head_ref`. When a later `run:` step in the same job executes code from
that checkout, the finding says which line does it.

**Fix.** Any one of these:

```yaml
# 1. the usual case — you do not need the privileged trigger
on:
  pull_request:

# 2. or keep pull_request_target but never materialise the fork's code
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  # no ref: — the base branch is checked out
```

`pull_request_target` on its own is not flagged: labelling, commenting and
triaging from the privileged context are legitimate uses. The pattern is the
*combination*.

---

## GHA03: Interpolation into run

**Why it matters.** GitHub substitutes `${{ … }}` inside a `run:` block into the
script text **before** the shell parses it. If the substituted value contains a
quote, a semicolon or `$(…)` — an issue title, a pull request title, a branch
name, a commit message — it is no longer data. For an untrusted trigger the
value is attacker-controlled.

**Detected.** A `${{ … }}` expression inside a step's `run:` value whose
contents read untrusted event data: issue/PR/comment/review titles and bodies,
`github.head_ref`, PR head ref/label/sha, discussion titles and bodies,
`github.event.pages`, `github.event.commits`, `workflow_run.head_branch`,
`client_payload`, and `inputs.*` when the workflow is called or dispatched.
Occurrences that are not inside shell quotes are listed first.

**Fix.** Pass the value through the environment and quote the variable, so the
shell receives it as one argument and never parses it:

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "$TITLE"
```

---

## GHA04: Over-scoped token

**Why it matters.** `permissions: write-all` hands every step in the job the
right to write to the repository, including steps that run third-party code or
code from a pull request. A job that pushes a tag, creates a release or opens a
pull request without declaring permissions gets the repository default, which
on older repositories is broad.

**Detected.** Three shapes, each reported on its own line:

- `permissions: write-all` at workflow or job level.
- A job that pushes, releases or publishes (`git push`, `gh release create`,
  `gh pr create`, `npm publish`, `twine upload`, `docker push`, or a known
  release/PR-creating action) in a repository where no `permissions:` key is
  declared anywhere.
- `contents: write` in a job whose workflow is also triggered by one of the
  untrusted triggers.

**Fix.**

```yaml
permissions:
  contents: read          # workflow-level default
jobs:
  release:
    permissions:
      contents: write     # only this job, and only what it needs
```

---

## GHA05: Self-hosted runner on an untrusted trigger

**Why it matters.** Self-hosted runners keep state. Files, credentials, caches
and environment variables survive between jobs, so a job that runs a fork's code
can read what the previous job left behind and can reach whatever the host can
reach. GitHub's own guidance is that self-hosted runners should not be used for
public repositories.

**Detected.** `runs-on` naming `self-hosted` (as a plain value or inside a
label list) in a workflow also triggered by `pull_request` or
`pull_request_target`.

**Fix.** Use a GitHub-hosted runner for those triggers, or run the self-hosted
runner as an ephemeral, isolated instance with no standing credentials and no
network path to anything you care about.

**Limit.** The tool cannot tell whether a runner is ephemeral or which host a
custom label points at. It matches the literal `self-hosted` label; a private
label that happens to resolve to a self-hosted runner looks like an ordinary
label in the text.

---

## GHA06: Secrets reachable by untrusted or logged code

**Why it matters.** A secret declared in `env:` or `with:` is in scope for
everything the step runs, including code from a pull request. A secret
interpolated into a `run:` block can be printed into a log that outlives the
job. `persist-credentials: true` leaves the token in `.git/config` for every
later step in the job.

**Detected.**

- A secret (`secrets.*`) in job-level `env:` or in a step's `with:` in a job
  that also checks out the pull request head.
- A secret interpolated inside a step's `run:` text.
- `persist-credentials: true` on a checkout step.
- `secrets: inherit` on a job whose workflow is reachable from an untrusted
  trigger.

**Fix.** Keep secrets out of jobs that touch pull-request code. Pass them by
name through `env:` at the step that needs them, never echo them, and set
`persist-credentials: false` when the checkout does not push.

---

## GHA07: Outsider-drivable trigger executing code

**Why it matters.** `issue_comment`, `discussion_comment` and `workflow_run`
can be started by someone outside the repository — a comment, a discussion
reply, or another workflow's completion. A job that then checks out and builds
the repository, or installs an artefact the upstream run produced, executes
content that an outsider influenced. `curl … | bash` in such a job turns a
download into a shell.

**Detected.** With one of those triggers present:

- A job that checks out the repository and runs code from it.
- A step using a `*-download-artifact` action, or `gh run download`.
- A `curl`/`wget` pipeline into a shell.
- `workflow_run` with no reference to `workflow_run.conclusion` anywhere in the
  file, reported on the trigger line.

**Fix.** Gate the job on an allow-list (author, label, membership) and on the
upstream conclusion; treat downloaded artefacts as untrusted input; never pipe a
download straight into a shell.

---

### Deliberately not shipped

Saying what a tool does **not** check is part of shipping it honestly:

- `pull_request_target` on its own. It has legitimate uses; only the head
  checkout makes it GHA02.
- `id-token`/OIDC usage. Judging it needs the job's cloud-side policy, which is
  not in the file.
- Anything that needs action contents, the network, or the GitHub API. The tool
  reads YAML text and nothing else.
- General YAML linting. Use [actionlint](https://github.com/rhysd/actionlint)
  alongside this; it validates syntax and expressions, ghaudit looks for the
  seven shapes above.

Patterns are versioned with the tool (`AUDIT_VERSION`). When a pattern stops
matching the shape it was written for, it is retired deliberately and the change
is recorded in CHANGELOG.md — never kept in the list to make the count look
larger.
