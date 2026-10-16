# Scope and limits

What ghaudit reads, what it never does, and how you can check both claims for
yourself. This page is the short version of the promises the README makes.

## What it reads

- **Workflow YAML text on the local disk.** A workflow directory, a repository
  root, or one workflow file. Nothing else.
- By default it looks in `.github/workflows` when you point it at a repository
  (`--repo`, or a root that carries a workflow directory).
- It reads files with `open(..., encoding="utf-8", errors="replace")` and passes
  the text to its own line-preserving reader. It does not import PyYAML to do
  this; `yaml` is used only by `--yaml-cross-check`, when it happens to be
  installed, and never as a requirement.

## What it never does

| It never… | Because |
|---|---|
| **Touches the network** | The tool has no network code at all. `tests/test_cli.py` parses every module under `ghaudit/` and fails if `socket`, `ssl`, `urllib`, `http`, `requests`, `ftplib`, `smtplib`, `telnetlib` or `xmlrpc` is imported anywhere. |
| **Queries GitHub** | There is no API client, no token, no HTTP call, no `git` invocation. The repository's name, its secrets, its settings and its permissions policy are all invisible to it. |
| **Executes a workflow** | It never shells out. The same AST test fails on `subprocess` and `os.system`. A workflow file is data here, not a program. |
| **Resolves an action** | `actions/checkout@v4` is a string. ghaudit never fetches the action, never asks what the tag pointed at, and never reads a composite action's internals. |
| **Follows references out of the file** | A reusable workflow living in another repository, an org-level secret, a runner's real configuration, a container image's digest — all outside what text in one file can show. |
| **Writes anywhere you did not ask** | The only write is `--write-report OUT`, to the path you name. There is no cache, no state file, no temp file, no telemetry, no update check. |

**Nothing about your repository leaves the machine it runs on.** The tool is
standard library only, so there is nowhere for data to go: no client library is
installed, no endpoint is configured, no credential is read. You can run it with
the network unplugged and get the same report.

## How to verify that

```bash
python3 -m unittest discover -s tests -v     # includes the AST import scan
grep -rn "urllib\|socket\|requests\|subprocess" ghaudit/   # expect no matches
```

## Limits that are not bugs

- **A finding is a pattern match in the text, not a proven exploit.** Whether the
  shape is exploitable depends on the repository, its token scopes, its secrets
  and its reviewers. ghaudit flags what it can see and stops there.
- **A clean run proves nothing.** It means these patterns were not found in the
  files that were read; it does not mean the workflows are safe.
- **It cannot see past the file.** Composite-action internals, reusable
  workflows defined elsewhere, runtime-resolved refs (`uses: ${{ … }}`),
  org-level secrets and whether a runner is ephemeral are all out of reach.
- **It is not a YAML validator or a general linter.** It understands the subset
  workflow files actually use and refuses the rest — tabs in indentation, YAML
  anchors and aliases, unterminated quotes — reporting the file as unparsed with
  the line and the reason rather than guessing. Run
  [actionlint](https://github.com/rhysd/actionlint) alongside it: actionlint
  validates syntax, expressions and runner labels; ghaudit looks for the
  documented patterns.
- **The threat model is mostly untrusted contributors.** Several patterns are far
  less interesting in a private repository with a handful of trusted
  contributors. The tool says which patterns those are instead of scoring them.
- **It is a checklist, not a pen test.** It never gets tired, and it is pointed
  at one file type.

## Privacy

No account, no configuration, no opt-in, no reporting. Run it on a customer's
private repository and nothing about the run leaves your machine — which is the
only reason a tool like this is allowed anywhere near one.
