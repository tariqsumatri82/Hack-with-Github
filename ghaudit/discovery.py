"""Finding workflow files on disk. No network, no git, no GitHub API."""

from __future__ import annotations

import os

WORKFLOW_DIR = os.path.join(".github", "workflows")
SUFFIXES = (".yml", ".yaml")


def looks_like_repo_root(path):
    """True when ``path`` is a repository root carrying a workflow directory."""
    wdir = os.path.join(path, WORKFLOW_DIR)
    if not os.path.isdir(wdir):
        return False
    return not any(
        name.endswith(SUFFIXES) for name in os.listdir(path) if os.path.isfile(os.path.join(path, name))
    )


def resolve_target(path, repo=False):
    """Return (root, error).

    ``root`` is the directory that will actually be read. With ``--repo`` the
    target is ``<path>/.github/workflows``. Without it a target that is a
    repository root (a ``.github/workflows`` directory and no workflow files of
    its own) is treated the same way, because that is what a user means when
    they point the tool at a checkout.
    """
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return None, "path does not exist: %s" % path
    if os.path.isfile(path):
        # One workflow file: audit that file and nothing else.
        return path, None
    if repo or looks_like_repo_root(path):
        return os.path.join(path, WORKFLOW_DIR), None
    return path, None


def find_workflows(root):
    """Workflow files under ``root``, sorted by path.

    ``root`` may be a single workflow file, which is then audited on its own —
    the CLI documents "a workflow directory, a repository root, or one workflow
    file". Descends subdirectories only when ``root`` itself has no workflow
    files (a plain workflow directory may be organised in subfolders).
    """
    if os.path.isfile(root):
        return [root]
    if not os.path.isdir(root):
        return []
    direct = sorted(
        os.path.join(root, name)
        for name in os.listdir(root)
        if os.path.isfile(os.path.join(root, name)) and name.endswith(SUFFIXES)
    )
    if direct:
        return direct
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for name in sorted(filenames):
            if name.endswith(SUFFIXES):
                found.append(os.path.join(dirpath, name))
    return sorted(found)
