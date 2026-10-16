"""ghaudit — a GitHub Actions workflow security auditor.

Reads workflow YAML text and flags the patterns that cause real supply-chain
and script-injection incidents. It never executes a workflow, never resolves an
action and never touches the network.
"""

__version__ = "0.1.0"

# Bumped when the set of audit patterns changes (a pattern added, changed or
# retired). It moves independently of __version__ so a report can name the
# pattern set it was produced with.
AUDIT_VERSION = "0.1.0"

__all__ = ["__version__", "AUDIT_VERSION"]
