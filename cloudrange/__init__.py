"""CLOUDRANGE -- cloud attack-and-detect range.

A Terraform-deployed deliberately-vulnerable AWS environment, a boto3 attack
chain (enumerate -> IAM privilege-escalation -> lateral movement -> S3 exfil),
and a read-only detection/audit layer that maps every privesc path and emits
SARIF + Markdown remediation.

Author: Vishnu Kosuri.
License: MIT.
"""

__version__ = "1.0.0"
__author__ = "Vishnu Kosuri"


def _locate_data(relative: str):
    """Resolve a bundled data file (fixtures/, schemas/) across layouts.

    Works whether CLOUDRANGE is run from a source checkout (data dirs are
    siblings of the package), an editable install (same), or a regular wheel
    install (data is copied *inside* the package via package-data). Tries the
    candidate locations in order and returns the first that exists.
    """
    from pathlib import Path

    here = Path(__file__).resolve().parent
    candidates = [
        here.parent / relative,  # source / editable: repo-root/<relative>
        here / relative,         # wheel install: inside the package
    ]
    for cand in candidates:
        if cand.exists():
            return cand
    raise FileNotFoundError(
        f"CLOUDRANGE bundled data file '{relative}' not found. Looked in: "
        + ", ".join(str(c) for c in candidates)
        + ". Run from a source checkout, or install editable with "
        "`pip install -e .` so the top-level fixtures/ and schemas/ dirs "
        "resolve (see README)."
    )
