"""Inlined documents for the AWS-managed policies CLOUDRANGE references.

In real mode these would be fetched via ``iam.get_policy_version``. We bundle
the canonical documents (or a faithful subset) so the policy evaluator has a
single code path and mock mode is fully offline. Only the managed policies the
range actually uses are included.
"""

from __future__ import annotations

from typing import Any

# AdministratorAccess -- the canonical "*:*" grant. This is the privesc sink.
ADMINISTRATOR_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}

# ReadOnlyAccess is enormous in reality; for reachability analysis the only
# property that matters is that it grants no write/escalation actions. We model
# a faithful, scoped subset of its read actions. Crucially it does NOT grant
# iam:CreateAccessKey / PassRole / PutUserPolicy, so it never creates a privesc
# edge on its own -- which is the correct behavior.
READ_ONLY_ACCESS = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*",
                "s3:Get*",
                "s3:List*",
                "ec2:Describe*",
                "lambda:Get*",
                "lambda:List*",
                "sts:GetCallerIdentity",
            ],
            "Resource": "*",
        }
    ],
}

_BY_ARN: dict[str, dict[str, Any]] = {
    "arn:aws:iam::aws:policy/AdministratorAccess": ADMINISTRATOR_ACCESS,
    "arn:aws:iam::aws:policy/ReadOnlyAccess": READ_ONLY_ACCESS,
}


def managed_policy_document(arn: str) -> dict[str, Any] | None:
    """Return the bundled document for a managed-policy ARN, or None."""
    return _BY_ARN.get(arn)


def managed_policy_name(arn: str) -> str:
    """Human-readable name from a managed-policy ARN."""
    return arn.rsplit("/", 1)[-1]
