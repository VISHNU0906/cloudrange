"""Normalized cloud-account model and a scoped IAM policy evaluator.

This is the shared contract every CLOUDRANGE module keys off of. ``enumerate``
populates it (from boto3 in real mode or from JSON fixtures in mock mode);
``privesc`` reasons over it; ``attack`` executes against it; ``detect`` audits
it.

Design goal: a *genuine* (but deliberately scoped) IAM policy evaluator. We
model the parts of AWS IAM evaluation that matter for privilege-escalation
reachability:

  * Effect ``Allow`` / ``Deny`` with **explicit-Deny precedence**.
  * ``Action`` wildcards (``*``, ``iam:*``, ``iam:Create*``) -- case-insensitive,
    glob-style.
  * ``Resource`` ARN wildcards (``*``, ``arn:aws:iam::*:user/*``).
  * Identity-based policies attached to users/roles/groups, both inline and
    managed (we inline the managed-policy documents into the model so the
    evaluator has a single code path).

Deliberately **out of scope** (documented honestly in the README so the
boundary is defensible -- we are not reimplementing all of IAM):

  * ``Condition`` blocks, ``NotAction`` / ``NotResource``.
  * Permission boundaries, Service Control Policies (SCPs), session policies.
  * Resource-based policy cross-account trust nuance beyond role trust docs.

The simplification is intentional and matches how a reachability analyzer
should behave: it errs toward *more* reachability (assume conditions are
satisfiable), which is the conservative choice for an attacker-perspective
audit.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- #
# Policy primitives
# --------------------------------------------------------------------------- #
@dataclass
class Statement:
    """A single normalized IAM policy statement."""

    effect: str  # "Allow" or "Deny"
    actions: list[str]
    resources: list[str]
    sid: str | None = None

    @classmethod
    def from_aws(cls, raw: dict[str, Any]) -> "Statement":
        """Build from an AWS-shaped statement dict (Action/Resource may be str)."""

        def _as_list(value: Any) -> list[str]:
            if value is None:
                return []
            if isinstance(value, str):
                return [value]
            return list(value)

        return cls(
            effect=raw.get("Effect", "Allow"),
            actions=_as_list(raw.get("Action")),
            resources=_as_list(raw.get("Resource", "*")),
            sid=raw.get("Sid"),
        )


@dataclass
class Policy:
    """A named policy document (inline or managed) -- a list of statements."""

    name: str
    statements: list[Statement]
    arn: str | None = None  # set for managed policies
    is_managed: bool = False

    @classmethod
    def from_document(
        cls,
        name: str,
        document: dict[str, Any],
        arn: str | None = None,
        is_managed: bool = False,
    ) -> "Policy":
        raw_statements = document.get("Statement", [])
        if isinstance(raw_statements, dict):  # AWS allows a single statement object
            raw_statements = [raw_statements]
        return cls(
            name=name,
            statements=[Statement.from_aws(s) for s in raw_statements],
            arn=arn,
            is_managed=is_managed,
        )


# --------------------------------------------------------------------------- #
# Principals and resources
# --------------------------------------------------------------------------- #
@dataclass
class Principal:
    """An IAM user or role.

    ``policies`` holds the *effective* set of policy documents that apply to
    this principal (inline policies + inlined copies of attached managed
    policies + inherited group policies). Keeping them inlined gives the
    evaluator a single, simple code path.
    """

    name: str
    principal_type: str  # "user" or "role"
    arn: str
    policies: list[Policy] = field(default_factory=list)
    attached_managed_arns: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    # Roles only: who is allowed to sts:AssumeRole this role.
    trust_principals: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def all_statements(self) -> list[Statement]:
        out: list[Statement] = []
        for pol in self.policies:
            out.extend(pol.statements)
        return out


@dataclass
class Group:
    name: str
    arn: str
    policies: list[Policy] = field(default_factory=list)


@dataclass
class Bucket:
    name: str
    public: bool = False
    public_reason: str | None = None
    crown_jewel: bool = False
    objects: list[str] = field(default_factory=list)
    policy: Policy | None = None
    encryption: bool = True


@dataclass
class Instance:
    """An EC2 instance. ``user_data`` may contain secrets; ``imds_v1`` means the
    metadata service is reachable without a token (SSRF-to-credential risk)."""

    instance_id: str
    attached_role: str | None = None
    user_data: str = ""
    imds_v1: bool = False
    public_ip: str | None = None


@dataclass
class Function:
    """A Lambda function with an execution role -- a PassRole privesc sink."""

    name: str
    execution_role: str | None = None
    runtime: str = "python3.11"
    env: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# The account model
# --------------------------------------------------------------------------- #
@dataclass
class AccountModel:
    """The whole normalized environment."""

    account_id: str = "000000000000"
    users: dict[str, Principal] = field(default_factory=dict)
    roles: dict[str, Principal] = field(default_factory=dict)
    groups: dict[str, Group] = field(default_factory=dict)
    buckets: dict[str, Bucket] = field(default_factory=dict)
    instances: dict[str, Instance] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    def principal(self, name: str) -> Principal | None:
        return self.users.get(name) or self.roles.get(name)

    def all_principals(self) -> list[Principal]:
        return list(self.users.values()) + list(self.roles.values())

    def admin_principals(self) -> list[Principal]:
        """Principals that already effectively hold ``*:*`` (the privesc sink)."""
        return [p for p in self.all_principals() if principal_is_admin(p)]

    def crown_jewel_buckets(self) -> list[Bucket]:
        return [b for b in self.buckets.values() if b.crown_jewel]


# --------------------------------------------------------------------------- #
# Policy evaluation -- the genuine (scoped) core
# --------------------------------------------------------------------------- #
def _matches(pattern: str, value: str) -> bool:
    """Case-insensitive glob match (AWS action/ARN matching uses ``*`` and ``?``)."""
    return fnmatch.fnmatch(value.lower(), pattern.lower())


def statement_matches_action(stmt: Statement, action: str) -> bool:
    return any(_matches(pat, action) for pat in stmt.actions)


def statement_matches_resource(stmt: Statement, resource: str) -> bool:
    # "*" resource (the common over-permission) matches everything.
    return any(_matches(pat, resource) for pat in stmt.resources)


def evaluate(
    statements: list[Statement], action: str, resource: str = "*"
) -> bool:
    """Return True iff ``action`` on ``resource`` is allowed.

    Implements AWS's core decision rule for identity policies:

        explicit Deny > Allow > implicit (default) Deny

    We scan for any matching Deny first (an explicit Deny on a matching
    action+resource wins regardless of Allows), then for any matching Allow.
    """
    explicit_deny = False
    allow = False
    for stmt in statements:
        if not statement_matches_action(stmt, action):
            continue
        if not statement_matches_resource(stmt, resource):
            continue
        if stmt.effect == "Deny":
            explicit_deny = True
        elif stmt.effect == "Allow":
            allow = True
    if explicit_deny:
        return False
    return allow


def principal_can(principal: Principal, action: str, resource: str = "*") -> bool:
    """Does this principal's effective identity policy allow ``action`` on
    ``resource``?"""
    return evaluate(principal.all_statements(), action, resource)


# Admin = effectively holds "*:*" (the privilege-escalation sink we path-find to).
ADMIN_ACTION = "*"


def principal_is_admin(principal: Principal) -> bool:
    """A principal is admin if it can perform any action on any resource.

    We probe the literal ``*`` action (matched by ``*`` or by an explicit
    ``"*"`` allow on ``"*"`` resource), which is exactly what AdministratorAccess
    and an inline ``{"Action":"*","Resource":"*"}`` grant.
    """
    return evaluate(principal.all_statements(), ADMIN_ACTION, "*")
