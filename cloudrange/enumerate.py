"""Enumeration: build the normalized AccountModel.

Mock mode reads ``fixtures/account.json``; real mode queries AWS via boto3
(read-only IAM/S3/EC2/Lambda list+get calls). Both produce the identical
:class:`~cloudrange.model.AccountModel`, so every downstream module
(privesc/attack/detect) is mode-agnostic.

boto3 is imported lazily *inside* the real-mode branch so that import and all
``--mock`` operations are fully offline -- no credentials, no network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import _locate_data
from .managed_policies import managed_policy_document, managed_policy_name
from .model import (
    AccountModel,
    Bucket,
    Function,
    Group,
    Instance,
    Policy,
    Principal,
)

DEFAULT_FIXTURE = _locate_data("fixtures/account.json")


# --------------------------------------------------------------------------- #
# Shared: attach managed-policy documents to a principal
# --------------------------------------------------------------------------- #
def _attach_managed(policies: list[Policy], managed_arns: list[str]) -> None:
    """Inline the bundled document for each managed-policy ARN."""
    for arn in managed_arns:
        doc = managed_policy_document(arn)
        if doc is None:
            # Unknown managed policy: model it as an empty (no-grant) policy so
            # the evaluator stays sound rather than guessing permissions.
            policies.append(
                Policy(name=managed_policy_name(arn), statements=[], arn=arn, is_managed=True)
            )
            continue
        policies.append(
            Policy.from_document(
                managed_policy_name(arn), doc, arn=arn, is_managed=True
            )
        )


# --------------------------------------------------------------------------- #
# Mock mode -- load from fixture JSON
# --------------------------------------------------------------------------- #
def load_from_fixture(path: str | Path | None = None) -> AccountModel:
    fixture_path = Path(path) if path else DEFAULT_FIXTURE
    data: dict[str, Any] = json.loads(Path(fixture_path).read_text(encoding="utf-8"))

    model = AccountModel(account_id=data.get("account_id", "000000000000"))

    # Users
    for name, raw in data.get("users", {}).items():
        policies: list[Policy] = []
        for pname, pdoc in raw.get("inline_policies", {}).items():
            policies.append(Policy.from_document(pname, pdoc))
        _attach_managed(policies, raw.get("attached_managed", []))
        model.users[name] = Principal(
            name=name,
            principal_type="user",
            arn=raw["arn"],
            policies=policies,
            attached_managed_arns=list(raw.get("attached_managed", [])),
            groups=list(raw.get("groups", [])),
            tags=dict(raw.get("tags", {})),
        )

    # Roles
    for name, raw in data.get("roles", {}).items():
        policies = []
        for pname, pdoc in raw.get("inline_policies", {}).items():
            policies.append(Policy.from_document(pname, pdoc))
        _attach_managed(policies, raw.get("attached_managed", []))
        model.roles[name] = Principal(
            name=name,
            principal_type="role",
            arn=raw["arn"],
            policies=policies,
            attached_managed_arns=list(raw.get("attached_managed", [])),
            trust_principals=list(raw.get("trust", [])),
            tags=dict(raw.get("tags", {})),
        )

    # Groups (and fold group policies into member principals)
    for name, raw in data.get("groups", {}).items():
        gpolicies: list[Policy] = []
        for pname, pdoc in raw.get("inline_policies", {}).items():
            gpolicies.append(Policy.from_document(pname, pdoc))
        _attach_managed(gpolicies, raw.get("attached_managed", []))
        model.groups[name] = Group(name=name, arn=raw.get("arn", ""), policies=gpolicies)
    for principal in model.all_principals():
        for gname in principal.groups:
            grp = model.groups.get(gname)
            if grp:
                principal.policies.extend(grp.policies)

    # Buckets
    for name, raw in data.get("buckets", {}).items():
        model.buckets[name] = Bucket(
            name=name,
            public=bool(raw.get("public", False)),
            public_reason=raw.get("public_reason"),
            crown_jewel=bool(raw.get("crown_jewel", False)),
            objects=list(raw.get("objects", [])),
            encryption=bool(raw.get("encryption", True)),
        )

    # Instances
    for iid, raw in data.get("instances", {}).items():
        model.instances[iid] = Instance(
            instance_id=iid,
            attached_role=raw.get("attached_role"),
            user_data=raw.get("user_data", ""),
            imds_v1=bool(raw.get("imds_v1", False)),
            public_ip=raw.get("public_ip"),
        )

    # Functions
    for fname, raw in data.get("functions", {}).items():
        model.functions[fname] = Function(
            name=fname,
            execution_role=raw.get("execution_role"),
            runtime=raw.get("runtime", "python3.11"),
            env=dict(raw.get("env", {})),
        )

    return model


# --------------------------------------------------------------------------- #
# Real mode -- query AWS via boto3 (read-only)
# --------------------------------------------------------------------------- #
def load_from_aws(region: str = "us-east-1") -> AccountModel:  # pragma: no cover
    """Enumerate a live AWS account read-only via boto3.

    Not exercised by the offline test suite (requires real credentials). Kept
    genuine: uses only List*/Get*/Describe* calls. Run against a throwaway
    account you own.
    """
    import boto3  # lazy import: keeps mock mode fully offline

    iam = boto3.client("iam", region_name=region)
    sts = boto3.client("sts", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    lam = boto3.client("lambda", region_name=region)

    account_id = sts.get_caller_identity()["Account"]
    model = AccountModel(account_id=account_id)

    # --- Users ---
    for u in _paginate(iam, "list_users", "Users"):
        name = u["UserName"]
        policies = _inline_user_policies(iam, name)
        managed = [p["PolicyArn"] for p in _attached_user_policies(iam, name)]
        _attach_managed_real(iam, policies, managed)
        groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=name).get("Groups", [])]
        model.users[name] = Principal(
            name=name,
            principal_type="user",
            arn=u["Arn"],
            policies=policies,
            attached_managed_arns=managed,
            groups=groups,
        )

    # --- Roles ---
    for r in _paginate(iam, "list_roles", "Roles"):
        name = r["RoleName"]
        policies = _inline_role_policies(iam, name)
        managed = [p["PolicyArn"] for p in _attached_role_policies(iam, name)]
        _attach_managed_real(iam, policies, managed)
        trust = _trust_principals(r.get("AssumeRolePolicyDocument", {}))
        model.roles[name] = Principal(
            name=name,
            principal_type="role",
            arn=r["Arn"],
            policies=policies,
            attached_managed_arns=managed,
            trust_principals=trust,
        )

    # --- Buckets ---
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        public, reason = _bucket_public(s3, name)
        model.buckets[name] = Bucket(name=name, public=public, public_reason=reason)

    # --- Instances ---
    for res in ec2.describe_instances().get("Reservations", []):
        for inst in res.get("Instances", []):
            role = None
            prof = inst.get("IamInstanceProfile", {}).get("Arn")
            if prof:
                role = prof.rsplit("/", 1)[-1]
            md = inst.get("MetadataOptions", {})
            imds_v1 = md.get("HttpTokens", "optional") != "required"
            model.instances[inst["InstanceId"]] = Instance(
                instance_id=inst["InstanceId"],
                attached_role=role,
                imds_v1=imds_v1,
                public_ip=inst.get("PublicIpAddress"),
            )

    # --- Functions ---
    for fn in lam.list_functions().get("Functions", []):
        role_arn = fn.get("Role", "")
        model.functions[fn["FunctionName"]] = Function(
            name=fn["FunctionName"],
            execution_role=role_arn.rsplit("/", 1)[-1] if role_arn else None,
            runtime=fn.get("Runtime", "unknown"),
        )

    return model


# --- real-mode boto3 helpers (pragma: no cover -- need live creds) --------- #
def _paginate(client, op: str, key: str):  # pragma: no cover
    paginator = client.get_paginator(op)
    for page in paginator.paginate():
        for item in page.get(key, []):
            yield item


def _inline_user_policies(iam, name: str) -> list[Policy]:  # pragma: no cover
    out = []
    for pname in iam.list_user_policies(UserName=name).get("PolicyNames", []):
        doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
        out.append(Policy.from_document(pname, doc))
    return out


def _inline_role_policies(iam, name: str) -> list[Policy]:  # pragma: no cover
    out = []
    for pname in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
        doc = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
        out.append(Policy.from_document(pname, doc))
    return out


def _attached_user_policies(iam, name: str):  # pragma: no cover
    return iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])


def _attached_role_policies(iam, name: str):  # pragma: no cover
    return iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", [])


def _attach_managed_real(iam, policies: list[Policy], managed_arns: list[str]) -> None:  # pragma: no cover
    for arn in managed_arns:
        doc = managed_policy_document(arn)
        if doc is None:
            try:
                meta = iam.get_policy(PolicyArn=arn)["Policy"]
                ver = iam.get_policy_version(
                    PolicyArn=arn, VersionId=meta["DefaultVersionId"]
                )["PolicyVersion"]["Document"]
                policies.append(
                    Policy.from_document(managed_policy_name(arn), ver, arn=arn, is_managed=True)
                )
                continue
            except Exception:
                policies.append(Policy(name=managed_policy_name(arn), statements=[], arn=arn, is_managed=True))
                continue
        policies.append(Policy.from_document(managed_policy_name(arn), doc, arn=arn, is_managed=True))


def _trust_principals(trust_doc: dict[str, Any]) -> list[str]:  # pragma: no cover
    out: list[str] = []
    stmts = trust_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        principal = s.get("Principal", {})
        for key in ("AWS", "Service"):
            val = principal.get(key)
            if isinstance(val, str):
                out.append(val)
            elif isinstance(val, list):
                out.extend(val)
    return out


def _bucket_public(s3, name: str):  # pragma: no cover
    try:
        pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        if all(pab.values()):
            return False, None
    except Exception:
        pass
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        for grant in acl.get("Grants", []):
            uri = grant.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                return True, "ACL grants access to a public group."
    except Exception:
        pass
    return False, None


# --------------------------------------------------------------------------- #
# Unified entry point
# --------------------------------------------------------------------------- #
def enumerate_account(
    mock: bool = True,
    fixture: str | Path | None = None,
    region: str = "us-east-1",
) -> AccountModel:
    """Build the AccountModel from a fixture (mock) or live AWS (real)."""
    if mock:
        return load_from_fixture(fixture)
    return load_from_aws(region=region)
