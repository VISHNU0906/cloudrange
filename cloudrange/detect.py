"""detect.py -- read-only cloud security auditor (folds in IAMScout).

Scans the AccountModel (mock fixture or live AWS) and flags every misconfig
with:

  * a severity,
  * the **exact privilege-escalation path** that consumes it (the linkage that
    makes this an attack-path-aware auditor, not a checklist), and
  * concrete remediation.

Findings are emitted as **SARIF v2.1.0** (validated against the bundled schema)
and as a **Markdown** report. IAM findings have no file/line, so we use SARIF
``logicalLocations`` (fullyQualifiedName = the principal/resource ARN), populate
``tool.driver.rules``, and map severity -> SARIF ``level``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__, _locate_data
from .model import AccountModel, principal_is_admin
from .privesc import PrivescPath, build_edges, find_all_privesc_paths

SCHEMA_PATH = _locate_data("schemas/sarif-2.1.0.schema.json")

# severity -> SARIF level
_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


# --------------------------------------------------------------------------- #
# Rule catalog
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    id: str
    name: str
    short: str
    full: str
    default_severity: str
    help_uri: str = ""


RULES: dict[str, Rule] = {
    "CR-IAM-PRIVESC": Rule(
        "CR-IAM-PRIVESC",
        "IamPrivilegeEscalationPath",
        "Principal can escalate to administrator access.",
        "The principal holds a permission (or chain of permissions) that allows "
        "it to obtain administrator-equivalent access via a known IAM privilege-"
        "escalation technique.",
        "CRITICAL",
        "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
    ),
    "CR-IAM-CREATEKEY": Rule(
        "CR-IAM-CREATEKEY",
        "OverpermissiveCreateAccessKey",
        "iam:CreateAccessKey allowed on other users.",
        "A principal can create access keys for IAM users other than itself, "
        "letting it impersonate them.",
        "HIGH",
    ),
    "CR-IAM-PASSROLE": Rule(
        "CR-IAM-PASSROLE",
        "PassRoleToCompute",
        "iam:PassRole with compute create/invoke.",
        "A principal can pass an over-privileged role to a compute service "
        "(Lambda/EC2) and execute code with that role's permissions.",
        "HIGH",
    ),
    "CR-IAM-SELFPOLICY": Rule(
        "CR-IAM-SELFPOLICY",
        "SelfPolicyModification",
        "Principal can modify its own (or others') IAM policy.",
        "iam:PutUserPolicy / iam:AttachUserPolicy allow a principal to grant "
        "itself administrator access.",
        "HIGH",
    ),
    "CR-IAM-ADMINROLE": Rule(
        "CR-IAM-ADMINROLE",
        "OverPrivilegedRole",
        "Role holds AdministratorAccess.",
        "A service or instance role is granted administrator access, creating a "
        "large blast radius if the role is assumed or its compute is compromised.",
        "HIGH",
    ),
    "CR-IAM-TRUST": Rule(
        "CR-IAM-TRUST",
        "OverBroadAssumeRoleTrust",
        "Role trust policy is over-broad.",
        "A role trusts another principal/account-root, enabling lateral movement "
        "via sts:AssumeRole.",
        "MEDIUM",
    ),
    "CR-S3-PUBLIC": Rule(
        "CR-S3-PUBLIC",
        "PublicS3Bucket",
        "S3 bucket is publicly accessible.",
        "Block Public Access is disabled or an ACL/policy grants public access.",
        "HIGH",
    ),
    "CR-S3-NOENC": Rule(
        "CR-S3-NOENC",
        "S3BucketUnencrypted",
        "S3 bucket has no default encryption.",
        "Default server-side encryption is not enabled on the bucket.",
        "MEDIUM",
    ),
    "CR-EC2-IMDSV1": Rule(
        "CR-EC2-IMDSV1",
        "Imdsv1Enabled",
        "EC2 instance allows token-less IMDSv1.",
        "IMDSv1 lets an SSRF or on-host attacker read the instance role's "
        "credentials without a session token.",
        "HIGH",
    ),
    "CR-EC2-SECRETS": Rule(
        "CR-EC2-SECRETS",
        "SecretsInUserData",
        "Secrets baked into EC2 user-data.",
        "Plaintext credentials/tokens in user-data are readable by anyone who "
        "can describe the instance or reach the metadata service.",
        "HIGH",
    ),
    "CR-LAMBDA-ADMIN": Rule(
        "CR-LAMBDA-ADMIN",
        "OverPrivilegedLambda",
        "Lambda function uses an admin execution role.",
        "A function runs with an administrator-equivalent execution role.",
        "HIGH",
    ),
}


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    rule_id: str
    severity: str
    resource_arn: str
    resource_name: str
    message: str
    remediation: str
    privesc_path: str | None = None  # the exact path that consumes this misconfig
    technique: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# The auditor
# --------------------------------------------------------------------------- #
class Auditor:
    def __init__(self, model: AccountModel):
        self.model = model
        self.paths: dict[str, PrivescPath] = find_all_privesc_paths(model)
        self.edges = build_edges(model)

    # ------------------------------------------------------------------ #
    def scan(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_privesc_paths())
        findings.extend(self._scan_iam_permissions())
        findings.extend(self._scan_admin_roles())
        findings.extend(self._scan_trust())
        findings.extend(self._scan_s3())
        findings.extend(self._scan_ec2())
        findings.extend(self._scan_lambda())
        return findings

    # --- privesc paths (the headline findings) ------------------------- #
    def _scan_privesc_paths(self) -> list[Finding]:
        out = []
        for principal, path in sorted(self.paths.items()):
            out.append(
                Finding(
                    rule_id="CR-IAM-PRIVESC",
                    severity="CRITICAL",
                    resource_arn=self.model.principal(principal).arn,
                    resource_name=principal,
                    message=(
                        f"Principal '{principal}' can escalate to administrator "
                        f"in {path.length} step(s) via "
                        f"{' -> '.join(path.techniques)}."
                    ),
                    remediation=(
                        "Remove the escalation permission(s) from this principal "
                        "and apply least privilege. See the linked privesc path."
                    ),
                    privesc_path=path.describe(),
                    technique=" -> ".join(path.techniques),
                    properties={
                        "path_techniques": path.techniques,
                        "path_length": path.length,
                    },
                )
            )
        return out

    # --- individual over-permissions, each linked to a path ------------ #
    def _path_using_technique(self, principal: str, technique: str) -> str | None:
        path = self.paths.get(principal)
        if path and technique in path.techniques:
            return path.describe()
        # The permission may feed someone else's path (e.g. an admin sink role).
        for p in self.paths.values():
            for e in p.edges:
                if e.src == principal and e.technique == technique:
                    return p.describe()
        return None

    def _scan_iam_permissions(self) -> list[Finding]:
        out = []
        for edge in self.edges:
            if edge.technique == "CreateAccessKey":
                out.append(self._perm_finding(
                    "CR-IAM-CREATEKEY", edge,
                    "Scope iam:CreateAccessKey to the principal's own user ARN, "
                    "or remove it. Never allow it on Resource '*'.",
                ))
            elif edge.technique == "PassRole+Lambda":
                out.append(self._perm_finding(
                    "CR-IAM-PASSROLE", edge,
                    "Constrain iam:PassRole to a specific, least-privilege role "
                    "ARN and add an iam:PassedToService condition; remove admin "
                    "from the passable role.",
                ))
            elif edge.technique in ("PutUserPolicy", "AttachUserPolicy"):
                out.append(self._perm_finding(
                    "CR-IAM-SELFPOLICY", edge,
                    "Remove iam:PutUserPolicy / iam:AttachUserPolicy from the "
                    "principal; route policy changes through a reviewed pipeline.",
                ))
            elif edge.technique == "AssumeRole":
                # Trust handled separately; the identity grant is still notable.
                pass
        return out

    def _perm_finding(self, rule_id: str, edge, remediation: str) -> Finding:
        principal = self.model.principal(edge.src)
        return Finding(
            rule_id=rule_id,
            severity=edge.severity,
            resource_arn=principal.arn if principal else edge.src,
            resource_name=edge.src,
            message=(
                f"Principal '{edge.src}' has {', '.join(edge.permissions)} "
                f"enabling technique '{edge.technique}': {edge.detail}"
            ),
            remediation=remediation,
            privesc_path=self._path_using_technique(edge.src, edge.technique),
            technique=edge.technique,
            properties={"permissions": edge.permissions},
        )

    # --- over-privileged roles ----------------------------------------- #
    def _scan_admin_roles(self) -> list[Finding]:
        out = []
        for role in self.model.roles.values():
            if not principal_is_admin(role):
                continue
            # Is this role a sink in some path?
            path_desc = None
            tech = None
            for p in self.paths.values():
                if p.edges and p.edges[-1].dst == "ADMIN":
                    # find an edge whose technique passes/assumes into this role
                    for e in p.edges:
                        if role.name.lower() in e.detail.lower():
                            path_desc = p.describe()
                            tech = e.technique
            out.append(
                Finding(
                    rule_id="CR-IAM-ADMINROLE",
                    severity="HIGH",
                    resource_arn=role.arn,
                    resource_name=role.name,
                    message=(
                        f"Role '{role.name}' holds AdministratorAccess "
                        f"(service/instance role with full admin blast radius)."
                    ),
                    remediation=(
                        "Replace AdministratorAccess with a least-privilege "
                        "policy scoped to exactly what the workload needs."
                    ),
                    privesc_path=path_desc,
                    technique=tech,
                )
            )
        return out

    # --- over-broad trust ---------------------------------------------- #
    def _scan_trust(self) -> list[Finding]:
        out = []
        for role in self.model.roles.values():
            for entry in role.trust_principals:
                is_aws_principal = entry.startswith("arn:aws:iam::") or entry.endswith(":root") or entry == "*"
                if not is_aws_principal:
                    continue  # service trust (e.g. lambda.amazonaws.com) is fine here
                # Find a path that uses an AssumeRole into this role.
                path_desc = None
                for p in self.paths.values():
                    for e in p.edges:
                        if e.technique == "AssumeRole" and role.name.lower() in e.detail.lower():
                            path_desc = p.describe()
                out.append(
                    Finding(
                        rule_id="CR-IAM-TRUST",
                        severity="MEDIUM",
                        resource_arn=role.arn,
                        resource_name=role.name,
                        message=(
                            f"Role '{role.name}' trust policy permits "
                            f"'{entry}' to assume it (lateral-movement vector)."
                        ),
                        remediation=(
                            "Restrict the trust policy to the minimal set of "
                            "principals and add ExternalId / source conditions."
                        ),
                        privesc_path=path_desc,
                        technique="AssumeRole" if path_desc else None,
                    )
                )
        return out

    # --- S3 ------------------------------------------------------------ #
    def _scan_s3(self) -> list[Finding]:
        out = []
        for bucket in self.model.buckets.values():
            arn = f"arn:aws:s3:::{bucket.name}"
            if bucket.public:
                out.append(
                    Finding(
                        rule_id="CR-S3-PUBLIC",
                        severity="HIGH",
                        resource_arn=arn,
                        resource_name=bucket.name,
                        message=(
                            f"S3 bucket '{bucket.name}' is publicly accessible. "
                            f"{bucket.public_reason or ''}".strip()
                        ),
                        remediation=(
                            "Enable S3 Block Public Access (account + bucket), "
                            "remove public ACL grants, and use a restrictive "
                            "bucket policy."
                        ),
                    )
                )
            if not bucket.encryption:
                out.append(
                    Finding(
                        rule_id="CR-S3-NOENC",
                        severity="MEDIUM",
                        resource_arn=arn,
                        resource_name=bucket.name,
                        message=f"S3 bucket '{bucket.name}' has no default encryption.",
                        remediation="Enable default SSE-KMS or SSE-S3 encryption.",
                    )
                )
        return out

    # --- EC2 ----------------------------------------------------------- #
    def _scan_ec2(self) -> list[Finding]:
        out = []
        for inst in self.model.instances.values():
            arn = f"arn:aws:ec2:::instance/{inst.instance_id}"
            if inst.imds_v1:
                # Tie to lateral movement: the instance role -> any privesc path.
                path_desc = None
                if inst.attached_role and inst.attached_role in self.paths:
                    path_desc = self.paths[inst.attached_role].describe()
                out.append(
                    Finding(
                        rule_id="CR-EC2-IMDSV1",
                        severity="HIGH",
                        resource_arn=arn,
                        resource_name=inst.instance_id,
                        message=(
                            f"Instance '{inst.instance_id}' allows token-less "
                            f"IMDSv1; an SSRF or on-host attacker can steal the "
                            f"'{inst.attached_role}' role credentials."
                        ),
                        remediation=(
                            "Require IMDSv2 (HttpTokens=required) and set "
                            "HttpPutResponseHopLimit=1."
                        ),
                        privesc_path=path_desc,
                        technique="AssumeRole" if path_desc else None,
                    )
                )
            if _looks_like_secret(inst.user_data):
                out.append(
                    Finding(
                        rule_id="CR-EC2-SECRETS",
                        severity="HIGH",
                        resource_arn=arn,
                        resource_name=inst.instance_id,
                        message=(
                            f"Instance '{inst.instance_id}' has plaintext "
                            f"secrets in user-data."
                        ),
                        remediation=(
                            "Remove secrets from user-data; use SSM Parameter "
                            "Store / Secrets Manager and an instance role."
                        ),
                    )
                )
        return out

    # --- Lambda -------------------------------------------------------- #
    def _scan_lambda(self) -> list[Finding]:
        out = []
        for fn in self.model.functions.values():
            role = self.model.roles.get(fn.execution_role or "")
            if role and principal_is_admin(role):
                out.append(
                    Finding(
                        rule_id="CR-LAMBDA-ADMIN",
                        severity="HIGH",
                        resource_arn=f"arn:aws:lambda:::function/{fn.name}",
                        resource_name=fn.name,
                        message=(
                            f"Lambda '{fn.name}' uses admin execution role "
                            f"'{fn.execution_role}'."
                        ),
                        remediation=(
                            "Scope the execution role to least privilege for "
                            "this function only."
                        ),
                    )
                )
        return out


def _looks_like_secret(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    needles = ["password", "secret", "api_token", "apikey", "api_key", "_key=", "token="]
    return any(n in lowered for n in needles)


# --------------------------------------------------------------------------- #
# SARIF emission
# --------------------------------------------------------------------------- #
def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    used_rule_ids = []
    seen = set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            used_rule_ids.append(f.rule_id)

    rules = []
    rule_index = {}
    for i, rid in enumerate(used_rule_ids):
        rule = RULES[rid]
        rule_index[rid] = i
        rules.append({
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.short},
            "fullDescription": {"text": rule.full},
            "helpUri": rule.help_uri or "https://github.com/VISHNU0906/cloudrange",
            "defaultConfiguration": {"level": _LEVEL.get(rule.default_severity, "warning")},
        })

    results = []
    for f in findings:
        msg = f.message
        if f.privesc_path:
            msg += f"  [privesc path: {f.privesc_path}]"
        props: dict[str, Any] = {"severity": f.severity, "remediation": f.remediation}
        if f.privesc_path:
            props["privescPath"] = f.privesc_path
        if f.technique:
            props["technique"] = f.technique
        props.update(f.properties)
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": rule_index[f.rule_id],
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": msg},
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": f.resource_name,
                            "fullyQualifiedName": f.resource_arn,
                            "kind": "resource",
                        }
                    ]
                }
            ],
            "properties": props,
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CLOUDRANGE",
                        "version": __version__,
                        "informationUri": "https://github.com/VISHNU0906/cloudrange",
                        "rules": rules,
                    }
                },
                "columnKind": "utf16CodeUnits",
                "results": results,
            }
        ],
    }


def validate_sarif(sarif: dict[str, Any]) -> None:
    """Validate emitted SARIF against the bundled 2.1.0 subset schema.

    Raises jsonschema.ValidationError on failure. Fully offline.
    """
    import jsonschema

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=sarif, schema=schema)


# --------------------------------------------------------------------------- #
# Markdown emission
# --------------------------------------------------------------------------- #
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
# ASCII-only badges so the Markdown renders identically on every console/locale
# (Windows code pages included) and stays diff-friendly in a repo.
_SEV_BADGE = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
    "INFO": "[INFO]",
}


def to_markdown(findings: list[Finding], account_id: str = "") -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines: list[str] = []
    lines.append("# CLOUDRANGE Detection Report")
    lines.append("")
    if account_id:
        lines.append(f"**Account:** `{account_id}`")
    lines.append(f"**Findings:** {len(findings)}")
    summary = "  ".join(
        f"{_SEV_BADGE.get(sev, sev)}: {counts.get(sev, 0)}"
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        if counts.get(sev)
    )
    lines.append(f"**Severity breakdown:** {summary}")
    lines.append("")
    lines.append("> Read-only audit. Each finding links to the exact privilege-")
    lines.append("> escalation path that consumes the misconfiguration.")
    lines.append("")

    ordered = sorted(
        findings, key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.rule_id, f.resource_name)
    )
    for i, f in enumerate(ordered, 1):
        lines.append(f"## {i}. {_SEV_BADGE.get(f.severity, f.severity)} - {f.rule_id}")
        lines.append("")
        lines.append(f"- **Resource:** `{f.resource_arn}`")
        lines.append(f"- **Finding:** {f.message}")
        if f.privesc_path:
            lines.append(f"- **Privesc path:** `{f.privesc_path}`")
        if f.technique:
            lines.append(f"- **Technique:** {f.technique}")
        lines.append(f"- **Remediation:** {f.remediation}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Convenience entry point
# --------------------------------------------------------------------------- #
def run_detection(model: AccountModel) -> list[Finding]:
    return Auditor(model).scan()
