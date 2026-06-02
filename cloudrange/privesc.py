"""privesc.py -- THE DEPTH SPINE.

IAM privilege escalation modeled as **graph reachability**.

Core idea (whiteboard this cold in an interview):

  Individually-minor permissions *compose* into administrator access. No single
  statement says "you are admin", but a chain of allowed actions lets a low-priv
  principal *obtain* admin. So detection cannot reason about single statements --
  it must reason about **reachability** in a permission graph.

Graph model
-----------
  * **Nodes** = principals (users + roles), plus a synthetic ``ADMIN`` sink node
    representing "effective *:* access".
  * **Edge A -> B** = "principal A can, using only permissions it already holds,
    obtain the privileges of B", labelled with the **named technique** that makes
    it possible (from Rhino Security Labs' *AWS IAM Privilege Escalation Methods*).
  * Some edges go directly to ``ADMIN`` (self-escalation: e.g. ``PutUserPolicy``
    with an admin document, or ``AttachUserPolicy`` of AdministratorAccess).
  * Some edges pivot through another principal that is itself admin (e.g.
    ``CreateAccessKey`` on an admin user, ``PassRole`` of an admin role to Lambda,
    ``AssumeRole`` into an admin role) -- those become edges to ``ADMIN`` *iff*
    the target principal is admin, and ordinary principal->principal edges
    otherwise (lateral movement).

A path from a starting principal to ``ADMIN`` is a privilege-escalation path.
We BFS for the **shortest** such path and return the ordered, technique-labelled
edges. The graph + BFS are hand-rolled (no networkx) -- the reachability search
is the moat, so it is implemented explicitly.

Technique catalog
-----------------
Each technique declares the *exact* permission set it requires; an edge exists
only if the source principal genuinely passes :func:`model.evaluate` for every
required action against the relevant resource. That is what makes this a real
analyzer and not a keyword matcher.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .model import (
    AccountModel,
    Principal,
    principal_can,
    principal_is_admin,
)

ADMIN_NODE = "ADMIN"


# --------------------------------------------------------------------------- #
# Edges
# --------------------------------------------------------------------------- #
@dataclass
class PrivescEdge:
    """A directed escalation edge in the permission graph."""

    src: str  # source principal name
    dst: str  # target principal name or ADMIN_NODE
    technique: str  # short technique id, e.g. "CreateAccessKey"
    title: str  # human title
    permissions: list[str]  # the permissions that enable this edge
    detail: str  # what the attacker does on this edge
    severity: str = "HIGH"
    reference: str = ""
    target_resource: str = ""  # concrete user/role the technique acts on

    def describe(self) -> str:
        arrow = "ADMIN" if self.dst == ADMIN_NODE else self.dst
        return f"{self.src} --[{self.technique}]--> {arrow}"


@dataclass
class PrivescPath:
    """An ordered chain of edges from a start principal to ADMIN."""

    start: str
    edges: list[PrivescEdge] = field(default_factory=list)

    @property
    def reaches_admin(self) -> bool:
        return bool(self.edges) and self.edges[-1].dst == ADMIN_NODE

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def techniques(self) -> list[str]:
        return [e.technique for e in self.edges]

    def describe(self) -> str:
        return "  ->  ".join([self.start] + [
            ("ADMIN" if e.dst == ADMIN_NODE else e.dst) for e in self.edges
        ])


# --------------------------------------------------------------------------- #
# Technique catalog -- each function returns edges from `src` if its required
# permissions are genuinely satisfied by the policy evaluator.
# --------------------------------------------------------------------------- #
TechniqueFn = Callable[[AccountModel, Principal], list[PrivescEdge]]

RHINO_REF = "Rhino Security Labs -- AWS IAM Privilege Escalation Methods"


def _t_create_access_key(model: AccountModel, src: Principal) -> list[PrivescEdge]:
    """iam:CreateAccessKey on another user -> mint long-lived creds for them.

    If the target user is admin, this is a direct path to ADMIN. Otherwise it is
    lateral movement to that user's privileges.
    """
    edges: list[PrivescEdge] = []
    for target in model.users.values():
        if target.name == src.name:
            continue
        if principal_can(src, "iam:CreateAccessKey", target.arn):
            dst = ADMIN_NODE if principal_is_admin(target) else target.name
            edges.append(
                PrivescEdge(
                    src=src.name,
                    dst=dst,
                    technique="CreateAccessKey",
                    title="Create access key for another IAM user",
                    permissions=["iam:CreateAccessKey"],
                    detail=(
                        f"Call iam:CreateAccessKey for user '{target.name}', "
                        f"obtaining valid long-lived credentials for that "
                        f"principal and inheriting all of its permissions."
                    ),
                    severity="CRITICAL" if dst == ADMIN_NODE else "HIGH",
                    reference=RHINO_REF,
                    target_resource=target.name,
                )
            )
    return edges


def _t_pass_role_lambda(model: AccountModel, src: Principal) -> list[PrivescEdge]:
    """iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction -> run code as
    a passed role. If the role is admin, that is admin code execution."""
    edges: list[PrivescEdge] = []
    has_lambda = principal_can(src, "lambda:CreateFunction") and principal_can(
        src, "lambda:InvokeFunction"
    )
    if not has_lambda:
        return edges
    for role in model.roles.values():
        if not _role_trusts_service(role, "lambda.amazonaws.com"):
            continue
        if not principal_can(src, "iam:PassRole", role.arn):
            continue
        dst = ADMIN_NODE if principal_is_admin(role) else role.name
        edges.append(
            PrivescEdge(
                src=src.name,
                dst=dst,
                technique="PassRole+Lambda",
                title="Pass an over-privileged role to a new Lambda function",
                permissions=["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                detail=(
                    f"Create a Lambda function with execution role "
                    f"'{role.name}' (PassRole), then invoke it to run "
                    f"arbitrary code with that role's permissions."
                ),
                severity="CRITICAL" if dst == ADMIN_NODE else "HIGH",
                reference=RHINO_REF,
                target_resource=role.name,
            )
        )
    return edges


def _t_put_user_policy(model: AccountModel, src: Principal) -> list[PrivescEdge]:
    """iam:PutUserPolicy on self (or any user) -> attach an inline admin policy.

    Prefer self-targeting (the realistic self-escalation) when allowed; fall
    back to any other user the principal can write a policy onto.
    """
    edges: list[PrivescEdge] = []
    target = _preferred_user_target(model, src, "iam:PutUserPolicy")
    if target is not None:
        same = target.name == src.name
        edges.append(
            PrivescEdge(
                src=src.name,
                dst=ADMIN_NODE,
                technique="PutUserPolicy",
                title="Write an inline admin policy onto an IAM user",
                permissions=["iam:PutUserPolicy"],
                detail=(
                    f"Call iam:PutUserPolicy on user "
                    f"'{'self' if same else target.name}' with an inline "
                    f'document granting {{"Action":"*","Resource":"*"}}.'
                ),
                severity="CRITICAL",
                reference=RHINO_REF,
                target_resource=target.name,
            )
        )
    return edges


def _t_attach_user_policy(model: AccountModel, src: Principal) -> list[PrivescEdge]:
    """iam:AttachUserPolicy on self -> attach the managed AdministratorAccess.

    Prefer self-targeting (realistic self-escalation) when allowed.
    """
    edges: list[PrivescEdge] = []
    target = _preferred_user_target(model, src, "iam:AttachUserPolicy")
    if target is not None:
        same = target.name == src.name
        edges.append(
            PrivescEdge(
                src=src.name,
                dst=ADMIN_NODE,
                technique="AttachUserPolicy",
                title="Attach the managed AdministratorAccess policy to a user",
                permissions=["iam:AttachUserPolicy"],
                detail=(
                    f"Call iam:AttachUserPolicy on "
                    f"'{'self' if same else target.name}' attaching "
                    f"arn:aws:iam::aws:policy/AdministratorAccess."
                ),
                severity="CRITICAL",
                reference=RHINO_REF,
                target_resource=target.name,
            )
        )
    return edges


def _preferred_user_target(
    model: AccountModel, src: Principal, action: str
) -> Principal | None:
    """Return the best target user for a self-escalation action: ``src`` itself
    if it is a user the action is allowed on, else the first other user."""
    if src.name in model.users and principal_can(src, action, src.arn):
        return model.users[src.name]
    for target in model.users.values():
        if principal_can(src, action, target.arn):
            return target
    return None


def _t_assume_role(model: AccountModel, src: Principal) -> list[PrivescEdge]:
    """sts:AssumeRole into a role that trusts this principal.

    Edge exists if the principal both (a) is allowed sts:AssumeRole on the role
    by its identity policy AND (b) is permitted by the role's trust policy. If
    the role is admin -> direct ADMIN; else lateral movement.
    """
    edges: list[PrivescEdge] = []
    for role in model.roles.values():
        if not principal_can(src, "sts:AssumeRole", role.arn):
            continue
        if not _role_trusts_principal(role, src):
            continue
        dst = ADMIN_NODE if principal_is_admin(role) else role.name
        edges.append(
            PrivescEdge(
                src=src.name,
                dst=dst,
                technique="AssumeRole",
                title="Assume a role whose trust policy permits this principal",
                permissions=["sts:AssumeRole"],
                detail=(
                    f"Call sts:AssumeRole on role '{role.name}', which trusts "
                    f"'{src.name}', obtaining that role's session credentials."
                ),
                severity="CRITICAL" if dst == ADMIN_NODE else "HIGH",
                reference=RHINO_REF,
                target_resource=role.name,
            )
        )
    return edges


TECHNIQUES: list[TechniqueFn] = [
    _t_create_access_key,
    _t_pass_role_lambda,
    _t_put_user_policy,
    _t_attach_user_policy,
    _t_assume_role,
]


# --------------------------------------------------------------------------- #
# Trust-policy helpers
# --------------------------------------------------------------------------- #
def _role_trusts_service(role: Principal, service: str) -> bool:
    return service in role.trust_principals


def _role_trusts_principal(role: Principal, src: Principal) -> bool:
    """Does the role's trust policy permit ``src`` to assume it?"""
    for entry in role.trust_principals:
        if entry == src.arn:
            return True
        # Allow account-root trust (a common over-broad pattern).
        if entry.endswith(":root"):
            return True
        # Wildcard trust.
        if entry == "*":
            return True
    return False


# --------------------------------------------------------------------------- #
# Graph construction + BFS reachability
# --------------------------------------------------------------------------- #
def build_edges(model: AccountModel) -> list[PrivescEdge]:
    """Compute every privesc edge in the account by running each technique
    against each principal."""
    edges: list[PrivescEdge] = []
    for principal in model.all_principals():
        # A principal that is already admin has no need to escalate.
        if principal_is_admin(principal):
            continue
        for technique in TECHNIQUES:
            edges.extend(technique(model, principal))
    return edges


def build_adjacency(model: AccountModel) -> dict[str, list[PrivescEdge]]:
    adj: dict[str, list[PrivescEdge]] = {}
    for edge in build_edges(model):
        adj.setdefault(edge.src, []).append(edge)
    return adj


def find_privesc_path(model: AccountModel, start: str) -> PrivescPath | None:
    """BFS for the **shortest** privilege-escalation path from ``start`` to ADMIN.

    Returns None if the principal cannot reach admin (genuinely low-privilege).
    """
    start_principal = model.principal(start)
    if start_principal is None:
        raise KeyError(f"Unknown principal: {start!r}")
    # If the start is already admin, there is nothing to escalate.
    if principal_is_admin(start_principal):
        return None

    adj = build_adjacency(model)

    # BFS. Each queue item is (current_node, path_of_edges).
    from collections import deque

    queue: deque[tuple[str, list[PrivescEdge]]] = deque([(start, [])])
    visited: set[str] = {start}

    while queue:
        node, path = queue.popleft()
        for edge in adj.get(node, []):
            if edge.dst == ADMIN_NODE:
                return PrivescPath(start=start, edges=path + [edge])
            if edge.dst not in visited:
                visited.add(edge.dst)
                queue.append((edge.dst, path + [edge]))
    return None


def find_all_privesc_paths(model: AccountModel) -> dict[str, PrivescPath]:
    """Shortest privesc path for every principal that can reach admin."""
    out: dict[str, PrivescPath] = {}
    for principal in model.all_principals():
        if principal_is_admin(principal):
            continue
        path = find_privesc_path(model, principal.name)
        if path is not None:
            out[principal.name] = path
    return out
