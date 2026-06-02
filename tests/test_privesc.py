"""Tests for the privilege-escalation reachability engine (the depth spine).

These assert KNOWN expected paths against the bundled fixture. They run fully
offline (mock mode only) and require no AWS credentials.
"""

from __future__ import annotations

import pytest

from cloudrange.enumerate import enumerate_account
from cloudrange.model import principal_can, principal_is_admin
from cloudrange.privesc import (
    ADMIN_NODE,
    find_all_privesc_paths,
    find_privesc_path,
)


@pytest.fixture(scope="module")
def model():
    return enumerate_account(mock=True)


# --------------------------------------------------------------------------- #
# Policy evaluator sanity (the core that everything else depends on)
# --------------------------------------------------------------------------- #
def test_admin_user_is_admin(model):
    assert principal_is_admin(model.users["admin"])


def test_lambda_admin_role_is_admin(model):
    assert principal_is_admin(model.roles["lambda-admin-role"])


def test_intern_is_not_admin(model):
    assert not principal_is_admin(model.users["intern"])


def test_readonly_does_not_grant_escalation(model):
    analyst = model.users["analyst"]
    # ReadOnlyAccess must NOT, on its own, grant a write/escalation action.
    # analyst's escalation comes from its inline policy, not ReadOnlyAccess.
    assert principal_can(analyst, "iam:CreateAccessKey", "*")
    assert not principal_can(model.users["intern"], "iam:CreateAccessKey", "*")


def test_explicit_deny_precedence():
    from cloudrange.model import Statement, evaluate

    stmts = [
        Statement("Allow", ["*"], ["*"]),
        Statement("Deny", ["iam:CreateAccessKey"], ["*"]),
    ]
    # Explicit deny must beat the broad allow.
    assert not evaluate(stmts, "iam:CreateAccessKey", "*")
    assert evaluate(stmts, "s3:GetObject", "*")


def test_action_wildcard_matching():
    from cloudrange.model import Statement, evaluate

    stmts = [Statement("Allow", ["iam:Create*"], ["*"])]
    assert evaluate(stmts, "iam:CreateAccessKey", "*")
    assert not evaluate(stmts, "iam:DeleteUser", "*")


# --------------------------------------------------------------------------- #
# PATH 1 -- analyst via CreateAccessKey on admin user
# --------------------------------------------------------------------------- #
def test_path1_analyst_create_access_key(model):
    path = find_privesc_path(model, "analyst")
    assert path is not None
    assert path.reaches_admin
    assert path.length == 1
    assert path.techniques == ["CreateAccessKey"]
    assert path.edges[0].dst == ADMIN_NODE
    assert path.edges[0].severity == "CRITICAL"


# --------------------------------------------------------------------------- #
# PATH 2 -- ci-deployer via PassRole + Lambda
# --------------------------------------------------------------------------- #
def test_path2_ci_deployer_passrole_lambda(model):
    path = find_privesc_path(model, "ci-deployer")
    assert path is not None
    assert path.reaches_admin
    assert path.techniques == ["PassRole+Lambda"]
    assert path.edges[0].dst == ADMIN_NODE


# --------------------------------------------------------------------------- #
# PATH 3 -- dev-deployer self-escalation via PutUserPolicy
# --------------------------------------------------------------------------- #
def test_path3_dev_deployer_put_user_policy(model):
    path = find_privesc_path(model, "dev-deployer")
    assert path is not None
    assert path.reaches_admin
    assert "PutUserPolicy" in path.techniques


# --------------------------------------------------------------------------- #
# PATH 4 -- support self-escalation via AttachUserPolicy
# --------------------------------------------------------------------------- #
def test_path4_support_attach_user_policy(model):
    path = find_privesc_path(model, "support")
    assert path is not None
    assert path.reaches_admin
    assert "AttachUserPolicy" in path.techniques


# --------------------------------------------------------------------------- #
# PATH 5 -- GENUINE MULTI-HOP lateral movement + escalation:
#   ec2-app-role --AssumeRole--> automation-role --PassRole+Lambda--> ADMIN
# This is the case that proves the BFS reachability search is *necessary*: no
# single edge from ec2-app-role reaches admin; it must traverse two hops through
# a non-admin intermediate role.
# --------------------------------------------------------------------------- #
def test_path5_multihop_assume_then_passrole(model):
    path = find_privesc_path(model, "ec2-app-role")
    assert path is not None
    assert path.reaches_admin
    # Exactly two hops, in order.
    assert path.length == 2
    assert path.techniques == ["AssumeRole", "PassRole+Lambda"]
    # First hop pivots into the NON-admin intermediate (lateral movement),
    # only the second hop reaches ADMIN.
    assert path.edges[0].dst == "automation-role"
    assert path.edges[0].dst != ADMIN_NODE
    assert path.edges[1].dst == ADMIN_NODE


def test_intermediate_role_is_not_admin(model):
    # The pivot role must genuinely NOT be admin, else the path would collapse
    # to a single hop and the multi-hop property would be fake.
    from cloudrange.model import principal_is_admin

    assert not principal_is_admin(model.roles["automation-role"])


# --------------------------------------------------------------------------- #
# Negative: intern has NO privesc path (no false positives)
# --------------------------------------------------------------------------- #
def test_intern_has_no_path(model):
    assert find_privesc_path(model, "intern") is None


def test_admin_returns_none(model):
    # An already-admin principal has nothing to escalate.
    assert find_privesc_path(model, "admin") is None


# --------------------------------------------------------------------------- #
# Aggregate: at least the documented privesc-capable principals are found
# --------------------------------------------------------------------------- #
def test_find_all_paths(model):
    paths = find_all_privesc_paths(model)
    escalating = set(paths.keys())
    # automation-role can itself escalate (PassRole+Lambda), and ec2-app-role
    # reaches admin through it -- both appear.
    expected = {"analyst", "ci-deployer", "dev-deployer", "support",
                "ec2-app-role", "automation-role"}
    assert expected.issubset(escalating)
    # intern and already-admins must NOT appear.
    assert "intern" not in escalating
    assert "admin" not in escalating


def test_unknown_principal_raises(model):
    with pytest.raises(KeyError):
        find_privesc_path(model, "does-not-exist")
