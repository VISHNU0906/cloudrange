"""Tests for enumeration + the model, and the offline guarantee of mock mode."""

from __future__ import annotations

import sys

import pytest

from cloudrange.enumerate import enumerate_account, load_from_fixture
from cloudrange.model import Statement, evaluate, principal_is_admin


@pytest.fixture(scope="module")
def model():
    return enumerate_account(mock=True)


def test_fixture_loads_expected_principals(model):
    assert set(model.users) == {
        "admin", "analyst", "ci-deployer", "dev-deployer", "intern", "support"
    }
    assert set(model.roles) == {
        "lambda-admin-role", "ec2-app-role", "automation-role"
    }


def test_managed_policy_inlined(model):
    # admin's AdministratorAccess managed policy must be inlined into statements.
    admin = model.users["admin"]
    assert any(p.is_managed for p in admin.policies)
    assert principal_is_admin(admin)


def test_buckets_and_crown_jewel(model):
    assert model.buckets["cloudrange-public-assets"].public
    assert model.buckets["cloudrange-crown-jewels"].crown_jewel
    assert model.crown_jewel_buckets()[0].name == "cloudrange-crown-jewels"


def test_instance_imds_and_userdata(model):
    inst = model.instances["i-0web0server0range"]
    assert inst.imds_v1
    assert inst.attached_role == "ec2-app-role"
    assert "PASSWORD" in inst.user_data.upper()


def test_mock_mode_does_not_import_boto3():
    # Critical offline guarantee: loading a fixture must not require boto3.
    # We can't unimport an already-loaded module, but we *can* prove the mock
    # code path never references it by loading with boto3 hidden.
    saved = sys.modules.pop("boto3", None)
    sys.modules["boto3"] = None  # any attribute access raises -> would fail if used
    try:
        m = load_from_fixture()
        assert m.account_id == "123456789012"
    finally:
        if saved is not None:
            sys.modules["boto3"] = saved
        else:
            sys.modules.pop("boto3", None)


def test_evaluate_resource_scoping():
    # A resource-scoped allow must not match a different resource.
    stmts = [Statement("Allow", ["iam:PutUserPolicy"],
                       ["arn:aws:iam::123456789012:user/dev-deployer"])]
    assert evaluate(stmts, "iam:PutUserPolicy",
                    "arn:aws:iam::123456789012:user/dev-deployer")
    assert not evaluate(stmts, "iam:PutUserPolicy",
                        "arn:aws:iam::123456789012:user/admin")


def test_wildcard_resource_matches_all():
    stmts = [Statement("Allow", ["iam:CreateAccessKey"], ["*"])]
    assert evaluate(stmts, "iam:CreateAccessKey",
                    "arn:aws:iam::123456789012:user/anyone")
