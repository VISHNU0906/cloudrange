"""Tests for the attack chain (mock simulation): it walks the privesc path,
reaches admin, and exfiltrates the crown-jewel objects -- fully offline."""

from __future__ import annotations

import pytest

from cloudrange.attack import run_attack
from cloudrange.enumerate import enumerate_account


@pytest.fixture(scope="module")
def model():
    return enumerate_account(mock=True)


def test_attack_ci_deployer_passrole(model):
    result = run_attack(model, "ci-deployer", mock=True)
    assert result.reached_admin
    assert result.succeeded
    assert "PassRole+Lambda" in [s.technique for s in result.steps]
    assert result.crown_jewel_bucket == "cloudrange-crown-jewels"
    assert "customer-pii.csv" in result.exfiltrated
    assert len(result.exfiltrated) == 3


def test_attack_analyst_create_access_key(model):
    result = run_attack(model, "analyst", mock=True)
    assert result.reached_admin
    step = next(s for s in result.steps if s.technique == "CreateAccessKey")
    # The minted key targets the admin user.
    assert "admin" in step.command


def test_attack_lateral_movement_multihop(model):
    result = run_attack(model, "ec2-app-role", mock=True)
    assert result.reached_admin
    techniques = [s.technique for s in result.steps]
    # Two escalation hops, in order, then the exfil step.
    assert techniques[:2] == ["AssumeRole", "PassRole+Lambda"]
    assume = next(s for s in result.steps if s.technique == "AssumeRole")
    # First hop assumes the non-admin intermediate discovered by the path-finder.
    assert "automation-role" in assume.command
    # Second hop passes the admin lambda role.
    passrole = next(s for s in result.steps if s.technique == "PassRole+Lambda")
    assert "lambda-admin-role" in passrole.command


def test_attack_self_escalation_targets_self(model):
    result = run_attack(model, "support", mock=True)
    step = next(s for s in result.steps if s.technique == "AttachUserPolicy")
    assert "support" in step.command  # acts on itself, not another user


def test_attack_no_path_principal(model):
    result = run_attack(model, "intern", mock=True)
    assert result.path is None
    assert not result.reached_admin
    assert not result.succeeded
    assert not result.exfiltrated


def test_every_step_logs_a_technique(model):
    result = run_attack(model, "ci-deployer", mock=True)
    for s in result.steps:
        assert s.technique
        assert s.command
        assert s.result


def test_attack_is_offline(model, monkeypatch):
    # Guard: mock attack must never import/use boto3 network. We assert it runs
    # without any AWS credentials configured.
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    result = run_attack(model, "ci-deployer", mock=True)
    assert result.succeeded
