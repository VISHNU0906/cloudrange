"""Tests for the read-only auditor: every planted misconfig is found, each
privesc finding links to its path, and the SARIF parses + validates."""

from __future__ import annotations

import json

import pytest

from cloudrange.detect import (
    RULES,
    Auditor,
    run_detection,
    to_markdown,
    to_sarif,
    validate_sarif,
)
from cloudrange.enumerate import enumerate_account


@pytest.fixture(scope="module")
def model():
    return enumerate_account(mock=True)


@pytest.fixture(scope="module")
def findings(model):
    return run_detection(model)


# --------------------------------------------------------------------------- #
# Coverage: every planted misconfig class is detected
# --------------------------------------------------------------------------- #
def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_all_planted_rule_classes_fire(findings):
    fired = _rule_ids(findings)
    expected = {
        "CR-IAM-PRIVESC",     # the 5 escalation paths
        "CR-IAM-CREATEKEY",   # analyst
        "CR-IAM-PASSROLE",    # ci-deployer
        "CR-IAM-SELFPOLICY",  # dev-deployer + support
        "CR-IAM-ADMINROLE",   # lambda-admin-role (admin execution role)
        "CR-IAM-TRUST",       # automation-role trust of ec2-app-role
        "CR-S3-PUBLIC",       # cloudrange-public-assets
        "CR-S3-NOENC",        # cloudrange-public-assets has no encryption
        "CR-EC2-IMDSV1",      # web server IMDSv1
        "CR-EC2-SECRETS",     # user-data secrets
        "CR-LAMBDA-ADMIN",    # report-generator
    }
    missing = expected - fired
    assert not missing, f"detector missed misconfig classes: {missing}"


def test_privesc_findings_count(findings):
    privesc = [f for f in findings if f.rule_id == "CR-IAM-PRIVESC"]
    # analyst, ci-deployer, dev-deployer, support, ec2-app-role, automation-role
    assert len(privesc) == 6
    # The multi-hop ec2-app-role path must be reported as 2 steps.
    ec2 = next(f for f in privesc if f.resource_name == "ec2-app-role")
    assert ec2.properties["path_length"] == 2


def test_every_privesc_finding_has_a_path(findings):
    for f in findings:
        if f.rule_id == "CR-IAM-PRIVESC":
            assert f.privesc_path, f"privesc finding for {f.resource_name} has no path"
            assert "ADMIN" in f.privesc_path


def test_overpermission_findings_link_to_path(findings):
    # The CreateAccessKey / PassRole / self-policy findings must name the exact
    # privesc path that consumes them -- the headline linkage requirement.
    for rid in ("CR-IAM-CREATEKEY", "CR-IAM-PASSROLE", "CR-IAM-SELFPOLICY"):
        matched = [f for f in findings if f.rule_id == rid]
        assert matched, f"no findings for {rid}"
        for f in matched:
            assert f.privesc_path, f"{rid} finding for {f.resource_name} has no linked path"


def test_public_bucket_flagged(findings):
    pub = [f for f in findings if f.rule_id == "CR-S3-PUBLIC"]
    assert any(f.resource_name == "cloudrange-public-assets" for f in pub)


def test_imdsv1_flagged(findings):
    imds = [f for f in findings if f.rule_id == "CR-EC2-IMDSV1"]
    assert imds
    assert any("i-0web0server0range" in f.resource_name for f in imds)


def test_secrets_in_userdata_flagged(findings):
    sec = [f for f in findings if f.rule_id == "CR-EC2-SECRETS"]
    assert sec


def test_every_finding_has_remediation(findings):
    for f in findings:
        assert f.remediation, f"{f.rule_id} has no remediation"
        assert f.rule_id in RULES, f"{f.rule_id} not in rule catalog"


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #
def test_sarif_structure_and_validates(findings):
    sarif = to_sarif(findings)
    # Round-trips through JSON (proves it is real, serializable JSON).
    reparsed = json.loads(json.dumps(sarif))
    assert reparsed["version"] == "2.1.0"
    assert reparsed["runs"][0]["tool"]["driver"]["name"] == "CLOUDRANGE"
    # Validates against the bundled SARIF 2.1.0 subset schema (offline).
    validate_sarif(reparsed)


def test_sarif_results_have_logical_locations(findings):
    sarif = to_sarif(findings)
    results = sarif["runs"][0]["results"]
    assert len(results) == len(findings)
    for r in results:
        loc = r["locations"][0]["logicalLocations"][0]
        assert loc["fullyQualifiedName"]  # the resource ARN
        assert r["level"] in ("error", "warning", "note")


def test_sarif_rules_declared(findings):
    sarif = to_sarif(findings)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    declared = {r["id"] for r in rules}
    used = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    # Every used ruleId must be declared in the driver.
    assert used.issubset(declared)


def test_sarif_levels_map_severity(findings):
    sarif = to_sarif(findings)
    for r in sarif["runs"][0]["results"]:
        sev = r["properties"]["severity"]
        if sev in ("CRITICAL", "HIGH"):
            assert r["level"] == "error"
        elif sev == "MEDIUM":
            assert r["level"] == "warning"


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def test_markdown_renders(findings, model):
    md = to_markdown(findings, model.account_id)
    assert "# CLOUDRANGE Detection Report" in md
    assert "Privesc path" in md
    assert md.isascii(), "Markdown must be ASCII-safe for all consoles"
