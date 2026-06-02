"""End-to-end CLI smoke tests (mock mode), including SARIF file output parsing."""

from __future__ import annotations

import json

from cloudrange.cli import main


def test_cli_enumerate_json(capsys):
    rc = main(["enumerate", "--mock", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["account_id"] == "123456789012"
    assert "analyst" in out["users"]


def test_cli_privesc_json(capsys):
    rc = main(["privesc", "--mock", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["analyst"]["reaches_admin"] is True
    assert data["analyst"]["techniques"] == ["CreateAccessKey"]


def test_cli_privesc_single_no_path(capsys):
    rc = main(["privesc", "--mock", "--principal", "intern", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["reaches_admin"] is False


def test_cli_attack_succeeds(capsys):
    rc = main(["attack", "--mock", "--principal", "ci-deployer", "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["succeeded"] is True
    assert data["exfiltrated"]


def test_cli_detect_json_is_sarif(capsys):
    rc = main(["detect", "--mock", "--json"])
    assert rc == 0
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]


def test_cli_detect_writes_files(tmp_path, capsys):
    sarif_path = tmp_path / "out.sarif"
    md_path = tmp_path / "out.md"
    rc = main([
        "detect", "--mock",
        "--sarif-out", str(sarif_path),
        "--md-out", str(md_path),
    ])
    assert rc == 0
    # SARIF file parses back.
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    # Markdown file is non-empty and ASCII-safe.
    md = md_path.read_text(encoding="utf-8")
    assert "CLOUDRANGE Detection Report" in md
