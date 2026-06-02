"""cloudrange CLI -- enumerate | privesc | attack | detect  [--mock].

Implemented with argparse (zero third-party CLI deps) so the tool runs anywhere
Python 3.11 does. ``--mock`` (the default) operates entirely on the bundled
fixture; ``--real`` uses boto3 against a deployed range.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .attack import run_attack
from .detect import run_detection, to_markdown, to_sarif, validate_sarif
from .enumerate import enumerate_account
from .privesc import find_all_privesc_paths, find_privesc_path

BANNER = r"""
  ___ _    ___  _   _ ___  ___    _   _  _  ___ ___
 / __| |  / _ \| | | |   \| _ \  /_\ | \| |/ __| __|
| (__| |_| (_) | |_| | |) |   / / _ \| .` | (_ | _|
 \___|____\___/ \___/|___/|_|_\/_/ \_\_|\_|\___|___|
  cloud attack-and-detect range  v{ver}
""".format(ver=__version__)


def _add_common(p: argparse.ArgumentParser) -> None:
    mode = p.add_mutually_exclusive_group()
    mode.add_argument(
        "--mock",
        dest="mock",
        action="store_true",
        default=True,
        help="Use the bundled fixture (offline, default).",
    )
    mode.add_argument(
        "--real",
        dest="mock",
        action="store_false",
        help="Use boto3 against a live (throwaway) AWS account.",
    )
    p.add_argument("--fixture", help="Path to a fixture JSON (mock mode).")
    p.add_argument("--region", default="us-east-1", help="AWS region (real mode).")
    p.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")


def _load(args) -> object:
    return enumerate_account(mock=args.mock, fixture=getattr(args, "fixture", None),
                             region=args.region)


# --------------------------------------------------------------------------- #
def cmd_enumerate(args) -> int:
    model = _load(args)
    if args.json:
        out = {
            "account_id": model.account_id,
            "users": sorted(model.users),
            "roles": sorted(model.roles),
            "buckets": sorted(model.buckets),
            "instances": sorted(model.instances),
            "functions": sorted(model.functions),
        }
        print(json.dumps(out, indent=2))
        return 0
    print(f"Account: {model.account_id}")
    print(f"\nUsers ({len(model.users)}):")
    for name, p in sorted(model.users.items()):
        admin = "  [ADMIN]" if _is_admin(p) else ""
        print(f"  - {name}{admin}")
    print(f"\nRoles ({len(model.roles)}):")
    for name, p in sorted(model.roles.items()):
        admin = "  [ADMIN]" if _is_admin(p) else ""
        trust = f"  trusts={p.trust_principals}" if p.trust_principals else ""
        print(f"  - {name}{admin}{trust}")
    print(f"\nBuckets ({len(model.buckets)}):")
    for name, b in sorted(model.buckets.items()):
        flags = []
        if b.public:
            flags.append("PUBLIC")
        if b.crown_jewel:
            flags.append("CROWN-JEWEL")
        print(f"  - {name}{('  [' + ','.join(flags) + ']') if flags else ''}")
    print(f"\nInstances ({len(model.instances)}):")
    for name, inst in sorted(model.instances.items()):
        print(f"  - {name}  role={inst.attached_role}  imdsv1={inst.imds_v1}")
    print(f"\nFunctions ({len(model.functions)}):")
    for name, fn in sorted(model.functions.items()):
        print(f"  - {name}  role={fn.execution_role}")
    return 0


def _is_admin(p) -> bool:
    from .model import principal_is_admin

    return principal_is_admin(p)


def cmd_privesc(args) -> int:
    model = _load(args)
    if args.principal:
        path = find_privesc_path(model, args.principal)
        if args.json:
            print(json.dumps(_path_json(args.principal, path), indent=2))
            return 0
        if path is None:
            print(f"[-] No privilege-escalation path from '{args.principal}'.")
            return 0
        _print_path(args.principal, path)
        return 0

    paths = find_all_privesc_paths(model)
    if args.json:
        print(json.dumps(
            {name: _path_json(name, p) for name, p in paths.items()}, indent=2))
        return 0
    if not paths:
        print("[-] No privilege-escalation paths found.")
        return 0
    print(f"[+] Found {len(paths)} principal(s) that can escalate to admin:\n")
    for name, path in sorted(paths.items()):
        _print_path(name, path)
        print()
    return 0


def _path_json(start: str, path) -> dict:
    if path is None:
        return {"start": start, "reaches_admin": False, "edges": []}
    return {
        "start": start,
        "reaches_admin": path.reaches_admin,
        "length": path.length,
        "techniques": path.techniques,
        "edges": [
            {
                "src": e.src,
                "dst": e.dst,
                "technique": e.technique,
                "title": e.title,
                "permissions": e.permissions,
                "severity": e.severity,
                "detail": e.detail,
            }
            for e in path.edges
        ],
    }


def _print_path(start: str, path) -> None:
    print(f"[!] {start}  ==>  ADMIN   ({path.length} step(s))")
    print(f"    {path.describe()}")
    for i, e in enumerate(path.edges, 1):
        print(f"      {i}. [{e.severity}] {e.technique}: {e.detail}")


def cmd_attack(args) -> int:
    model = _load(args)
    if not args.principal:
        # Default to the first principal that has a path.
        paths = find_all_privesc_paths(model)
        if not paths:
            print("[-] No attackable principal found.")
            return 1
        args.principal = sorted(paths)[0]
        print(f"[*] No --principal given; attacking '{args.principal}'.\n")

    if not args.mock:
        _confirm_real("attack")

    result = run_attack(model, args.principal, mock=args.mock, region=args.region)

    if args.json:
        print(json.dumps(_attack_json(result), indent=2))
        return 0 if result.succeeded else 1

    mode = "MOCK (simulated)" if args.mock else "REAL"
    print(f"=== CLOUDRANGE attack chain [{mode}] : start = {result.start} ===\n")
    if result.path is None:
        print(f"[-] No privilege-escalation path from '{result.start}'.")
        return 1
    for step in result.steps:
        mark = "[+]" if step.success else "[-]"
        print(f"{mark} Step {step.seq} - {step.technique} ({step.action})")
        print(f"      $ {step.command}")
        print(f"      {step.result}\n")
    if result.reached_admin:
        print(f"[+] REACHED ADMIN via {' -> '.join(result.path.techniques)}")
    if result.exfiltrated:
        print(f"[+] EXFILTRATED {len(result.exfiltrated)} object(s) from "
              f"'{result.crown_jewel_bucket}': {', '.join(result.exfiltrated)}")
    print()
    print("[OK] Attack chain succeeded." if result.succeeded
          else "[--] Attack chain did not reach crown-jewel data.")
    return 0 if result.succeeded else 1


def _attack_json(result) -> dict:
    return {
        "start": result.start,
        "reached_admin": result.reached_admin,
        "succeeded": result.succeeded,
        "crown_jewel_bucket": result.crown_jewel_bucket,
        "exfiltrated": result.exfiltrated,
        "steps": [
            {
                "seq": s.seq,
                "technique": s.technique,
                "action": s.action,
                "command": s.command,
                "result": s.result,
                "success": s.success,
            }
            for s in result.steps
        ],
    }


def cmd_detect(args) -> int:
    model = _load(args)
    findings = run_detection(model)

    sarif = to_sarif(findings)
    # Always validate the SARIF we produce.
    try:
        validate_sarif(sarif)
        sarif_valid = True
    except Exception as exc:  # pragma: no cover - schema is correct
        sarif_valid = False
        print(f"[!] SARIF validation FAILED: {exc}", file=sys.stderr)

    if args.sarif_out:
        Path(args.sarif_out).write_text(
            json.dumps(sarif, indent=2), encoding="utf-8")
    if args.md_out:
        Path(args.md_out).write_text(
            to_markdown(findings, model.account_id), encoding="utf-8")

    if args.json:
        print(json.dumps(sarif, indent=2))
        return 0

    if args.markdown:
        print(to_markdown(findings, model.account_id))
        return 0

    # Default: human summary.
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print(f"=== CLOUDRANGE detection : account {model.account_id} ===\n")
    print(f"[+] {len(findings)} finding(s)  "
          f"(SARIF schema-valid: {sarif_valid})")
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    print("    " + "  ".join(
        f"{sev}={counts.get(sev, 0)}" for sev in order if counts.get(sev)))
    print()
    for f in sorted(findings, key=lambda x: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                              "LOW": 3, "INFO": 4}.get(x.severity, 9),
                                             x.rule_id)):
        print(f"  [{f.severity:8}] {f.rule_id:18} {f.resource_name}")
        print(f"             {f.message}")
        if f.privesc_path:
            print(f"             privesc: {f.privesc_path}")
        print(f"             fix: {f.remediation}")
        print()
    if args.sarif_out:
        print(f"[OK] SARIF written to {args.sarif_out}")
    if args.md_out:
        print(f"[OK] Markdown written to {args.md_out}")
    return 0


def _confirm_real(action: str) -> None:
    print(f"[!!] REAL mode {action}: this performs live AWS API calls against "
          f"the target account.")
    print("[!!] Only run against a THROWAWAY account you own. "
          "Always 'terraform destroy' afterwards.")


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloudrange",
        description="CLOUDRANGE -- cloud attack-and-detect range.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"cloudrange {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enum = sub.add_parser("enumerate", help="List principals/policies/buckets.")
    _add_common(p_enum)
    p_enum.set_defaults(func=cmd_enumerate)

    p_priv = sub.add_parser("privesc", help="Find privilege-escalation paths.")
    _add_common(p_priv)
    p_priv.add_argument("--principal", help="Single principal to analyze.")
    p_priv.set_defaults(func=cmd_privesc)

    p_atk = sub.add_parser("attack", help="Execute a privesc path + exfil.")
    _add_common(p_atk)
    p_atk.add_argument("--principal", help="Start principal.")
    p_atk.set_defaults(func=cmd_attack)

    p_det = sub.add_parser("detect", help="Audit + emit SARIF/Markdown.")
    _add_common(p_det)
    p_det.add_argument("--markdown", action="store_true",
                       help="Print the Markdown report to stdout.")
    p_det.add_argument("--sarif-out", help="Write SARIF to this file.")
    p_det.add_argument("--md-out", help="Write Markdown to this file.")
    p_det.set_defaults(func=cmd_detect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
