# CLOUDRANGE

**Cloud attack-and-detect range.** Terraform deploys a deliberately-misconfigured
AWS environment; a boto3 attack chain automates **IAM privilege-escalation ->
lateral movement -> S3 data exfiltration**; a read-only auditor maps supported
privesc path and emits **SARIF + Markdown** remediation.

> Offense **and** defense, reproducible via `terraform apply` -- and runnable
> **fully offline** in `--mock` mode against a bundled fixture, so the privesc
> logic and detection can be explored and tested without an AWS account.

Built by **Vishnu Kosuri** ([github.com/VISHNU0906](https://github.com/VISHNU0906)). MIT licensed.

---

## IAM privilege escalation as graph reachability

The core idea -- the thing worth whiteboarding -- is that **individually-minor
permissions compose into administrator access**. No single statement says "you
are admin"; a *chain* of allowed actions lets a low-privilege principal *obtain*
admin. So detection cannot reason about single statements in isolation -- it must
reason about **reachability** in a permission graph.

CLOUDRANGE models that directly:

- **Nodes** = IAM principals (users + roles) + a synthetic `ADMIN` sink
  (effective `*:*`).
- **Edge `A -> B`** = "principal A can, using only permissions it already holds,
  obtain the privileges of B", labelled with the **named technique** that makes
  it possible (from [Rhino Security Labs' *AWS IAM Privilege Escalation
  Methods*](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)).
- A **BFS** finds the shortest path from any principal to `ADMIN`; that ordered,
  technique-labelled path *is* the privesc.

The edges are computed by a **real (scoped) IAM policy evaluator** -- not keyword
matching. It implements Effect Allow/Deny with **explicit-Deny precedence**,
`Action` wildcards (`iam:*`, `Create*`), and `Resource` ARN wildcards. An edge
exists only if the source principal genuinely passes evaluation for every
permission the technique requires. (Deliberately out of scope, documented below:
`Condition`, `NotAction`, permission boundaries, SCPs.)

### Attack-path diagram

```
                         CreateAccessKey(admin)
        analyst  ──────────────────────────────────────────────────►  ┌─────────┐
                                                                       │         │
                         PassRole + Lambda(lambda-admin-role)          │         │
   ci-deployer  ──────────────────────────────────────────────────►   │         │
                                                                       │  ADMIN  │
                         PutUserPolicy(self)                           │  (*:*)  │
  dev-deployer  ──────────────────────────────────────────────────►   │         │
                                                                       │         │
                         AttachUserPolicy(self)                        │         │
      support  ───────────────────────────────────────────────────►   │         │
                                                                       └────▲────┘
                                                                            │
                  AssumeRole          PassRole + Lambda(lambda-admin-role)  │
   ec2-app-role ─────────────► automation-role ─────────────────────────────┘
   (IMDSv1 SSRF)               (NOT admin -- a real pivot;  2-hop chain)
       intern  ──X  (no path -- genuinely least-privilege; a control case)
```

Five privesc paths: four distinct one-step techniques to direct-admin, plus one
**genuine 2-hop** chain -- `ec2-app-role --AssumeRole--> automation-role
--PassRole+Lambda--> ADMIN` -- where the pivot (`automation-role`) is **not**
admin, so no single edge reaches the sink and the BFS *must* traverse two hops.
And one control principal (`intern`) with **no** path, which the analyzer must
correctly leave alone (no false positives). That 2-hop case is the proof that
this reasons about **reachability**, not single statements.

---

## Quickstart (offline -- no AWS account needed)

```bash
pip install -r requirements.txt        # deps only; run via `python -m cloudrange`
# ...or install the `cloudrange` console script (editable keeps the top-level
# fixtures/ and schemas/ dirs resolvable):
pip install -e .

python -m cloudrange --version

# 1. See the (mock) vulnerable environment.
python -m cloudrange enumerate --mock

# 2. Find every privilege-escalation path.
python -m cloudrange privesc --mock

# 3. Run the attack chain end-to-end (simulated, logged step by step).
python -m cloudrange attack --mock --principal analyst

# 4. Read-only audit -> SARIF + Markdown.
python -m cloudrange detect --mock --sarif-out findings.sarif --md-out findings.md

# Run the offline test suite.
python -m pytest -q
```

(With the package installed, `cloudrange ...` works in place of
`python -m cloudrange ...`. A `Makefile` wraps all of these: `make privesc`,
`make attack`, `make detect`, `make report`, `make test`, `make validate`.)

### Sample: the attack chain

```
$ python -m cloudrange attack --mock --principal analyst
=== CLOUDRANGE attack chain [MOCK (simulated)] : start = analyst ===

[+] Step 1 - CreateAccessKey (iam:CreateAccessKey)
      $ aws iam create-access-key --user-name admin
      [SIMULATED] Minted access key AKIA<redacted> for 'admin'. Now authenticated as 'admin'.

[+] Step 2 - S3Exfil (s3:GetObject)
      $ aws s3 sync s3://cloudrange-crown-jewels/ ./loot/
      [SIMULATED] Downloaded 3 object(s): customer-pii.csv, prod-db-dump.sql, secrets/master.key

[+] REACHED ADMIN via CreateAccessKey
[+] EXFILTRATED 3 object(s) from 'cloudrange-crown-jewels': customer-pii.csv, ...
[OK] Attack chain succeeded.
```

### Sample: the detector (SARIF excerpt)

Each finding carries a severity, a remediation, and -- crucially -- **the exact
privesc path that consumes the misconfiguration**. IAM findings have no
file/line, so SARIF `logicalLocations` carry the principal/resource ARN. A full
sample is in [`docs/sample-findings.sarif`](docs/sample-findings.sarif) /
[`docs/sample-findings.md`](docs/sample-findings.md).

```json
{
  "ruleId": "CR-IAM-PRIVESC",
  "level": "error",
  "message": { "text": "Principal 'analyst' can escalate to administrator in 1 step(s) via CreateAccessKey.  [privesc path: analyst -> ADMIN]" },
  "locations": [{ "logicalLocations": [{ "name": "analyst",
      "fullyQualifiedName": "arn:aws:iam::123456789012:user/analyst", "kind": "resource" }]}],
  "properties": { "severity": "CRITICAL", "technique": "CreateAccessKey",
      "privescPath": "analyst -> ADMIN", "remediation": "Remove the escalation permission(s)..." }
}
```

The emitted SARIF is validated against a bundled SARIF 2.1.0 schema
([`schemas/sarif-2.1.0.schema.json`](schemas/sarif-2.1.0.schema.json)) on every
`detect` run -- fully offline. The output also validates cleanly against the
**official** SARIF 2.1.0 schema (json.schemastore.org), so it loads in the
GitHub code-scanning Security tab and any SARIF viewer.

---

## Architecture

```
cloudrange/
  model.py             Normalized account model + scoped IAM policy evaluator
                       (Allow/Deny + explicit-Deny precedence, action/ARN wildcards)
  managed_policies.py  Bundled AWS-managed policy docs (AdministratorAccess, ReadOnlyAccess)
  enumerate.py         Build the model -- fixtures (mock) OR boto3 read-only (real)
  privesc.py           *** THE SPINE *** permission graph + BFS reachability,
                       Rhino-Security technique catalog (CreateAccessKey, PassRole+Lambda,
                       PutUserPolicy, AttachUserPolicy, AssumeRole)
  attack.py            Execute a chosen path step-by-step (simulate/log in mock,
                       boto3 in real) -> exfil the crown-jewel S3 data
  detect.py            Read-only auditor (folds in IAMScout): flags every misconfig
                       with severity + the exact privesc path + remediation -> SARIF/MD
  cli.py               cloudrange enumerate | privesc | attack | detect  [--mock|--real]

fixtures/account.json  Vulnerable-account fixture (mirrors terraform/, 5 privesc paths)
schemas/               Bundled SARIF 2.1.0 validating schema
terraform/             The deployable vulnerable AWS env (terraform validate-clean)
terraform-hardened/    Line-by-line remediation overlay
tests/                 Offline tests: privesc paths, detector coverage, SARIF, CLI
```

**Mock vs real.** Every module is mode-agnostic: `enumerate` produces the same
`AccountModel` from a JSON fixture (`--mock`, the offline default) or from boto3
read-only calls (`--real`). boto3 is imported lazily *inside* the real-mode
branch, so import and the entire mock workflow never touch the network or
require credentials (there is a test that proves this).

---

## The vulnerable AWS environment (Terraform)

`terraform/` deploys the live version of the fixture: over-permissive IAM users
and roles with real privesc paths (`iam:CreateAccessKey` on `*`, `iam:PassRole`
+ Lambda, `iam:PutUserPolicy`, `iam:AttachUserPolicy`, an assume-role chain), a
public S3 bucket, an EC2 instance with token-less **IMDSv1** + secrets in
user-data, and an over-privileged Lambda. It is **`terraform validate`-clean**
(validated against Terraform 1.9.x + `hashicorp/aws ~> 5.0`; no `apply` needed
to validate). Billable compute (EC2/Lambda) is gated behind `deploy_compute`
(default `false`) so the IAM/S3 mess deploys effectively free.

See [`terraform/README.md`](terraform/README.md) for apply/destroy and the
[`terraform-hardened/`](terraform-hardened/README.md) overlay for the fix to
every flaw.

---

## Safety

> **This project creates deliberately-vulnerable infrastructure.**
>
> - Deploy `terraform/` **only in a brand-new, throwaway AWS account you own**.
>   Never apply it to an account with anything real in it.
> - The attack chain's `--real` mode performs **live AWS API calls** (creates
>   keys, Lambdas, policies). Run it **only against your own range**.
> - **Always `terraform destroy`** when you finish. Do not leave the range
>   running.
> - The bundled fixture and all seeded "crown-jewel" objects are **synthetic,
>   non-sensitive placeholders**.

The `--mock` workflow touches nothing -- no AWS, no network -- and is the
recommended way to explore the tool.

---

## Scope and limitations

The policy evaluator models the parts of IAM evaluation that drive
privilege-escalation reachability, and **deliberately** leaves out (so the
boundary is explicit, not accidental):

- `Condition` blocks, `NotAction`/`NotResource` -- the analyzer assumes
  conditions are satisfiable, the *conservative* (attacker-favoring) choice for
  an audit.
- Permission boundaries, Service Control Policies, session policies.
- Resource-based policies beyond IAM role trust documents.

The Rhino technique catalog is the high-impact subset (5 techniques); it is
structured so adding more is a single function each. The graph + BFS are
hand-rolled (no `networkx`) so the reachability search is fully self-contained
and testable offline.

## Tests

`python -m pytest -q` runs the offline suite: privesc path-finding asserted
against known expected paths (including the negative `intern` case and the
multi-hop assume-role chain), detector coverage of every planted misconfig,
SARIF schema validation + round-trip, and CLI end-to-end.

## License

MIT (c) 2026 Vishnu Kosuri. See [LICENSE](LICENSE).
