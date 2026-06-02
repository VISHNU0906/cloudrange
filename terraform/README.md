# CLOUDRANGE Terraform -- the vulnerable AWS range

> **WARNING -- DELIBERATELY INSECURE INFRASTRUCTURE.**
> This module creates IAM users/roles with real privilege-escalation paths, a
> public S3 bucket, an EC2 instance with token-less IMDSv1 and secrets in
> user-data, and an over-privileged Lambda. **Deploy ONLY in a brand-new,
> throwaway AWS account that you own and can afford to delete. NEVER apply this
> to an account with anything real in it.** Always `terraform destroy` when done.

This range mirrors `../fixtures/account.json` exactly (same principal names,
same five privesc paths), so the offline `cloudrange ... --mock` workflow and a
live `--real` run against this range tell the identical story.

## What it deploys

| Resource | Why it is here |
|---|---|
| `cloudrange-admin` user (AdministratorAccess) | The privesc **sink** every path reaches. |
| `cloudrange-analyst` | PATH 1: `iam:CreateAccessKey` on `*` -> mint admin's keys. |
| `cloudrange-ci-deployer` | PATH 2: `iam:PassRole` + Lambda create/invoke -> run as `lambda-admin-role`. |
| `cloudrange-dev-deployer` | PATH 3: `iam:PutUserPolicy` on self -> inline `*:*` policy. |
| `cloudrange-support` | PATH 4: `iam:AttachUserPolicy` on `*` -> attach AdministratorAccess. |
| `cloudrange-intern` | Control user with **no** privesc path (proves no false positives). |
| `lambda-admin-role` | PATH 2 sink: admin execution role trusting Lambda. |
| `ec2-app-role` / `automation-role` | PATH 5: genuine 2-hop chain -- `ec2-app-role` assumes the **non-admin** `automation-role`, which then escalates via PassRole+Lambda. |
| `cloudrange-public-assets` bucket | Public (Block Public Access disabled + public-read ACL), unencrypted. |
| `cloudrange-crown-jewels` bucket | The sensitive data the attack chain exfiltrates (synthetic placeholder objects). |
| EC2 web server *(optional)* | IMDSv1 enabled + plaintext secrets in user-data. |
| `report-generator` Lambda *(optional)* | Over-privileged (admin execution role). |

## Cost & safety

- The **IAM + S3** resources are effectively free (a few cents for S3 storage).
- The **EC2 + Lambda** are gated behind `deploy_compute` (default `false`) so the
  free IAM/S3 mess deploys without launching billable compute. The IAM privesc
  paths work either way. Set `-var deploy_compute=true` to include them
  (`t3.micro` is free-tier eligible; Lambda at-rest is free).
- S3 buckets use `force_destroy = true` so `terraform destroy` removes them even
  with objects inside. Object content is synthetic, non-sensitive placeholder text.

## Usage

```bash
cd terraform

# 1. Initialize (downloads the AWS/random/archive providers).
terraform init

# 2. (Recommended) sanity-check the config -- no AWS credentials needed.
terraform validate
terraform fmt -check

# 3. Review the plan. IAM + S3 only (free):
terraform plan

#    ...or include the billable compute:
terraform plan -var deploy_compute=true

# 4. Deploy (THROWAWAY ACCOUNT ONLY).
terraform apply

# 5. Run the attack chain / detector against it (real mode):
cd ..
cloudrange enumerate --real
cloudrange privesc   --real
cloudrange attack    --real --principal cloudrange-analyst   # CAUTION: live calls
cloudrange detect    --real --sarif-out findings.sarif

# 6. TEAR DOWN. Always. Do not leave this running.
cd terraform
terraform destroy
```

## Validation status

`terraform validate` and `terraform fmt -check` both pass cleanly against
Terraform 1.9.x with `hashicorp/aws ~> 5.0`. No `apply` is required to validate.

## Hardened version

See `../terraform-hardened/README.md` for the line-by-line remediation of every
misconfiguration here (least-privilege policies, scoped `PassRole`, IMDSv2
required, Block Public Access on, secrets out of user-data).
