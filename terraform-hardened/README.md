# CLOUDRANGE -- hardened configuration (the fix for every planted flaw)

This is the remediation overlay for `../terraform`. For each deliberate
misconfiguration in the vulnerable range, it shows the secure version. The
through-line is **least privilege + reachability-aware design**: no single
principal should be able to *compose* its permissions into administrator access.

Run `cloudrange detect --real` (or `--mock`) against the hardened environment
and it should report **zero** `CR-IAM-PRIVESC` findings.

---

## PATH 1 -- `iam:CreateAccessKey` on `*`  (CR-IAM-CREATEKEY)

**Vulnerable**

```hcl
{ Effect = "Allow", Action = ["iam:CreateAccessKey"], Resource = "*" }
```

**Hardened** -- scope to the principal's own user only (self-service key
rotation), never `*`:

```hcl
{
  Effect   = "Allow"
  Action   = ["iam:CreateAccessKey", "iam:ListAccessKeys"]
  Resource = "arn:aws:iam::${local.account_id}:user/$${aws:username}"
}
```

`$${aws:username}` resolves to the caller, so a user can only manage its own
keys. Better still: remove long-lived keys entirely and use SSO/STS.

---

## PATH 2 -- `iam:PassRole` on `*` + Lambda  (CR-IAM-PASSROLE)

**Vulnerable** -- `PassRole` on `*` lets `ci-deployer` pass the admin role.

**Hardened** -- constrain `PassRole` to a single least-privilege role and pin
the service it may be passed to:

```hcl
{
  Effect   = "Allow"
  Action   = ["iam:PassRole"]
  Resource = aws_iam_role.lambda_least_priv.arn
  Condition = {
    StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" }
  }
}
```

And remove `AdministratorAccess` from the Lambda execution role -- give it only
the specific actions the function needs.

---

## PATH 3 / 4 -- `iam:PutUserPolicy` / `iam:AttachUserPolicy`  (CR-IAM-SELFPOLICY)

**Vulnerable** -- a principal can write/attach policies to itself -> instant admin.

**Hardened** -- **no human/service principal should hold `iam:PutUserPolicy`,
`iam:AttachUserPolicy`, `iam:PutRolePolicy`, or `iam:AttachRolePolicy`.** Route
all IAM changes through a reviewed Terraform/CI pipeline running under a
dedicated automation role, and deny self-modification with a permission
boundary:

```hcl
# Permission boundary attached to every human user.
{
  Effect = "Deny"
  Action = [
    "iam:PutUserPolicy", "iam:AttachUserPolicy",
    "iam:PutRolePolicy", "iam:AttachRolePolicy",
    "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"
  ]
  Resource = "*"
}
```

---

## PATH 5 -- 2-hop assume-role + PassRole chain  (CR-IAM-TRUST + CR-IAM-PASSROLE + CR-IAM-ADMINROLE)

**Vulnerable** -- a genuine two-hop chain:

1. `ec2-app-role` (attached to the IMDSv1 EC2) holds `sts:AssumeRole` into
   `automation-role`, whose trust policy names `ec2-app-role`.
2. `automation-role` is **not** admin, but holds `iam:PassRole` + Lambda
   create/invoke, so it can pass the admin `lambda-admin-role` to a function and
   run admin code.

No single statement is "admin"; the privilege escalation only emerges from the
*composition* of the two edges -- which is the whole reason detection must reason
about reachability.

**Hardened** -- break *both* edges (defense in depth):

- **Edge 1:** remove the `sts:AssumeRole` grant from `ec2-app-role`'s identity
  policy, and tighten `automation-role`'s trust policy with an `sts:ExternalId`
  condition and a specific source ARN so it cannot be assumed laterally:

  ```hcl
  Condition = { StringEquals = { "sts:ExternalId" = var.automation_external_id } }
  ```

- **Edge 2:** scope `automation-role`'s `iam:PassRole` to a single
  least-privilege role ARN with an `iam:PassedToService` condition (see PATH 2),
  and remove `AdministratorAccess` from `lambda-admin-role`.

Breaking either edge removes the path; breaking both is the resilient fix. Run
`cloudrange detect` after the change and the `ec2-app-role` privesc finding
disappears.

---

## S3 public bucket  (CR-S3-PUBLIC + CR-S3-NOENC)

```hcl
resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}
```

Serve public content through CloudFront with OAC instead of a public bucket.

---

## EC2 IMDSv1 + secrets in user-data  (CR-EC2-IMDSV1 + CR-EC2-SECRETS)

**Hardened** -- require IMDSv2 and remove secrets from user-data:

```hcl
metadata_options {
  http_endpoint               = "enabled"
  http_tokens                 = "required" # IMDSv2 only
  http_put_response_hop_limit = 1          # block SSRF-via-proxy hops
}
```

Fetch secrets at runtime from SSM Parameter Store / Secrets Manager using the
instance role; never bake them into user-data.

---

## Over-privileged Lambda  (CR-LAMBDA-ADMIN)

Replace the admin execution role with a function-specific least-privilege role
that grants exactly the API calls the handler makes -- nothing more.

---

### Net effect

After these changes, the permission graph has **no path** from any non-admin
principal to `*:*`. That is the whole point: privilege escalation is a
*reachability* property of the graph, and least privilege removes the edges.
