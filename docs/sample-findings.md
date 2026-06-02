# CLOUDRANGE Detection Report

**Account:** `123456789012`
**Findings:** 22
**Severity breakdown:** [CRITICAL]: 11  [HIGH]: 9  [MEDIUM]: 2

> Read-only audit. Each finding links to the exact privilege-
> escalation path that consumes the misconfiguration.

## 1. [CRITICAL] - CR-IAM-CREATEKEY

- **Resource:** `arn:aws:iam::123456789012:user/analyst`
- **Finding:** Principal 'analyst' has iam:CreateAccessKey enabling technique 'CreateAccessKey': Call iam:CreateAccessKey for user 'admin', obtaining valid long-lived credentials for that principal and inheriting all of its permissions.
- **Privesc path:** `analyst  ->  ADMIN`
- **Technique:** CreateAccessKey
- **Remediation:** Scope iam:CreateAccessKey to the principal's own user ARN, or remove it. Never allow it on Resource '*'.

## 2. [CRITICAL] - CR-IAM-PASSROLE

- **Resource:** `arn:aws:iam::123456789012:role/automation-role`
- **Finding:** Principal 'automation-role' has iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction enabling technique 'PassRole+Lambda': Create a Lambda function with execution role 'lambda-admin-role' (PassRole), then invoke it to run arbitrary code with that role's permissions.
- **Privesc path:** `automation-role  ->  ADMIN`
- **Technique:** PassRole+Lambda
- **Remediation:** Constrain iam:PassRole to a specific, least-privilege role ARN and add an iam:PassedToService condition; remove admin from the passable role.

## 3. [CRITICAL] - CR-IAM-PASSROLE

- **Resource:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Finding:** Principal 'ci-deployer' has iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction enabling technique 'PassRole+Lambda': Create a Lambda function with execution role 'lambda-admin-role' (PassRole), then invoke it to run arbitrary code with that role's permissions.
- **Privesc path:** `ci-deployer  ->  ADMIN`
- **Technique:** PassRole+Lambda
- **Remediation:** Constrain iam:PassRole to a specific, least-privilege role ARN and add an iam:PassedToService condition; remove admin from the passable role.

## 4. [CRITICAL] - CR-IAM-PRIVESC

- **Resource:** `arn:aws:iam::123456789012:user/analyst`
- **Finding:** Principal 'analyst' can escalate to administrator in 1 step(s) via CreateAccessKey.
- **Privesc path:** `analyst  ->  ADMIN`
- **Technique:** CreateAccessKey
- **Remediation:** Remove the escalation permission(s) from this principal and apply least privilege. See the linked privesc path.

## 5. [CRITICAL] - CR-IAM-PRIVESC

- **Resource:** `arn:aws:iam::123456789012:role/automation-role`
- **Finding:** Principal 'automation-role' can escalate to administrator in 1 step(s) via PassRole+Lambda.
- **Privesc path:** `automation-role  ->  ADMIN`
- **Technique:** PassRole+Lambda
- **Remediation:** Remove the escalation permission(s) from this principal and apply least privilege. See the linked privesc path.

## 6. [CRITICAL] - CR-IAM-PRIVESC

- **Resource:** `arn:aws:iam::123456789012:user/ci-deployer`
- **Finding:** Principal 'ci-deployer' can escalate to administrator in 1 step(s) via PassRole+Lambda.
- **Privesc path:** `ci-deployer  ->  ADMIN`
- **Technique:** PassRole+Lambda
- **Remediation:** Remove the escalation permission(s) from this principal and apply least privilege. See the linked privesc path.

## 7. [CRITICAL] - CR-IAM-PRIVESC

- **Resource:** `arn:aws:iam::123456789012:user/dev-deployer`
- **Finding:** Principal 'dev-deployer' can escalate to administrator in 1 step(s) via PutUserPolicy.
- **Privesc path:** `dev-deployer  ->  ADMIN`
- **Technique:** PutUserPolicy
- **Remediation:** Remove the escalation permission(s) from this principal and apply least privilege. See the linked privesc path.

## 8. [CRITICAL] - CR-IAM-PRIVESC

- **Resource:** `arn:aws:iam::123456789012:role/ec2-app-role`
- **Finding:** Principal 'ec2-app-role' can escalate to administrator in 2 step(s) via AssumeRole -> PassRole+Lambda.
- **Privesc path:** `ec2-app-role  ->  automation-role  ->  ADMIN`
- **Technique:** AssumeRole -> PassRole+Lambda
- **Remediation:** Remove the escalation permission(s) from this principal and apply least privilege. See the linked privesc path.

## 9. [CRITICAL] - CR-IAM-PRIVESC

- **Resource:** `arn:aws:iam::123456789012:user/support`
- **Finding:** Principal 'support' can escalate to administrator in 1 step(s) via AttachUserPolicy.
- **Privesc path:** `support  ->  ADMIN`
- **Technique:** AttachUserPolicy
- **Remediation:** Remove the escalation permission(s) from this principal and apply least privilege. See the linked privesc path.

## 10. [CRITICAL] - CR-IAM-SELFPOLICY

- **Resource:** `arn:aws:iam::123456789012:user/dev-deployer`
- **Finding:** Principal 'dev-deployer' has iam:PutUserPolicy enabling technique 'PutUserPolicy': Call iam:PutUserPolicy on user 'self' with an inline document granting {"Action":"*","Resource":"*"}.
- **Privesc path:** `dev-deployer  ->  ADMIN`
- **Technique:** PutUserPolicy
- **Remediation:** Remove iam:PutUserPolicy / iam:AttachUserPolicy from the principal; route policy changes through a reviewed pipeline.

## 11. [CRITICAL] - CR-IAM-SELFPOLICY

- **Resource:** `arn:aws:iam::123456789012:user/support`
- **Finding:** Principal 'support' has iam:AttachUserPolicy enabling technique 'AttachUserPolicy': Call iam:AttachUserPolicy on 'self' attaching arn:aws:iam::aws:policy/AdministratorAccess.
- **Privesc path:** `support  ->  ADMIN`
- **Technique:** AttachUserPolicy
- **Remediation:** Remove iam:PutUserPolicy / iam:AttachUserPolicy from the principal; route policy changes through a reviewed pipeline.

## 12. [HIGH] - CR-EC2-IMDSV1

- **Resource:** `arn:aws:ec2:::instance/i-0web0server0range`
- **Finding:** Instance 'i-0web0server0range' allows token-less IMDSv1; an SSRF or on-host attacker can steal the 'ec2-app-role' role credentials.
- **Privesc path:** `ec2-app-role  ->  automation-role  ->  ADMIN`
- **Technique:** AssumeRole
- **Remediation:** Require IMDSv2 (HttpTokens=required) and set HttpPutResponseHopLimit=1.

## 13. [HIGH] - CR-EC2-SECRETS

- **Resource:** `arn:aws:ec2:::instance/i-0web0server0range`
- **Finding:** Instance 'i-0web0server0range' has plaintext secrets in user-data.
- **Remediation:** Remove secrets from user-data; use SSM Parameter Store / Secrets Manager and an instance role.

## 14. [HIGH] - CR-IAM-ADMINROLE

- **Resource:** `arn:aws:iam::123456789012:role/lambda-admin-role`
- **Finding:** Role 'lambda-admin-role' holds AdministratorAccess (service/instance role with full admin blast radius).
- **Privesc path:** `automation-role  ->  ADMIN`
- **Technique:** PassRole+Lambda
- **Remediation:** Replace AdministratorAccess with a least-privilege policy scoped to exactly what the workload needs.

## 15. [HIGH] - CR-IAM-CREATEKEY

- **Resource:** `arn:aws:iam::123456789012:user/analyst`
- **Finding:** Principal 'analyst' has iam:CreateAccessKey enabling technique 'CreateAccessKey': Call iam:CreateAccessKey for user 'ci-deployer', obtaining valid long-lived credentials for that principal and inheriting all of its permissions.
- **Privesc path:** `analyst  ->  ADMIN`
- **Technique:** CreateAccessKey
- **Remediation:** Scope iam:CreateAccessKey to the principal's own user ARN, or remove it. Never allow it on Resource '*'.

## 16. [HIGH] - CR-IAM-CREATEKEY

- **Resource:** `arn:aws:iam::123456789012:user/analyst`
- **Finding:** Principal 'analyst' has iam:CreateAccessKey enabling technique 'CreateAccessKey': Call iam:CreateAccessKey for user 'dev-deployer', obtaining valid long-lived credentials for that principal and inheriting all of its permissions.
- **Privesc path:** `analyst  ->  ADMIN`
- **Technique:** CreateAccessKey
- **Remediation:** Scope iam:CreateAccessKey to the principal's own user ARN, or remove it. Never allow it on Resource '*'.

## 17. [HIGH] - CR-IAM-CREATEKEY

- **Resource:** `arn:aws:iam::123456789012:user/analyst`
- **Finding:** Principal 'analyst' has iam:CreateAccessKey enabling technique 'CreateAccessKey': Call iam:CreateAccessKey for user 'support', obtaining valid long-lived credentials for that principal and inheriting all of its permissions.
- **Privesc path:** `analyst  ->  ADMIN`
- **Technique:** CreateAccessKey
- **Remediation:** Scope iam:CreateAccessKey to the principal's own user ARN, or remove it. Never allow it on Resource '*'.

## 18. [HIGH] - CR-IAM-CREATEKEY

- **Resource:** `arn:aws:iam::123456789012:user/analyst`
- **Finding:** Principal 'analyst' has iam:CreateAccessKey enabling technique 'CreateAccessKey': Call iam:CreateAccessKey for user 'intern', obtaining valid long-lived credentials for that principal and inheriting all of its permissions.
- **Privesc path:** `analyst  ->  ADMIN`
- **Technique:** CreateAccessKey
- **Remediation:** Scope iam:CreateAccessKey to the principal's own user ARN, or remove it. Never allow it on Resource '*'.

## 19. [HIGH] - CR-LAMBDA-ADMIN

- **Resource:** `arn:aws:lambda:::function/report-generator`
- **Finding:** Lambda 'report-generator' uses admin execution role 'lambda-admin-role'.
- **Remediation:** Scope the execution role to least privilege for this function only.

## 20. [HIGH] - CR-S3-PUBLIC

- **Resource:** `arn:aws:s3:::cloudrange-public-assets`
- **Finding:** S3 bucket 'cloudrange-public-assets' is publicly accessible. Bucket ACL grants READ to AllUsers (public-read) and block-public-access is disabled.
- **Remediation:** Enable S3 Block Public Access (account + bucket), remove public ACL grants, and use a restrictive bucket policy.

## 21. [MEDIUM] - CR-IAM-TRUST

- **Resource:** `arn:aws:iam::123456789012:role/automation-role`
- **Finding:** Role 'automation-role' trust policy permits 'arn:aws:iam::123456789012:role/ec2-app-role' to assume it (lateral-movement vector).
- **Privesc path:** `ec2-app-role  ->  automation-role  ->  ADMIN`
- **Technique:** AssumeRole
- **Remediation:** Restrict the trust policy to the minimal set of principals and add ExternalId / source conditions.

## 22. [MEDIUM] - CR-S3-NOENC

- **Resource:** `arn:aws:s3:::cloudrange-public-assets`
- **Finding:** S3 bucket 'cloudrange-public-assets' has no default encryption.
- **Remediation:** Enable default SSE-KMS or SSE-S3 encryption.
