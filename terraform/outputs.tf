output "account_id" {
  description = "The account the range was deployed into."
  value       = local.account_id
}

output "users" {
  description = "IAM users created (privesc starting principals + controls)."
  value = {
    admin        = aws_iam_user.admin.arn
    analyst      = aws_iam_user.analyst.arn
    ci_deployer  = aws_iam_user.ci_deployer.arn
    dev_deployer = aws_iam_user.dev_deployer.arn
    support      = aws_iam_user.support.arn
    intern       = aws_iam_user.intern.arn
  }
}

output "roles" {
  description = "IAM roles created (privesc sinks + lateral-movement pivots)."
  value = {
    lambda_admin = aws_iam_role.lambda_admin.arn
    ec2_app      = aws_iam_role.ec2_app.arn
    automation   = aws_iam_role.automation.arn
  }
}

output "buckets" {
  description = "S3 buckets (public misconfig + crown-jewel target)."
  value = {
    public_assets = aws_s3_bucket.public_assets.id
    crown_jewels  = aws_s3_bucket.crown_jewels.id
  }
}

output "crown_jewel_bucket" {
  description = "The bucket the attack chain exfiltrates after reaching admin."
  value       = aws_s3_bucket.crown_jewels.id
}

output "web_instance_id" {
  description = "Vulnerable EC2 instance id (null unless deploy_compute = true)."
  value       = var.deploy_compute ? aws_instance.web[0].id : null
}

output "privesc_paths" {
  description = "The intended privilege-escalation paths planted in this range."
  value = [
    "analyst      -> CreateAccessKey(admin)                              -> ADMIN",
    "ci-deployer  -> PassRole(lambda-admin-role)                         -> ADMIN",
    "dev-deployer -> PutUserPolicy(self)                                 -> ADMIN",
    "support      -> AttachUserPolicy(self)                              -> ADMIN",
    "ec2-app-role -> AssumeRole(automation-role) -> PassRole+Lambda      -> ADMIN  (2-hop)",
  ]
}
