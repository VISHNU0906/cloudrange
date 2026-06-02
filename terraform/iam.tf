###############################################################################
# IAM -- the deliberately-vulnerable mess.
#
# These principals and over-permissions mirror fixtures/account.json exactly so
# the offline (--mock) attack chain and the deployed (--real) range tell the
# SAME story. Every block here is a planted, documented privesc primitive.
#
# !!! DELIBERATELY INSECURE. Deploy ONLY in a throwaway account you own. !!!
###############################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# --------------------------------------------------------------------------- #
# admin -- the break-glass admin user. The privesc SINK every path reaches.
# --------------------------------------------------------------------------- #
resource "aws_iam_user" "admin" {
  name = "${var.name_prefix}-admin"
  tags = var.tags
}

resource "aws_iam_user_policy_attachment" "admin_admin" {
  user       = aws_iam_user.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --------------------------------------------------------------------------- #
# PATH 1 -- analyst : iam:CreateAccessKey on ANY user -> mint admin's keys.
# --------------------------------------------------------------------------- #
resource "aws_iam_user" "analyst" {
  name = "${var.name_prefix}-analyst"
  tags = var.tags
}

resource "aws_iam_user_policy_attachment" "analyst_readonly" {
  user       = aws_iam_user.analyst.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user_policy" "analyst_extra" {
  name = "analyst-extra"
  user = aws_iam_user.analyst.name

  # VULN: CreateAccessKey on Resource "*" -> can create keys for admin.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "OverpermissiveKeyMgmt"
        Effect = "Allow"
        Action = [
          "iam:CreateAccessKey",
          "iam:ListAccessKeys",
          "iam:GetUser",
          "iam:ListUsers"
        ]
        Resource = "*"
      }
    ]
  })
}

# --------------------------------------------------------------------------- #
# PATH 2 -- ci-deployer : iam:PassRole + lambda create/invoke -> run as admin role.
# --------------------------------------------------------------------------- #
resource "aws_iam_user" "ci_deployer" {
  name = "${var.name_prefix}-ci-deployer"
  tags = var.tags
}

resource "aws_iam_user_policy" "ci_deploy" {
  name = "ci-deploy"
  user = aws_iam_user.ci_deployer.name

  # VULN: PassRole on "*" + lambda CreateFunction/InvokeFunction.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaDeploy"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
          "lambda:UpdateFunctionCode",
          "lambda:GetFunction",
          "lambda:ListFunctions",
          "iam:PassRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# --------------------------------------------------------------------------- #
# PATH 3 -- dev-deployer : iam:PutUserPolicy on self -> inline admin policy.
# --------------------------------------------------------------------------- #
resource "aws_iam_user" "dev_deployer" {
  name = "${var.name_prefix}-dev-deployer"
  tags = var.tags
}

resource "aws_iam_user_policy" "dev_self" {
  name = "dev-self"
  user = aws_iam_user.dev_deployer.name

  # VULN: PutUserPolicy scoped to self -> write a "*:*" inline policy on self.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SelfPolicyWrite"
        Effect   = "Allow"
        Action   = ["iam:PutUserPolicy", "iam:GetUser"]
        Resource = "arn:aws:iam::${local.account_id}:user/${var.name_prefix}-dev-deployer"
      }
    ]
  })
}

# --------------------------------------------------------------------------- #
# PATH 4 -- support : iam:AttachUserPolicy on "*" -> attach AdministratorAccess.
# --------------------------------------------------------------------------- #
resource "aws_iam_user" "support" {
  name = "${var.name_prefix}-support"
  tags = var.tags
}

resource "aws_iam_user_policy_attachment" "support_readonly" {
  user       = aws_iam_user.support.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_user_policy" "support_attach" {
  name = "support-attach"
  user = aws_iam_user.support.name

  # VULN: AttachUserPolicy on "*" -> attach AdministratorAccess to self.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AttachAnything"
        Effect   = "Allow"
        Action   = ["iam:AttachUserPolicy", "iam:ListAttachedUserPolicies"]
        Resource = "*"
      }
    ]
  })
}

# --------------------------------------------------------------------------- #
# intern : genuinely low-privilege control user (NO privesc path).
# --------------------------------------------------------------------------- #
resource "aws_iam_user" "intern" {
  name = "${var.name_prefix}-intern"
  tags = var.tags
}

resource "aws_iam_user_policy" "intern_ro" {
  name = "intern-ro"
  user = aws_iam_user.intern.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "JustS3List"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetObject"]
        Resource = "${aws_s3_bucket.public_assets.arn}/*"
      }
    ]
  })
}

###############################################################################
# Roles
###############################################################################

# --------------------------------------------------------------------------- #
# PATH 2 SINK -- lambda-admin-role : admin execution role, trusts Lambda.
# --------------------------------------------------------------------------- #
resource "aws_iam_role" "lambda_admin" {
  name = "${var.name_prefix}-lambda-admin-role"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin_admin" {
  role       = aws_iam_role.lambda_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# --------------------------------------------------------------------------- #
# ec2-app-role : attached to the web EC2 (reachable via IMDSv1). Reads the
# crown jewels and can assume the (non-admin) automation-role (lateral movement).
# --------------------------------------------------------------------------- #
resource "aws_iam_role" "ec2_app" {
  name = "${var.name_prefix}-ec2-app-role"
  tags = var.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_app" {
  name = "ec2-app"
  role = aws_iam_role.ec2_app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadCrownJewels"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.crown_jewels.arn,
          "${aws_s3_bucket.crown_jewels.arn}/*"
        ]
      },
      {
        # VULN: can assume the (non-admin) automation-role -> lateral movement,
        # the first hop of a genuine 2-hop escalation chain.
        Sid      = "AssumeAutomation"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = aws_iam_role.automation.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_app" {
  name = "${var.name_prefix}-ec2-app-profile"
  role = aws_iam_role.ec2_app.name
}

# --------------------------------------------------------------------------- #
# PATH 5 INTERMEDIATE -- automation-role : NOT admin, but can iam:PassRole +
# Lambda the admin lambda-admin-role. Reachability:
#   ec2-app-role --AssumeRole--> automation-role --PassRole+Lambda--> ADMIN
# Two hops through a non-admin pivot -- this is why detection must reason about
# graph reachability, not single statements.
# --------------------------------------------------------------------------- #
resource "aws_iam_role" "automation" {
  name = "${var.name_prefix}-automation-role"
  tags = var.tags

  # VULN: trusts the EC2 app role directly -> assume-role privesc chain.
  # The ARN is constructed (not a direct reference) to avoid a dependency cycle
  # with aws_iam_role_policy.ec2_app, which references this role's ARN.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:role/${var.name_prefix}-ec2-app-role" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "automation" {
  name = "automation-lambda"
  role = aws_iam_role.automation.id

  # VULN: PassRole on "*" + Lambda create/invoke -> escalate to the admin
  # lambda execution role. The role itself is NOT admin (no admin policy).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DeployViaLambda"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction",
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "iam:PassRole"
        ]
        Resource = "*"
      }
    ]
  })
}
