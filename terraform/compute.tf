###############################################################################
# Compute -- the EC2 web server (IMDSv1 + secrets in user-data) and the
# over-privileged Lambda. Gated behind var.deploy_compute (default: false) so
# you can deploy the free IAM/S3 mess without launching billable compute. The
# IAM privesc paths are exercised regardless of this flag.
###############################################################################

# Latest Amazon Linux 2023 AMI in the chosen region.
data "aws_ami" "al2023" {
  count       = var.deploy_compute ? 1 : 0
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# --------------------------------------------------------------------------- #
# Vulnerable web server.
# --------------------------------------------------------------------------- #
resource "aws_instance" "web" {
  count                = var.deploy_compute ? 1 : 0
  ami                  = data.aws_ami.al2023[0].id
  instance_type        = var.instance_type
  iam_instance_profile = aws_iam_instance_profile.ec2_app.name

  # VULN: IMDSv1 allowed (HttpTokens=optional) -> token-less credential theft
  # via SSRF or on-host access.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  # VULN: plaintext secrets baked into user-data.
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD=SuperSecretP@ss123
    export API_TOKEN=cr_live_8f3a2b1c9d4e5f6a
    aws s3 cp s3://${aws_s3_bucket.crown_jewels.id}/prod-db-dump.sql /tmp/
  EOF

  tags = merge(var.tags, { Name = "${var.name_prefix}-web-server" })
}

# --------------------------------------------------------------------------- #
# Over-privileged Lambda (uses the admin execution role even at rest).
# --------------------------------------------------------------------------- #
data "archive_file" "report_zip" {
  count       = var.deploy_compute ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/build/report.zip"

  source {
    content  = "def handler(event, context):\n    return {'ok': True}\n"
    filename = "index.py"
  }
}

resource "aws_lambda_function" "report_generator" {
  count            = var.deploy_compute ? 1 : 0
  function_name    = "${var.name_prefix}-report-generator"
  role             = aws_iam_role.lambda_admin.arn # VULN: admin execution role
  handler          = "index.handler"
  runtime          = "python3.11"
  filename         = data.archive_file.report_zip[0].output_path
  source_code_hash = data.archive_file.report_zip[0].output_base64sha256

  environment {
    variables = {
      REPORT_BUCKET = aws_s3_bucket.public_assets.id
    }
  }

  tags = var.tags
}
