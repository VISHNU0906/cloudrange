variable "aws_region" {
  description = "AWS region to deploy the (throwaway) CLOUDRANGE environment into."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for all resource names so the range is easy to find and destroy."
  type        = string
  default     = "cloudrange"
}

variable "deploy_compute" {
  description = <<-EOT
    If true, deploy the EC2 instance and Lambda function (incurs minor cost).
    Set to false to deploy only the IAM/S3 mess (effectively free). The attack
    chain's IAM privesc paths work with either setting.
  EOT
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "EC2 instance type for the vulnerable web server (free-tier eligible)."
  type        = string
  default     = "t3.micro"
}

variable "tags" {
  description = "Tags applied to all resources. The 'cloudrange' tag makes teardown unambiguous."
  type        = map(string)
  default = {
    project    = "cloudrange"
    range      = "vulnerable"
    managed_by = "terraform"
    warning    = "deliberately-insecure-do-not-use-in-prod"
  }
}
