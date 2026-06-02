provider "aws" {
  region = var.aws_region

  # Tag everything so the whole range is unmistakable and easy to destroy.
  default_tags {
    tags = var.tags
  }
}

provider "random" {}

provider "archive" {}
