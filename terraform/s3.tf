###############################################################################
# S3 -- a public bucket (misconfig) and the crown-jewel data bucket.
###############################################################################

resource "random_id" "suffix" {
  byte_length = 4
}

# --------------------------------------------------------------------------- #
# public-assets : DELIBERATELY PUBLIC (Block Public Access disabled + public ACL).
# --------------------------------------------------------------------------- #
resource "aws_s3_bucket" "public_assets" {
  bucket        = "${var.name_prefix}-public-assets-${random_id.suffix.hex}"
  force_destroy = true # so 'terraform destroy' removes it even with objects
  tags          = var.tags
}

# VULN: Block Public Access fully DISABLED.
resource "aws_s3_bucket_public_access_block" "public_assets" {
  bucket                  = aws_s3_bucket.public_assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "public_assets" {
  bucket = aws_s3_bucket.public_assets.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# VULN: public-read ACL grants the world READ.
resource "aws_s3_bucket_acl" "public_assets" {
  depends_on = [
    aws_s3_bucket_ownership_controls.public_assets,
    aws_s3_bucket_public_access_block.public_assets,
  ]
  bucket = aws_s3_bucket.public_assets.id
  acl    = "public-read"
}

# VULN: no default encryption on this bucket (note: omitted intentionally).

# --------------------------------------------------------------------------- #
# crown-jewels : the sensitive data the attack chain exfiltrates. Private, but
# reachable once a principal escalates to admin (or via the EC2 role).
# --------------------------------------------------------------------------- #
resource "aws_s3_bucket" "crown_jewels" {
  bucket        = "${var.name_prefix}-crown-jewels-${random_id.suffix.hex}"
  force_destroy = true
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "crown_jewels" {
  bucket                  = aws_s3_bucket.crown_jewels.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "crown_jewels" {
  bucket = aws_s3_bucket.crown_jewels.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Seed the "crown-jewel" objects so the exfil step has something to read.
# (Synthetic, non-sensitive placeholder content.)
resource "aws_s3_object" "crown_pii" {
  bucket  = aws_s3_bucket.crown_jewels.id
  key     = "customer-pii.csv"
  content = "id,name,email\n1,SYNTHETIC,demo@example.invalid\n"
  tags    = var.tags
}

resource "aws_s3_object" "crown_dump" {
  bucket  = aws_s3_bucket.crown_jewels.id
  key     = "prod-db-dump.sql"
  content = "-- SYNTHETIC placeholder dump for the CLOUDRANGE exercise --\n"
  tags    = var.tags
}

resource "aws_s3_object" "crown_key" {
  bucket  = aws_s3_bucket.crown_jewels.id
  key     = "secrets/master.key"
  content = "SYNTHETIC-PLACEHOLDER-KEY-DO-NOT-USE\n"
  tags    = var.tags
}
