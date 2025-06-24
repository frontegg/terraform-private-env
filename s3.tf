data "aws_iam_policy_document" "cloudfront_assume_role" {
  count = local.config.settings.s3.enabled ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    effect = "Allow"
  }
}

resource "aws_iam_role" "cloudfront_access_to_s3" {
  count              = local.config.settings.s3.enabled ? 1 : 0
  assume_role_policy = data.aws_iam_policy_document.cloudfront_assume_role[0].json
}

module "policy" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = local.config.settings.s3.enabled ? 1 : 0
  create_bucket            = local.config.settings.s3.enabled
  bucket_prefix            = local.s3_policy
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  versioning = {
    enabled = true
  }
  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      filter = {
        prefix = ""
      }
      noncurrent_version_expiration = {
        days = 180
      }
    }
  ]
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = {
    serviceName = "policy-service"
  }
}

module "reporting-engine-triggered-reports" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = local.config.settings.s3.enabled ? 1 : 0
  create_bucket            = local.config.settings.s3.enabled
  bucket_prefix            = local.reporting_engine_triggered_reports
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  versioning = {
    enabled = true
  }
  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      filter = {
        prefix = ""
      }
      noncurrent_version_expiration = {
        days = 180
      }
    }
  ]
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
  tags = {
    serviceName = "triggered-reports"
  }
}

data "aws_iam_policy_document" "pricing_viewes_bucket_policy" {
  count = local.config.settings.s3.enabled ? 1 : 0
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::${local.pricing_views_bundles}-${random_string.suffix[0].result}/*",
    ]
  }
}

module "pricing-views-bundles" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = local.config.settings.s3.enabled ? 1 : 0
  create_bucket            = local.config.settings.s3.enabled
  bucket                   = "${local.pricing_views_bundles}-${random_string.suffix[0].result}"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  ignore_public_acls       = true
  block_public_acls        = false
  block_public_policy      = false
  restrict_public_buckets  = false
  attach_policy            = true
  acl                      = "public-read"
  policy                   = data.aws_iam_policy_document.pricing_viewes_bucket_policy[0].json

  versioning = {
    enabled = true
  }
  tags = {
    usedBy = "pricing-views-bundles"
  }
  cors_rule = [
    {
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      allowed_headers = ["Content-Length", "Authorization"]
      max_age_seconds = 3000
    }
  ]
  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      filter = {
        prefix = ""
      }
      noncurrent_version_expiration = {
        days = 180
      }
    }
  ]
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

data "aws_iam_policy_document" "dashboard_static_content_bucket_policy" {
  count = local.config.settings.s3.enabled ? 1 : 0
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cloudfront_access_to_s3[0].arn]
    }
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::${local.dashboard_static_content_bucket_name}-${random_string.suffix[0].result}/*",
    ]
  }
}

module "dashboard-static-content" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = local.config.settings.s3.enabled ? 1 : 0
  create_bucket            = local.config.settings.s3.enabled
  bucket                   = "${local.dashboard_static_content_bucket_name}-${random_string.suffix[0].result}"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  ignore_public_acls       = true
  block_public_acls        = false
  block_public_policy      = false
  restrict_public_buckets  = false
  attach_policy            = true
  acl                      = "public-read"
  policy                   = data.aws_iam_policy_document.dashboard_static_content_bucket_policy[0].json
  versioning = {
    enabled = true
  }
  tags = {
    usedBy = "dashboard"
  }
  cors_rule = [
    {
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      allowed_headers = ["Content-Length", "Authorization"]
      max_age_seconds = 3000
    }
  ]
  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      filter = {
        prefix = "content/"
      }
      noncurrent_version_expiration = {
        days = 180
      }
    }
  ]
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

data "aws_iam_policy_document" "tenants_assets_bucket_policy" {
  count = local.config.settings.s3.enabled ? 1 : 0
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.cloudfront_access_to_s3[0].arn]
    }
    actions = [
      "s3:GetObject",
    ]
    resources = [
      "arn:aws:s3:::${local.tenants_assets}-${random_string.suffix[0].result}/*",
    ]
  }
}

module "tenants-assets" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = local.config.settings.s3.enabled ? 1 : 0
  create_bucket            = local.config.settings.s3.enabled
  bucket                   = "${local.tenants_assets}-${random_string.suffix[0].result}"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  ignore_public_acls       = true
  block_public_acls        = false
  block_public_policy      = false
  restrict_public_buckets  = false
  attach_policy            = true
  acl                      = "public-read"
  policy                   = data.aws_iam_policy_document.tenants_assets_bucket_policy[0].json
  versioning = {
    enabled = true
  }
  tags = {
    usedBy = "tenants"
  }
  cors_rule = [
    {
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      allowed_headers = ["Content-Length", "Authorization"]
      max_age_seconds = 3000
    }
  ]
  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      filter = {
        prefix = ""
      }
      noncurrent_version_expiration = {
        days = 180
      }
    }
  ]
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "random_string" "suffix" {
  count   = local.config.settings.s3.enabled ? 1 : 0
  length  = 8
  special = false
  upper   = false
}

module "s3_debezium_connector" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0
  create_bucket            = true
  bucket                   = "frontegg-debezium-connector-${random_string.suffix[0].result}"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  ignore_public_acls       = true
  versioning = {
    enabled = true
  }
}

resource "aws_s3_object" "debezium_upload" {
  count  = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0
  bucket = module.s3_debezium_connector[0].s3_bucket_id
  key    = "uploades/debezium/debezium-connector-mysql-1.9.7.zip"
  source = "${path.module}/config/debezium-connector-mysql-1.9.7.zip"
}

module "msk-logs" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  count                    = try(local.config.settings.msk.config.enable_msk_logs, true) ? 1 : 0
  bucket                   = local.msk_bucket_name
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  versioning = {
    enabled = true
  }
  lifecycle_rule = [
    {
      id      = "log"
      enabled = true
      filter = {
        prefix = "msk-logs/"
      }
      noncurrent_version_expiration = {
        days = 180
      }
    }
  ]
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

module "opa-s3-bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.7.0"

  bucket                   = "frontegg-${local.environment}-opa-policy-${random_string.s3_bucket_suffix[0].result}"
  acl                      = "private"
  control_object_ownership = true
  object_ownership         = "ObjectWriter"
  force_destroy            = local.s3_force_destroy_buckets
  versioning = {
    enabled = true
  }

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "random_string" "s3_bucket_suffix" {
  count   = local.config.settings.s3.enabled ? 1 : 0
  length  = 6
  special = false
  upper   = false
  lower   = true
  numeric = true
}