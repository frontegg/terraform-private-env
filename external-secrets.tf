resource "helm_release" "external_secrets" {
  provider         = helm.eks
  count            = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0
  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  version          = local.config.settings.external_secrets.config.version
  create_namespace = true
  namespace        = "external-secrets"

  values = [
    templatefile("${path.module}/templates/external-secret.yaml.tpl", {
      accountid    = data.aws_caller_identity.current.account_id
      region       = local.region
      environment  = local.environment
      replicaCount = local.config.settings.external_secrets.config.replicaCount
      installCRDs  = true
      concurrent   = local.config.settings.external_secrets.config.concurrent
    })
  ]

  depends_on = [module.eks]

  lifecycle {
    ignore_changes = [
      values,
    ]
    prevent_destroy = false
  }
}

resource "aws_iam_role" "external_secrets" {
  count = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0
  name  = "external-secrets-${local.environment}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${local.eks_oidc_provider}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${local.eks_oidc_provider}:sub" : "system:serviceaccount:external-secrets:external-secrets"
            "${local.eks_oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "external_secrets" {
  count       = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0
  name        = "external-secrets-${local.environment}-policy"
  description = "Policy for External Secrets Operator to access secrets in ${local.environment} environment"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Secrets Manager permissions
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:${local.environment}/*",
          "arn:aws:secretsmanager:*:${data.aws_caller_identity.current.account_id}:secret:${local.environment}-*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      },

      # SSM Parameter Store permissions
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = [
          "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/${local.environment}/*"
        ]
      },

      # KMS permissions (if your secrets are encrypted with a custom KMS key)
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [
          "arn:aws:kms:*:${data.aws_caller_identity.current.account_id}:key/*"
        ]
        Condition = {
          StringLike = {
            "kms:ViaService" : [
              "secretsmanager.*.amazonaws.com",
              "ssm.*.amazonaws.com"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "external_secrets" {
  count      = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0
  role       = aws_iam_role.external_secrets[0].name
  policy_arn = aws_iam_policy.external_secrets[0].arn
}

resource "aws_iam_role_policy_attachment" "external_secrets_cloudwatch" {
  count      = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0
  role       = aws_iam_role.external_secrets[0].name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

resource "aws_iam_role" "external_secret" {
  count = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0

  name = "${local.environment}-external-secret"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = local.eks_oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${local.eks_oidc_provider}:sub" = "system:serviceaccount:external-secrets:external-secret"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "external_secret" {
  count = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0

  name = "${local.environment}-external-secret"
  role = aws_iam_role.external_secret[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecretVersionIds",
          "secretsmanager:ListSecrets"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:*"
        ]
      }
    ]
  })
}

resource "helm_release" "external_secrets_objects" {
  provider         = helm.eks
  count            = local.config.settings.external_secrets.config.enabled && local.kubernetes_cluster_name != null ? 1 : 0
  name             = "external-secrets-objects"
  chart            = "${path.module}/helm/external-secrets-objects"
  namespace        = "external-secrets"
  create_namespace = true
  version          = "0.1.0"

  values = [
    yamlencode({
      global = {
        region      = local.region
        environment = local.environment
      }
      externalSecrets = {
        enabled = true
        clusterSecretStore = {
          name = "external-secret-store"
          serviceAccount = {
            name      = "external-secrets"
            namespace = "external-secrets"
          }
        }
      }
    })
  ]

  depends_on = [
    helm_release.external_secrets,
    aws_iam_role.external_secrets,
    aws_iam_role_policy_attachment.external_secrets,
    module.eks
  ]

  lifecycle {
    ignore_changes = [
      values,
    ]
    prevent_destroy = false
  }
}


