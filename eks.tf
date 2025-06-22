module "eks" {
  count   = local.config.settings.eks.config.enabled && !try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.36.1"

  vpc_id                               = local.config.settings.vpc.enabled ? module.vpc[0].vpc_id : data.aws_vpc.existing[0].id
  subnet_ids                           = local.config.settings.vpc.enabled ? module.vpc[0].private_subnets : [for subnet in data.aws_subnet.private : subnet.id]
  control_plane_subnet_ids             = local.config.settings.vpc.enabled ? module.vpc[0].private_subnets : [for subnet in data.aws_subnet.private : subnet.id]
  cluster_name                         = local.kubernetes_cluster_name
  cluster_version                      = local.config.settings.eks.config.cluster.version
  cluster_endpoint_public_access       = local.config.settings.eks.config.cluster.endpoint_public_access
  cluster_endpoint_public_access_cidrs = local.config.settings.eks.config.cluster.endpoint_public_access_cidrs

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    eks-pod-identity-agent = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_irsa_role[0].iam_role_arn
    }
  }
  cluster_security_group_additional_rules = {
    ingress_nodes_ephemeral_ports_tcp = {
      description                = "Nodes on ephemeral ports"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "ingress"
      source_node_security_group = true
    }
  }
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    egress_all = {
      description = "Node all egress"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "egress"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  eks_managed_node_group_defaults = {
    attach_cluster_primary_security_group = true
    instance_types                        = local.config.settings.eks.config.managed_node_groups_defaults.instance_types
    ami_type                              = "BOTTLEROCKET_x86_64"
    iam_role_additional_policies = {
      additional     = aws_iam_policy.autoscaling[0].arn
      secret_manager = aws_iam_policy.secret_manager[0].arn
      load_balancing = aws_iam_policy.load_balancing[0].arn
      route53        = aws_iam_policy.route53[0].arn
      ssm            = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      s3readonly     = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
    }
    block_device_mappings = {
      xvda = {
        device_name = "/dev/xvda"
        ebs = {
          volume_size           = 100
          volume_type           = "gp3"
          iops                  = 3000
          throughput            = 150
          delete_on_termination = true
        }
      }
    }
  }
  eks_managed_node_groups = {
    general_propuse = {
      min_size       = local.config.settings.eks.config.managed_node_groups.min_size
      max_size       = local.config.settings.eks.config.managed_node_groups.max_size
      desired_size   = local.config.settings.eks.config.managed_node_groups.desired_size
      instance_types = local.config.settings.eks.config.managed_node_groups.instance_types
      capacity_type  = local.config.settings.eks.config.managed_node_groups.capacity_type
    }
    system = {
      instance_types = ["m5.large", "m5.xlarge"]
      min_size       = 0
      max_size       = 1
      desired_size   = 1
      capacity_type  = "SPOT"
      labels = {
        "karpenter.sh/controller" = "true"
      }
    }
  }
  enable_cluster_creator_admin_permissions = true
  node_security_group_tags = {
    "karpenter.sh/discovery" = local.kubernetes_cluster_name
    "service"                = "frontegg private environment"
  }
}

module "eks_auto_mode" {
  count   = local.config.settings.eks.config.enabled && try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.36.0"

  cluster_name    = local.kubernetes_cluster_name
  cluster_version = local.config.settings.eks.config.cluster.version

  vpc_id     = local.config.settings.vpc.enabled ? module.vpc[0].vpc_id : data.aws_vpc.existing[0].id
  subnet_ids = local.config.settings.vpc.enabled ? module.vpc[0].private_subnets : [for subnet in data.aws_subnet.private : subnet.id]

  cluster_endpoint_public_access           = local.config.settings.eks.config.cluster.endpoint_public_access
  enable_cluster_creator_admin_permissions = true
  node_iam_role_name                       = "${local.kubernetes_cluster_name}-role"

  cluster_compute_config = {
    enabled = true
    node_pools = [
      "general-purpose",
      "system"
    ]
  }
}

resource "aws_iam_policy" "autoscaling" {
  count  = local.config.settings.eks.config.enabled && !try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  name   = "${local.environment}-autoscaling"
  policy = data.aws_iam_policy_document.autoscaling.json
}

data "aws_iam_policy_document" "autoscaling" {
  statement {
    effect = "Allow"
    actions = [
      "acm:*",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeScalingActivities",
      "autoscaling:DescribeTags",
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "cloudfront:*",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:GetInstanceTypesFromInstanceRequirements",
      "eks:DescribeNodegroup",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "route53" {
  count  = local.config.settings.eks.config.enabled && !try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  name   = "${local.environment}-route53"
  policy = data.aws_iam_policy_document.route53.json
}

data "aws_iam_policy_document" "route53" {
  statement {
    effect = "Allow"
    actions = [
      "route53:ChangeResourceRecordSets",
      "route53:Get*",
      "route53:List*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "secret_manager" {
  count  = local.config.settings.eks.config.enabled && !try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  name   = "${local.environment}-secret_manager"
  policy = data.aws_iam_policy_document.secret_manager.json
}

data "aws_iam_policy_document" "secret_manager" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetResourcePolicy",
      "secretsmanager:GetSecretValue",
      "secretsmanager:ListSecretVersionIds"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "load_balancing" {
  count  = local.config.settings.eks.config.enabled && !try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  name   = "${local.environment}-load_balancing"
  policy = data.aws_iam_policy_document.load_balancing.json
}

data "aws_iam_policy_document" "load_balancing" {
  statement {
    effect = "Allow"
    actions = [
      "acm:Describe*",
      "acm:List*",
      "cognito-idp:Describe*",
      "ec2:CreateSecurityGroup",
      "ec2:CreateTags",
      "ec2:DeleteTags",
      "ec2:Describe*",
      "ec2:Get*",
      "ec2:List*",
      "ec2:RevokeSecurityGroupIngress",
      "elasticloadbalancing:*",
      "elasticloadbalancing:RemoveTags",
      "iam:CreateServiceLinkedRole",
      "iam:GetServerCertificate",
      "iam:ListServerCertificates",
      "shield:Create*",
      "shield:Delete*",
      "shield:Describe*",
      "shield:GetSubscriptionState",
      "waf-regional:AssociateWebACL",
      "waf-regional:DisassociateWebACL",
      "waf-regional:Get*",
      "wafv2:AssociateWebACL",
      "wafv2:DisassociateWebACL"
    ]
    resources = ["*"]
  }
}

module "ebs_csi_irsa_role" {
  count   = local.config.settings.eks.config.enabled && !try(local.config.settings.eks.config.auto_mode.enabled, false) ? 1 : 0
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.20"

  role_name             = "${module.eks[0].cluster_name}-ebs-csi-controller"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks[0].oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

# Create the gp3 StorageClass
resource "kubernetes_storage_class" "gp3" {
  provider = kubernetes.eks
  count    = local.config.settings.eks.config.enabled ? 1 : 0

  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "true"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Delete"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  lifecycle {
    ignore_changes = all
  }
}

resource "kubernetes_storage_class" "gp3-high-performance" {
  provider = kubernetes.eks
  count    = local.config.settings.eks.config.enabled ? 1 : 0

  metadata {
    name = "gp3-high-performance"
  }

  storage_provisioner = "ebs.csi.aws.com"
  reclaim_policy      = "Delete"
  parameters = {
    type       = "gp3"
    iopsPerGB  = "3000"
    throughput = "150"
  }
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  lifecycle {
    ignore_changes = all
  }
}


