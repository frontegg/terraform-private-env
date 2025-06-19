module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.21.0"

  count = local.config.settings.vpc.enabled ? 1 : 0
  name  = "vpc-${local.environment}-${random_string.vpc_random_letters[0].result}"
  cidr  = local.config.settings.vpc.cidr
  vpc_tags = {
    "kubernetes.io/cluster/${local.kubernetes_cluster_name}" : "shared"
  }
  public_subnets = local.public_subnets
  public_subnet_tags = {
    "k8s.io/cluster-autoscaler/${local.kubernetes_cluster_name}" : "1"
    "kubernetes.io/cluster/${local.kubernetes_cluster_name}" : "shared"
    "kubernetes.io/role/elb" : "1"
    "subnet-type" : "public"
  }
  private_subnets = local.private_subnets
  private_subnet_tags = {
    "k8s.io/cluster-autoscaler/enabled" : "true"
    "kubernetes.io/role/internal-elb" : "1"
    "subnet-type" : "private"
  }
  intra_subnets = local.intra_subnets
  intra_subnet_tags = {
    "subnet-type" : "local"
  }
  enable_dns_hostnames = true
  enable_dns_support   = true
  enable_nat_gateway   = true
  single_nat_gateway   = true
  azs                  = local.azs
}

# Data source to get VPC information when using existing VPC
data "aws_vpc" "existing" {
  count = local.config.settings.vpc.enabled ? 0 : 1
  id    = local.config.settings.vpc.enabled ? null : local.config.settings.vpc.vpc_id
}

# Data source to get subnet information when using existing subnets
data "aws_subnet" "private" {
  count = local.config.settings.vpc.enabled ? 0 : length(local.private_subnets)
  id    = local.private_subnets[count.index]
}

data "aws_subnet" "intra" {
  count = local.config.settings.vpc.enabled ? 0 : length(local.intra_subnets)
  id    = local.intra_subnets[count.index]
}
