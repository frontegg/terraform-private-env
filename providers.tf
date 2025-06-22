terraform {
  backend "s3" {}
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.17.0" # TODO: Update to v3 when stable
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
  }
  required_version = "~> 1.0"
}

provider "aws" {
  region = local.region
  default_tags {
    tags = {
      Environment = local.environment
      Project     = local.project
      ManagedBy   = "terraform"
    }
  }
}

provider "kubernetes" {
  alias = "eks"
  # Only configure if EKS is enabled or external cluster exists
  host                   = try(local.kubernetes_cluster_endpoint, null)
  cluster_ca_certificate = try(base64decode(local.kubernetes_cluster_ca_data), null)

  dynamic "exec" {
    for_each = try(local.kubernetes_cluster_name, null) != null ? [1] : []
    content {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", local.kubernetes_cluster_name, "--region", local.region]
    }
  }
}

provider "helm" {
  alias = "eks"
  kubernetes {
    host                   = try(local.kubernetes_cluster_endpoint, null)
    cluster_ca_certificate = try(base64decode(local.kubernetes_cluster_ca_data), null)

    dynamic "exec" {
      for_each = try(local.kubernetes_cluster_name, null) != null ? [1] : []
      content {
        api_version = "client.authentication.k8s.io/v1beta1"
        command     = "aws"
        args        = ["eks", "get-token", "--cluster-name", local.kubernetes_cluster_name, "--region", local.region]
      }
    }
  }
}
