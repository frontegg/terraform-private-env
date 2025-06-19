module "redis" {
  source  = "umotif-public/elasticache-redis/aws"
  version = "~> 3.0.0"

  count                      = local.config.settings.redis.config.enabled ? 1 : 0
  name_prefix                = "${local.environment}-${replace(local.config.settings.redis.config.engine_version, ".", "-")}"
  num_cache_clusters         = try(local.config.settings.redis.config.num_cache_clusters, 1)
  node_type                  = try(local.config.settings.redis.config.node_type, "cache.t3.micro")
  family                     = try(local.config.settings.redis.config.family, "redis7")
  engine_version             = try(local.config.settings.redis.config.engine_version, "7.0")
  port                       = try(tonumber(local.config.settings.redis.config.port), 6379)
  apply_immediately          = true
  ingress_cidr_blocks        = local.config.settings.vpc.enabled ? module.vpc[0].private_subnets_cidr_blocks : [for subnet in data.aws_subnet.private : subnet.cidr_block]
  transit_encryption_enabled = local.redis_transit_encryption_enabled
  auth_token                 = local.redis_auth_token
  subnet_ids                 = local.config.settings.vpc.enabled ? module.vpc[0].intra_subnets : [for subnet in data.aws_subnet.intra : subnet.id]
  vpc_id                     = local.config.settings.vpc.enabled ? module.vpc[0].vpc_id : data.aws_vpc.existing[0].id
}
