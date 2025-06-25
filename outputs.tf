output "eks_output" {
  description = "EKS Cluster Output"
  value       = local.config.settings.eks.config.enabled && length(module.eks) > 0 ? module.eks[0] : null
}

output "eks_auto_mode_output" {
  description = "EKS Auto Mode Cluster Output"
  value       = try(local.config.settings.eks.config.auto_mode.enabled, false) && length(module.eks_auto_mode) > 0 ? module.eks_auto_mode[0] : null
}

output "msk_output" {
  description = "MSK Output"
  value       = local.config.settings.msk.config.enabled && length(module.msk_kafka_cluster) > 0 ? module.msk_kafka_cluster[0] : null
}

output "mysql_output" {
  description = "MySQL Output"
  value       = local.config.settings.mysql.config.enabled && length(module.rds_mysql) > 0 ? module.rds_mysql[0] : null
  sensitive   = true
}

output "redis_output" {
  description = "Redis Output"
  value       = local.config.settings.redis.config.enabled && length(module.redis) > 0 ? module.redis[0] : null
  sensitive   = true
}

output "vpc_output" {
  description = "VPC Output"
  value       = local.config.settings.vpc.enabled && length(module.vpc) > 0 ? module.vpc[0] : null
}

output "s3_buckets" {
  description = "Map of all S3 bucket IDs created by this deployment."
  value = {
    policy_bucket_id                      = local.config.settings.s3.enabled && length(module.policy) > 0 ? module.policy[0].s3_bucket_id : null
    reporting_engine_triggered_reports_id = local.config.settings.s3.enabled && length(module.reporting-engine-triggered-reports) > 0 ? module.reporting-engine-triggered-reports[0].s3_bucket_id : null
    pricing_views_bundles_id              = local.config.settings.s3.enabled && length(module.pricing-views-bundles) > 0 ? module.pricing-views-bundles[0].s3_bucket_id : null
    dashboard_static_content_id           = local.config.settings.s3.enabled && length(module.dashboard-static-content) > 0 ? module.dashboard-static-content[0].s3_bucket_id : null
    tenants_assets_id                     = local.config.settings.s3.enabled && length(module.tenants-assets) > 0 ? module.tenants-assets[0].s3_bucket_id : null
    s3_debezium_connector_id              = local.config.settings.msk.config.enabled && local.config.settings.msk.connector.debezium.enabled && length(module.s3_debezium_connector) > 0 ? module.s3_debezium_connector[0].s3_bucket_id : null
    msk_logs_id                           = try(module.msk-logs[0].s3_bucket_id, null)
  }
}

output "opa_s3_bucket_name" {
  description = "The name of the OPA S3 bucket."
  value       = length(module.opa-s3-bucket) > 0 ? module.opa-s3-bucket.s3_bucket_id : null
}

output "eks_cluster_security_group_id" {
  description = "The security group ID for the EKS cluster (control plane). Use for NGINX AWS LB."
  value       = local.config.settings.eks.config.enabled && length(module.eks) > 0 ? module.eks[0].cluster_security_group_id : null
}
