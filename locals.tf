locals {
  # Load environment variables from config.yaml
  config = yamldecode(file("config/config.yaml"))

  environment = lower(local.config.global.environment)
  customer    = lower(local.config.global.customer)
  region      = lower(local.config.global.region)
  project     = lower(local.config.global.project)

  ############## VPC ###############
  # VPC ID: from module if created, from config if imported
  vpc_id             = local.config.settings.vpc.enabled ? module.vpc[0].vpc_id : ""
  azs                = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnet_ids = local.config.settings.vpc.enabled ? slice(data.aws_subnets.private-subnets.ids, 0, min(3, length(data.aws_subnets.private-subnets.ids))) : local.config.settings.vpc.subnets.private
  intra_subnets      = local.config.settings.vpc.enabled ? [for k, v in local.azs : cidrsubnet(local.config.settings.vpc.cidr, 4, k + 12)] : local.config.settings.vpc.subnets.intra
  private_subnets    = local.config.settings.vpc.enabled ? [for k, v in local.azs : cidrsubnet(local.config.settings.vpc.cidr, 3, k + 3)] : local.config.settings.vpc.subnets.private
  public_subnets     = local.config.settings.vpc.enabled ? [for k, v in local.azs : cidrsubnet(local.config.settings.vpc.cidr, 3, k)] : []

  ############## EKS ###############
  # EKS Base Cluster Name
  eks_base_cluster_name = local.config.settings.eks.config.enabled ? lower("${local.customer}-${local.environment}-eks") : local.config.settings.eks.config.cluster.name
  # Kubernetes provider configuration based on which cluster is deployed
  kubernetes_cluster_endpoint = local.config.settings.eks.config.enabled ? (
    try(local.config.settings.eks.config.auto_mode.enabled, false) ? try(module.eks_auto_mode[0].cluster_endpoint, null) : try(module.eks[0].cluster_endpoint, null)
  ) : try(data.aws_eks_cluster.external[0].endpoint, null)
  kubernetes_cluster_ca_data = local.config.settings.eks.config.enabled ? (
    try(local.config.settings.eks.config.auto_mode.enabled, false) ? try(module.eks_auto_mode[0].cluster_certificate_authority_data, null) : try(module.eks[0].cluster_certificate_authority_data, null)
  ) : try(data.aws_eks_cluster.external[0].certificate_authority[0].data, null)
  kubernetes_cluster_name = local.config.settings.eks.config.enabled ? (
    try(local.config.settings.eks.config.auto_mode.enabled, false) ? "${local.eks_base_cluster_name}-auto-mode" : local.eks_base_cluster_name
  ) : try(local.config.settings.eks.config.cluster.name, null)

  eks_oidc_issuer_url = local.config.settings.eks.config.enabled ? (
    try(local.config.settings.eks.config.auto_mode.enabled, false) ?
    try(module.eks_auto_mode[0].cluster_oidc_issuer_url, null) :
    try(module.eks[0].cluster_oidc_issuer_url, null)
    ) : (
    local.kubernetes_cluster_name != null ?
    try(data.aws_eks_cluster.external[0].identity[0].oidc[0].issuer, null) :
    null
  )

  eks_oidc_provider_arn = local.config.settings.eks.config.enabled ? (
    try(local.config.settings.eks.config.auto_mode.enabled, false) ?
    try(module.eks_auto_mode[0].oidc_provider_arn, null) :
    try(module.eks[0].oidc_provider_arn, null)
    ) : (
    local.kubernetes_cluster_name != null ?
    try("arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${replace(data.aws_eks_cluster.external[0].identity[0].oidc[0].issuer, "https://", "")}", null) :
    null
  )

  eks_oidc_provider = local.eks_oidc_issuer_url != null ? replace(local.eks_oidc_issuer_url, "https://", "") : null

  ############## MySQL ###############
  mysql_endpoint = local.config.settings.mysql.config.enabled ? split(":", module.rds_mysql[0].db_instance_endpoint)[0] : local.config.settings.mysql.config.endpoint
  mysql_username = local.config.settings.mysql.config.enabled ? "rdsmaster_${random_string.mysql_random_letters[0].result}" : local.config.settings.mysql.config.username
  mysql_password = local.config.settings.mysql.config.enabled ? random_password.mysql_password[0].result : local.config.settings.mysql.config.password

  ############## REDIS ###############
  redis_config = local.config.settings.redis.config.enabled ? {
    enabled = true
    } : {
    enabled  = false
    endpoint = local.config.settings.redis.config.endpoint
    username = local.config.settings.redis.config.username
    password = local.config.settings.redis.config.password
    port     = local.config.settings.redis.config.port
    tls      = local.config.settings.redis.config.tls
  }

  redis_secrets = local.config.settings.redis.config.enabled ? {
    host     = "${module.redis[0].elasticache_replication_group_primary_endpoint_address}:${module.redis[0].elasticache_port}"
    password = ""
    username = ""
    port     = module.redis[0].elasticache_port
    tls      = local.config.settings.redis.config.tls
    } : {
    host     = local.config.settings.redis.config.endpoint
    password = local.config.settings.redis.config.password
    username = local.config.settings.redis.config.username
    port     = local.config.settings.redis.config.port
    tls      = local.config.settings.redis.config.tls
  }

  # Set redis_transit_encryption_enabled from config, default to false if not set
  redis_transit_encryption_enabled = try(local.config.settings.redis.config.transit_encryption_enabled, false)

  # Set redis_auth_token based on redis_transit_encryption_enabled
  redis_auth_token = local.redis_transit_encryption_enabled ? random_password.redis_password[0].result : ""

  ############## MONGO ###############
  # mongo_username          = coalesce(local.config.settings.mongo.config.username, "aaa")
  # mongo_password          = coalesce(local.config.settings.mongo.config.password, "aaa")
  # mongo_endpoint          = coalesce(local.config.settings.mongo.config.endpoint, "aaa")
  # mongo_connection_string = "mongodb+srv://${local.mongo_username}:${local.mongo_password}@${local.mongo_endpoint}"
  # mongo_connection_string = "mongodb+srv://mongo-mongodb"
  mongo_connection_string = local.config.settings.mongo.config.endpoint

  ############## MSK ###############
  msk_allow_unauthenticated = try(local.config.settings.msk.config.authentication.unauthenticated, false) # Default to false if not set
  msk_sasl_iam_enabled      = try(local.config.settings.msk.config.authentication.sasl.iam, false)        # Default to false
  msk_sasl_scram_enabled    = try(local.config.settings.msk.config.authentication.sasl.scram, true)       # Default to true
  kafka_username            = local.config.settings.msk.config.enabled ? "kafkamaster_${random_string.kafka_random_letters[0].result}" : local.config.settings.msk.config.username
  kafka_password            = local.config.settings.msk.config.enabled ? random_password.kafka_password[0].result : local.config.settings.msk.config.password
  kafka_broker_list = local.config.settings.msk.config.enabled ? module.msk_kafka_cluster[0].bootstrap_brokers : (
    length(trimspace(local.config.settings.msk.config.msk_bootstrap_brokers_plaintext)) > 0 ? split(",", local.config.settings.msk.config.msk_bootstrap_brokers_plaintext) :
    length(trimspace(local.config.settings.msk.config.msk_bootstrap_brokers_sasl_iam)) > 0 ? split(",", local.config.settings.msk.config.msk_bootstrap_brokers_sasl_iam) :
    length(trimspace(local.config.settings.msk.config.msk_bootstrap_brokers_sasl_scram)) > 0 ? split(",", local.config.settings.msk.config.msk_bootstrap_brokers_sasl_scram) :
    length(trimspace(local.config.settings.msk.config.msk_bootstrap_brokers_tls)) > 0 ? split(",", local.config.settings.msk.config.msk_bootstrap_brokers_tls) :
    []
  )

  ############### S3 ###############
  s3_logs_bucket  = local.config.settings.msk.config.enabled ? module.msk-logs[0].s3_bucket_id : ""
  msk_bucket_name = local.config.settings.msk.config.enabled ? (try(local.config.settings.msk.config.enable_msk_logs, false) ? "msk-kafka-logs-${random_string.kafka_s3_log_random_letters[0].result}" : "") : ""

  kafka_secret_data = local.config.settings.msk.config.enabled ? {
    password = random_password.kafka_password[0].result
    username = local.kafka_username
    } : {
    password = local.config.settings.msk.config.password
    username = local.config.settings.msk.config.username
  }

  api_key_names = [
    "nlpExecutionAssistantApiKey",
    "authHubServiceApiKey",
    "customCodeServiceApiKey",
    "applicationsServiceApiKey",
    "directoryServiceApiKey",
    "teamManagementApiKey",
    "auditsServiceApiKey",
    "authenticationServiceApiKey",
    "metadataServiceApiKey",
    "notificationServiceApiKey",
    "reportsServiceApiKey",
    "vendorsServiceApiKey",
    "tenantsServiceApiKey",
    "webpushServiceApiKey",
    "webhooksServiceApiKey",
    "eventsServiceApiKey",
    "reportsEngineApiKey",
    "reportsSchedulerApiKey",
    "adminsServiceApiKey",
    "integrationsServiceApiKey",
    "identityServiceApiKey",
    "oauthServiceApiKey",
    "subscriptionsServiceApiKey",
    "policyServiceApiKey",
    "eventRetryServiceApiKey",
    "usageTrackingApiKey",
    "envDuplicatorApiKey",
    "dahboardEnvBuilderApiKey",
    "backofficeApiKey",
    "pricingViewsApiKey",
    "emailServiceApiKey",
    "prehookApiKey",
    "logsServiceApiKey",
    "logsStreamingServiceApiKey",
    "entitlementsServiceApiKey",
    "securityEnginesApiKey",
    "securityCenterServiceApiKey",
    "apiGatewayApiKey",
    "signalsServiceApiKey",
    "idgwBackendApiKey",
    "mcpServerApiKey",
    "appIntegrationsApiKey"
  ]

  ################ Validations ######################
  validate_eks_public_access = (
    try(local.config.settings.eks.config.cluster.endpoint_public_access, false) == true &&
    length(try(local.config.settings.eks.config.cluster.endpoint_public_access_cidrs, [])) == 0
  ) ? tobool("Error: When endpoint_public_access is true, endpoint_public_access_cidrs must not be empty") : true
  validate_eks_public_access_cidrs = (
    try(local.config.settings.eks.config.cluster.endpoint_public_access, false) == true
    ? [for cidr in try(local.config.settings.eks.config.cluster.endpoint_public_access_cidrs, []) : can(cidrnetmask(cidr)) ? true : tobool("Error: Invalid CIDR format in endpoint_public_access_cidrs: ${cidr}")]
    : [true]
  )
  validate_environment                 = (can(regex("^[a-zA-Z0-9_]{1,20}$", local.environment)) ? true : tobool("Invalid environment ID format. Please use alphanumeric characters and underscores only, and ensure the length does not exceed 20 characters."))
  validate_cidr                        = (local.config.settings.vpc.enabled ? (can(cidrsubnet(local.config.settings.vpc.cidr, 0, 0)) ? true : tobool("Invalid CIDR block format ${local.config.settings.vpc.cidr}. Please provide a valid CIDR block in the format x.x.x.x/x.")) : true)
  dashboard_static_content_bucket_name = (can(regex("^[a-z0-9.-]{3,54}$", "dashboard-static-content")) ? "dashboard-static-content" : tobool("Invalid bucket name format. Please provide a valid bucket name."))
  pricing_viewes_bucket_name           = (can(regex("^[a-z0-9.-]{3,54}$", "pricing-views-bundles")) ? "pricing-views-bundles" : tobool("Invalid bucket name format. Please provide a valid bucket name."))
  reporting_engine_triggered_reports   = (can(regex("^[a-z0-9-]{1,37}$", "${local.environment}-triggered-reports")) ? lower("${local.environment}-triggered-reports") : tobool("Reporting engine triggered reports bucket name must be lowercase and less than or equal to 37 characters in length"))
  pricing_views_bundles                = (can(regex("^[a-z0-9-]{1,37}$", "${local.environment}-pricing-views-bundles")) ? lower("${local.environment}-pricing-views-bundles") : tobool("Pricing views bundles bucket name must be lowercase and less than or equal to 37 characters in length"))
  tenants_assets                       = (can(regex("^[a-z0-9-]{1,37}$", "${local.environment}-tenants-assets")) ? lower("${local.environment}-tenants-assets") : tobool("Tenants assets bucket name must be lowercase and less than or equal to 37 characters in length"))
  s3_policy                            = (can(regex("^[a-z0-9-]{1,37}$", "${local.environment}-policy")) ? lower("${local.environment}-policy") : tobool("S3 policy bucket name must be lowercase and less than or equal to 37 characters in length"))
  s3_force_destroy_buckets             = try(local.config.settings.s3.force_destroy_buckets, false)
}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_eks_cluster" "external" {
  count = !local.config.settings.eks.config.enabled && try(local.config.settings.eks.config.cluster.name, "") != "" ? 1 : 0
  name  = local.config.settings.eks.config.cluster.name
}

resource "random_string" "kafka_random_letters" {
  count   = local.config.settings.msk.config.enabled ? 1 : 0
  length  = 6
  special = false
  upper   = true
  lower   = true
  numeric = false
}

resource "random_string" "mysql_random_letters" {
  count   = local.config.settings.mysql.config.enabled ? 1 : 0
  length  = 6
  special = false
  upper   = true
  lower   = true
  numeric = false
}

resource "random_password" "redis_password" {
  count            = local.config.settings.redis.config.enabled ? 1 : 0
  length           = 32
  special          = false
  override_special = "!, &, #, $, ^, <, >, -"
}

resource "random_string" "kafka_s3_log_random_letters" {
  count   = local.config.settings.msk.config.enabled ? 1 : 0
  length  = 6
  special = false
  upper   = false
  lower   = true
  numeric = false
}

resource "random_password" "kafka_password" {
  count   = local.config.settings.msk.config.enabled ? 1 : 0
  length  = 32
  special = false
  # override_special = "!#$%&*()"
}

resource "random_password" "mysql_password" {
  count   = local.config.settings.mysql.config.enabled ? 1 : 0
  length  = 32
  special = false
}

resource "random_string" "vpc_random_letters" {
  count   = local.config.settings.vpc.enabled ? 1 : 0
  length  = 6
  special = false
  upper   = false
  lower   = true
  numeric = true
}