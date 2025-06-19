resource "aws_secretsmanager_secret" "env_main_secret" {
  name                    = "${local.environment}-frontegg-private-deployment-main-secret"
  recovery_window_in_days = local.config.settings.secretsManager.secrets.recovery_window_in_days
}

resource "random_uuid" "api_keys" {
  for_each = toset(local.api_key_names)
}

resource "tls_private_key" "auth" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "random_uuid" "fronteggClientId" {}

resource "random_uuid" "fronteggApiKey" {}

resource "random_uuid" "customDomains" {}

resource "random_uuid" "logsServiceEncryptionKey" {}

resource "random_uuid" "teamManagement" {}

resource "random_uuid" "vendors_apiKeySecret" {}

resource "random_uuid" "vendors_webhookSecret" {}

resource "random_uuid" "vendors_prehookSecret" {}

resource "random_uuid" "oauthServiceSigningKey" {}

resource "random_string" "cryptoKeyV2" {
  length  = 32
  special = false
}

resource "random_string" "oauthServiceCryptoKey" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret_version" "env_secret_version" {
  secret_id = aws_secretsmanager_secret.env_main_secret.id
  secret_string = templatefile(
    "${path.module}/templates/secrets.template.tpl", {
      mysql_endpoint                 = local.mysql_endpoint
      mysql_password                 = local.mysql_password
      mysql_username                 = local.mysql_username
      kafka_password                 = local.kafka_password
      kafka_username                 = local.kafka_username
      kafka_broker_list              = local.kafka_broker_list[0]
      kafka_all_brokers              = join(",", local.kafka_broker_list)
      redis_endpoint                 = try(module.redis[0].elasticache_replication_group_primary_endpoint_address, local.config.settings.redis.config.endpoint)
      redis_username                 = try(local.redis_secrets.username, "")
      redis_password                 = local.redis_secrets.password
      redis_port                     = local.config.settings.redis.config.enabled ? module.redis[0].elasticache_port : local.redis_config.port
      mongo_connection_string        = local.mongo_connection_string
      api_keys                       = { for k in local.api_key_names : k => random_uuid.api_keys[k].result }
      AUTH_PRIVATE_KEY_AUTOGENERTAED = base64encode(tls_private_key.auth.private_key_pem)
      AUTH_PUBLIC_KEY_AUTOGENERTAED  = base64encode(tls_private_key.auth.public_key_pem)
      fronteggClientId               = random_uuid.fronteggClientId.result
      fronteggApiKey                 = random_uuid.fronteggApiKey.result
      customDomains                  = random_uuid.customDomains.result
      logsServiceEncryptionKey       = random_uuid.logsServiceEncryptionKey.result
      teamManagement                 = random_uuid.teamManagement.result
      vendors_apiKeySecret           = random_uuid.vendors_apiKeySecret.result
      vendors_webhookSecret          = random_uuid.vendors_webhookSecret.result
      vendors_prehookSecret          = random_uuid.vendors_prehookSecret.result
      oauthServiceSigningKey         = random_uuid.oauthServiceSigningKey.result
      cryptoKeyV2                    = random_string.cryptoKeyV2.result
      oauthServiceCryptoKey          = random_string.oauthServiceCryptoKey.result
    }
  )
}

