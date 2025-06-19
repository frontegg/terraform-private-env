module "msk_kafka_cluster" {
  source  = "terraform-aws-modules/msk-kafka-cluster/aws"
  version = "~> 2.11.1"

  count                      = local.config.settings.msk.config.enabled ? 1 : 0
  name                       = "${local.environment}-msk-${replace(local.config.settings.msk.config.version, ".", "-")}"
  kafka_version              = local.config.settings.msk.config.version
  number_of_broker_nodes     = local.config.settings.msk.config.number_of_broker_nodes
  enhanced_monitoring        = "PER_TOPIC_PER_PARTITION"
  broker_node_client_subnets = local.private_subnet_ids
  broker_node_storage_info = {
    ebs_storage_info = { volume_size = local.config.settings.msk.config.volume_size }
  }
  broker_node_instance_type           = local.config.settings.msk.config.broker_node_instance_type
  broker_node_security_groups         = [module.security_group[0].security_group_id]
  encryption_in_transit_client_broker = local.config.settings.msk.config.encryption_in_transit_client_broker #"PLAINTEXT" "TLS_PLAINTEXT"
  encryption_in_transit_in_cluster    = true
  configuration_name                  = "${local.environment}-msk-configuration"
  configuration_description           = "${local.environment}-msk-configuration"
  configuration_server_properties = {
    "auto.create.topics.enable"  = true
    "delete.topic.enable"        = true
    "default.replication.factor" = "3"
    "min.insync.replicas"        = "2"
  }
  jmx_exporter_enabled    = true
  node_exporter_enabled   = true
  cloudwatch_logs_enabled = true

  s3_logs_enabled = local.config.settings.msk.config.enable_msk_logs
  s3_logs_bucket  = local.s3_logs_bucket
  s3_logs_prefix  = "msk-logs"

  scaling_max_capacity = local.config.settings.msk.config.scaling_max_capacity
  scaling_target_value = local.config.settings.msk.config.scaling_target_value
  client_authentication = {
    unauthenticated = local.msk_allow_unauthenticated
    sasl = {
      iam   = local.msk_sasl_iam_enabled
      scram = local.msk_sasl_scram_enabled
    }
  }
  create_scram_secret_association = local.msk_sasl_scram_enabled
  scram_secret_association_secret_arn_list = [
    aws_secretsmanager_secret.kafka_secret[0].arn
  ]

  create_connect_worker_configuration           = true
  connect_worker_config_name                    = "msk-connector-${local.environment}"
  connect_worker_config_description             = "msk connect worker configuration"
  connect_worker_config_properties_file_content = <<-EOT
key.converter=org.apache.kafka.connect.json.JsonConverter
value.converter=org.apache.kafka.connect.json.JsonConverter
topic.creation.enable=true
EOT

  connect_custom_plugins = local.config.settings.msk.connector.debezium.enabled ? {
    debezium = {
      name                       = "debezium-${local.environment}"
      description                = "Debezium MySQL connector"
      content_type               = "ZIP"
      s3_bucket_arn              = module.s3_debezium_connector[0].s3_bucket_arn
      s3_file_key                = aws_s3_object.debezium_upload[0].key
      s3_object_version          = data.aws_s3_object.debezium_connector[0].version_id
      service_execution_role_arn = aws_iam_role.msk_connect[0].arn
      timeouts = {
        create = "20m"
      }
    }
  } : {}
}

resource "aws_secretsmanager_secret" "kafka_secret" {
  count                   = local.config.settings.msk.config.enabled ? 1 : 0
  name                    = "AmazonMSK_${local.environment}_secret"
  kms_key_id              = aws_kms_key.kafka_scram_key[0].key_id
  policy                  = data.aws_iam_policy_document.kafka_secret_policy.json
  recovery_window_in_days = local.config.settings.secretsManager.secrets.recovery_window_in_days
}

resource "aws_secretsmanager_secret_version" "kafka_secret_version" {
  count         = local.config.settings.msk.config.enabled ? 1 : 0
  secret_id     = aws_secretsmanager_secret.kafka_secret[0].id
  secret_string = jsonencode(local.kafka_secret_data)
}

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3.0"

  count       = local.config.settings.msk.config.enabled ? 1 : 0
  name        = "${local.environment}-kafka"
  description = "Security group for kafka ${local.environment}"
  vpc_id      = local.config.settings.vpc.enabled ? module.vpc[0].vpc_id : data.aws_vpc.existing[0].id

  ingress_cidr_blocks = local.config.settings.vpc.enabled ? module.vpc[0].private_subnets_cidr_blocks : [for subnet in data.aws_subnet.private : subnet.cidr_block]
  ingress_rules = [
    "kafka-broker-tcp",
    "kafka-broker-tls-tcp",
    "kafka-broker-sasl-scram-tcp",
    "kafka-node-exporter-tcp",
    "kafka-jmx-exporter-tcp"
  ]
  ingress_with_cidr_blocks = flatten([
    for cidr in(
      local.config.settings.vpc.enabled ? module.vpc[0].intra_subnets_cidr_blocks : [for s in data.aws_subnet.intra : s.cidr_block]
      ) : {
      from_port   = 3306
      to_port     = 3306
      protocol    = "tcp"
      description = "Allow MySQL from private to intra subnets"
      cidr_blocks = cidr
    }
  ])
  egress_rules = ["all-all"]
}

data "aws_iam_policy_document" "kafka_secret_policy" {
  statement {
    sid    = "AWSKafkaResourcePolicy"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["kafka.amazonaws.com"]
    }
    actions   = ["secretsmanager:getSecretValue"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "kafka_scram_key" {
  count                   = local.config.settings.msk.config.enabled ? 1 : 0
  description             = "KMS key for kafka scram"
  deletion_window_in_days = 10
}

resource "aws_kms_alias" "kafka_scram_key_alias" {
  count         = local.config.settings.msk.config.enabled ? 1 : 0
  name          = "alias/${local.environment}/kafka/scram/key"
  target_key_id = aws_kms_key.kafka_scram_key[0].key_id
}

# Generate unique server ID for Debezium
resource "random_integer" "mysql_server_id" {
  # count = local.config.settings.msk.config.enabled ? 1 : 0
  count = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0
  min   = 100000
  max   = 999999
  keepers = {
    environment = local.environment
  }
}

# IAM role for MSK Connect
resource "aws_iam_role" "msk_connect" {
  count = local.config.settings.msk.config.enabled ? 1 : 0
  name  = "${local.environment}-msk-connect-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "kafkaconnect.amazonaws.com"
        }
      }
    ]
  })
}

# IAM policy for MSK Connect to access S3
resource "aws_iam_role_policy" "msk_connect_s3" {
  count = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0
  name  = "${local.environment}-msk-connect-s3-policy"
  role  = aws_iam_role.msk_connect[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          module.s3_debezium_connector[0].s3_bucket_arn,
          "${module.s3_debezium_connector[0].s3_bucket_arn}/*"
        ]
      }
    ]
  })
}

# S3 bucket policy for MSK Connect access
resource "aws_s3_bucket_policy" "msk_connect" {
  count  = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0 #local.config.settings.msk.connector.debezium.enabled ? 1 : 0
  bucket = split(":", module.s3_debezium_connector[0].s3_bucket_arn)[5]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowMSKConnectAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.msk_connect[0].arn
        }
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          module.s3_debezium_connector[0].s3_bucket_arn,
          "${module.s3_debezium_connector[0].s3_bucket_arn}/*"
        ]
      }
    ]
  })
}

data "aws_s3_object" "debezium_connector" {
  count  = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0 #local.config.settings.msk.connector.debezium.enabled ? 1 : 0
  bucket = module.s3_debezium_connector[0].s3_bucket_id
  key    = aws_s3_object.debezium_upload[0].key
}

resource "aws_mskconnect_connector" "connector" {
  count                = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0 #local.config.settings.msk.connector.debezium.enabled ? 1 : 0
  name                 = "msk-connector-${local.environment}"
  kafkaconnect_version = "2.7.1"
  capacity {
    provisioned_capacity {
      mcu_count    = 1
      worker_count = 1
    }
  }
  log_delivery {
    worker_log_delivery {
      cloudwatch_logs {
        enabled   = true
        log_group = aws_cloudwatch_log_group.connector_log_group[0].name
      }
      s3 {
        enabled = true
        bucket  = local.s3_logs_bucket
        prefix  = "msk-logs"
      }
    }
  }
  connector_configuration = {
    "connector.class"                          = "io.debezium.connector.mysql.MySqlConnector"
    "transforms.unwrap.delete.handling.mode"   = "rewrite"
    "tasks.max"                                = "1"
    "database.history.kafka.topic"             = "dbhistory.identity"
    "transforms"                               = "unwrap"
    "include.schema.changes"                   = "true"
    "tombstones.on.delete"                     = "false"
    "topic.prefix"                             = "identity"
    "transforms.unwrap.drop.tombstones"        = "false"
    "transforms.unwrap.type"                   = "io.debezium.transforms.ExtractNewRecordState"
    "value.converter"                          = "org.apache.kafka.connect.json.JsonConverter"
    "key.converter"                            = "org.apache.kafka.connect.json.JsonConverter"
    "database.allowPublicKeyRetrieval"         = "true"
    "database.user"                            = local.mysql_username
    "database.server.id"                       = random_integer.mysql_server_id[0].result
    "database.history.kafka.bootstrap.servers" = local.kafka_broker_list[0]
    "database.server.name"                     = "identity"
    "database.port"                            = "3306"
    "key.converter.schemas.enable"             = "false"
    "database.hostname"                        = local.mysql_endpoint
    "database.password"                        = random_password.mysql_password[0].result
    "value.converter.schemas.enable"           = "false"
    "transforms.unwrap.add.fields"             = "op,table,source.ts_ms"
    "table.include.list"                       = "frontegg_identity.users,frontegg_identity.users_tenants,frontegg_identity.users_tenants_roles,frontegg_identity.roles"
    "database.include.list"                    = "frontegg_identity"
    "snapshot.mode"                            = "schema_only"
    "snapshot.locking.mode"                    = "none"
    "message.key.columns"                      = "frontegg_identity.users_tenants:vendorId,tenantId,userId;frontegg_identity.users:vendorId,email"
  }
  kafka_cluster {
    apache_kafka_cluster {
      bootstrap_servers = local.kafka_broker_list[0]
      vpc {
        security_groups = [module.security_group[0].security_group_id]
        subnets         = local.private_subnet_ids
      }
    }
  }
  kafka_cluster_client_authentication {
    authentication_type = "NONE"
  }
  kafka_cluster_encryption_in_transit {
    encryption_type = "PLAINTEXT"
  }
  plugin {
    custom_plugin {
      arn      = module.msk_kafka_cluster[0].connect_custom_plugins["debezium"].arn
      revision = module.msk_kafka_cluster[0].connect_custom_plugins["debezium"].latest_revision
    }
  }
  dynamic "worker_configuration" {
    for_each = module.msk_kafka_cluster[0].connect_worker_configuration_arn != "" ? [1] : []
    content {
      arn      = module.msk_kafka_cluster[0].connect_worker_configuration_arn
      revision = module.msk_kafka_cluster[0].connect_worker_configuration_latest_revision
    }
  }
  service_execution_role_arn = aws_iam_role.msk_connect[0].arn
  timeouts {
    create = "15m"
    update = "10m"
    delete = "10m"
  }
  depends_on = [
    module.s3_debezium_connector
  ]
}

resource "aws_cloudwatch_log_group" "connector_log_group" {
  count             = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0
  name              = "${local.environment}-msk-connector-logs"
  retention_in_days = 90
}

data "aws_msk_broker_nodes" "msk_broker_nodes" {
  count       = local.config.settings.msk.config.enabled ? (local.config.settings.msk.connector.debezium.enabled ? 1 : 0) : 0
  cluster_arn = module.msk_kafka_cluster[0].arn
}

data "aws_subnets" "private-subnets" {
  filter {
    name   = "tag:Name"
    values = ["*private*"]
  }
  filter {
    name   = "vpc-id"
    values = [local.vpc_id]
  }

}
