# All available versions: http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_MySQL.html#MySQL.Concepts.VersionMgmt
module "rds_mysql" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.12.0"

  count                                 = local.config.settings.mysql.config.enabled ? 1 : 0
  identifier                            = "${local.environment}-mysql${replace(local.config.settings.mysql.config.engine_version, ".", "-")}"
  engine                                = "mysql"
  engine_version                        = local.config.settings.mysql.config.engine_version
  major_engine_version                  = local.config.settings.mysql.config.major_engine_version
  family                                = local.config.settings.mysql.config.family
  instance_class                        = local.config.settings.mysql.config.instance_class
  storage_type                          = try(local.config.settings.mysql.config.storage.type, "gp3")
  allocated_storage                     = local.config.settings.mysql.config.storage.allocated
  max_allocated_storage                 = local.config.settings.mysql.config.storage.max_allocated
  port                                  = local.config.settings.mysql.config.port
  multi_az                              = local.config.settings.mysql.config.multi_az
  backup_retention_period               = local.config.settings.mysql.config.backup_retention_period
  maintenance_window                    = local.config.settings.mysql.config.maintenance_window
  backup_window                         = local.config.settings.mysql.config.backup_window
  enabled_cloudwatch_logs_exports       = local.config.settings.mysql.config.enabled_cloudwatch_logs_exports
  create_cloudwatch_log_group           = local.config.settings.mysql.config.create_cloudwatch_log_group
  skip_final_snapshot                   = local.config.settings.mysql.config.skip_final_snapshot
  deletion_protection                   = local.config.settings.mysql.config.deletion_protection
  performance_insights_enabled          = local.config.settings.mysql.config.performance_insights_enabled
  performance_insights_retention_period = local.config.settings.mysql.config.performance_insights_retention_period
  create_monitoring_role                = true
  monitoring_interval                   = 60
  db_name                               = null
  username                              = local.mysql_username
  password                              = random_password.mysql_password[0].result
  manage_master_user_password           = false
  create_db_subnet_group                = true
  subnet_ids                            = local.config.settings.vpc.enabled ? module.vpc[0].intra_subnets : [for subnet in data.aws_subnet.intra : subnet.id]
  vpc_security_group_ids                = [module.mysql_sg[0].security_group_id]
  option_group_timeouts = {
    create = "5m"
    update = "10m"
    delete = "5m"
  }
  parameters = [
    {
      name         = "slow_query_log"
      value        = "1"
      apply_method = "immediate"
    },
    {
      name         = "general_log"
      value        = "0"
      apply_method = "immediate"
    },
    {
      name         = "long_query_time"
      value        = "2"
      apply_method = "immediate"
    },
    {
      name         = "log_output"
      value        = "FILE"
      apply_method = "immediate"
    },
    {
      name         = "autocommit"
      value        = "1"
      apply_method = "immediate"
    },
    {
      name         = "binlog_format"
      value        = "ROW"
      apply_method = "immediate"
    },
    {
      name         = "binlog_row_image"
      value        = "FULL"
      apply_method = "immediate"
    },
    {
      name         = "log_slow_admin_statements"
      value        = "1"
      apply_method = "immediate"
    },
    {
      name         = "innodb_print_all_deadlocks"
      value        = "1"
      apply_method = "immediate"
    },
    {
      name         = "performance_schema_max_sql_text_length"
      value        = "2048"
      apply_method = "pending-reboot"
    },
    {
      name         = "transaction_isolation"
      value        = "READ-COMMITTED"
      apply_method = "immediate"
    },
    {
      name         = "max_execution_time"
      value        = "15000"
      apply_method = "immediate"
    },
    {
      name         = "character_set_client"
      value        = "utf8mb4"
      apply_method = "immediate"
    },
    {
      name         = "character_set_server"
      value        = "utf8mb4"
      apply_method = "immediate"
    }
  ]
}


module "mysql_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 5.3.0"

  count               = local.config.settings.mysql.config.enabled ? 1 : 0
  name                = "${local.environment}-mysql"
  description         = "Security group for ${local.environment}-mysql"
  vpc_id              = local.config.settings.vpc.enabled ? module.vpc[0].vpc_id : data.aws_vpc.existing[0].id
  ingress_cidr_blocks = local.config.settings.vpc.enabled ? module.vpc[0].private_subnets_cidr_blocks : [for subnet in data.aws_subnet.private : subnet.cidr_block]
  ingress_rules = [
    "mysql-tcp"
  ]
}


