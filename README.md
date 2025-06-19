# Frontegg Customer Environment - Terraform Infrastructure

This directory contains the Infrastructure as Code (IaC) configuration for the Frontegg customer environment. It uses Terraform to provision and manage AWS cloud resources and Kubernetes deployments required for the Frontegg platform.

## Architecture Overview

The infrastructure is designed as a modular, configuration-driven deployment that supports both new resource creation and integration with existing infrastructure. All configuration is centralized in `config/config.yaml`, which drives the Terraform deployment through dynamic resource provisioning.

## Configuration-Driven Approach

### Core Configuration: `config/config.yaml`

The `config/config.yaml` file is the central configuration source that defines:

- **Global Settings**: AWS region, environment name, customer identifier, and project name
- **Resource Configuration**: Detailed settings for each infrastructure component
- **Feature Toggles**: Enable/disable specific components based on requirements
- **Integration Settings**: Configuration for external resources when not provisioning new ones

The configuration is loaded in `locals.tf` using:
```hcl
config = yamldecode(file("config/config.yaml"))
```

### Configuration Structure

#### Global Section
```yaml
global:
  region: us-east-1           # AWS region for deployment
  environment: prod           # Environment identifier (dev/staging/prod)
  customer: private-env       # Customer identifier
  project: frontegg-private-env # Project name
```

#### Settings Section
Each major infrastructure component has its own configuration block under `settings`:

- **vpc**: Virtual Private Cloud configuration
- **s3**: S3 bucket settings
- **secretsManager**: AWS Secrets Manager configuration
- **msk**: Managed Streaming for Kafka (MSK) settings
- **mysql**: RDS MySQL database configuration
- **redis**: ElastiCache Redis configuration
- **mongo**: MongoDB connection settings
- **eks**: Elastic Kubernetes Service configuration
- **external_secrets**: External Secrets Operator settings

## File Structure and Components

### Core Terraform Files

#### `providers.tf`
Defines Terraform providers and their configurations:
- **AWS Provider**: Configured with region from config.yaml and default tags
- **Kubernetes Provider**: Connects to EKS cluster for K8s resource management
- **Helm Provider**: Manages Helm chart deployments
- **Backend Configuration**: S3 backend for state management

#### `locals.tf`
Central logic hub that:
- Loads and parses `config/config.yaml`
- Defines computed values and conditional logic
- Handles resource naming and tagging
- Manages integration between created and external resources
- Includes validation rules for configuration values

#### `outputs.tf`
Defines Terraform outputs for:
- EKS cluster information (standard and auto-mode)
- Database connection details (MySQL, Redis)
- MSK cluster information
- VPC details
- S3 bucket IDs and ARNs

### Infrastructure Components

#### `vpc.tf`
**Purpose**: Network infrastructure management
**Configuration**: `settings.vpc`
**Features**:
- Conditional VPC creation based on `vpc.enabled`
- Automatic subnet calculation using CIDR blocks
- Support for existing VPC integration
- Multi-AZ deployment across 3 availability zones

**Key Logic**:
```hcl
# Creates VPC only if enabled in config
resource "aws_vpc" "main" {
  count = local.config.settings.vpc.enabled ? 1 : 0
  # ... configuration from config.yaml
}
```

#### `eks.tf`
**Purpose**: Kubernetes cluster management
**Configuration**: `settings.eks`
**Features**:
- Standard EKS cluster or EKS Auto Mode
- Managed node groups with configurable instance types
- SPOT or ON_DEMAND capacity types
- Public/private endpoint access control
- Integration with existing clusters

**Conditional Deployment**:
- Creates EKS cluster if `eks.config.enabled = true`
- Uses existing cluster if `enabled = false` (requires cluster name)
- Supports both standard and auto-mode EKS clusters

#### `mysql.tf`
**Purpose**: RDS MySQL database management
**Configuration**: `settings.mysql`
**Features**:
- RDS MySQL instance with configurable engine version
- Automated backup and maintenance windows
- Performance Insights and CloudWatch logging
- Multi-AZ deployment option
- Integration with existing databases

**Security**:
- Random password generation for new instances
- Secrets Manager integration for credential storage
- VPC security group configuration

#### `redis.tf`
**Purpose**: ElastiCache Redis cluster management
**Configuration**: `settings.redis`
**Features**:
- Redis replication group with configurable node types
- Multi-AZ deployment
- TLS encryption support
- Integration with existing Redis instances

#### `msk.tf`
**Purpose**: Managed Streaming for Kafka
**Configuration**: `settings.msk`
**Features**:
- MSK cluster with configurable broker nodes
- Multiple authentication methods (IAM, SCRAM, unauthenticated)
- Auto-scaling configuration
- CloudWatch logging integration
- Debezium connector support for CDC

**Advanced Features**:
- S3 integration for Kafka logs
- Custom Kafka configurations
- Security group management
- Integration with existing Kafka clusters

**Debezium MySQL Configuration Verification**:
For MySQL databases used with Debezium CDC, use the verification script:
```bash
cd config
python3 verify_mysql_for_debezium.py --host <mysql-host> --user <username> --password <password> --database <database> --rds-instance-id <rds-id>
```

This script verifies:
- Binary logging is enabled and configured correctly
- User has required privileges (SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT)
- All tables have primary keys (required for Debezium)
- GTID mode and other CDC-specific settings

#### `s3.tf`
**Purpose**: S3 bucket management for various services
**Configuration**: `settings.s3`
**Buckets Created**:
- Policy storage bucket
- Reporting engine triggered reports
- Pricing views bundles
- Dashboard static content
- Tenant assets
- MSK logs (if MSK logging enabled)
- Debezium connector storage

#### `external-secrets.tf`
**Purpose**: External Secrets Operator deployment
**Configuration**: `settings.external_secrets`
**Features**:
- Helm chart deployment of External Secrets Operator
- AWS Secrets Manager integration
- IRSA (IAM Roles for Service Accounts) configuration
- Custom resource definitions for secret synchronization

#### `secrets.tf`
**Purpose**: AWS Secrets Manager integration
**Features**:
- Stores database credentials
- API keys management
- Integration with External Secrets Operator
- Configurable recovery windows

## Usage Instructions

### Prerequisites
1. **Terraform**: Install [Terraform](https://www.terraform.io/downloads.html) (version ~> 1.0)
2. **AWS CLI**: Configure AWS credentials with appropriate permissions
3. **kubectl**: For Kubernetes cluster management (if EKS enabled)
4. **Helm**: For Helm chart deployments (if EKS enabled)
5. **Python 3.6+**: For configuration helper scripts and MySQL verification
6. **Python packages**: Install required packages for helper scripts:
   ```bash
   pip install boto3 pymysql pyyaml jinja2
   ```

### Configuration Management

#### Using the Configuration Helper Script
The `config/main.py` script provides an interactive way to generate `config.yaml`:

```bash
cd config
python3 main.py
```

This script:
- Guides through configuration options
- Validates input values
- Generates `config.yaml` from the Jinja2 template
- Provides configuration preview

#### Manual Configuration
Edit `config/config.yaml` directly, ensuring:
- Valid YAML syntax
- Correct data types for each setting
- Required fields are populated
- CIDR blocks and other network settings are valid

### Deployment Process

1. **Initialize Terraform**:
   ```bash
   terraform init -backend-config=backend.config.tfvars
   ```

2. **Review Configuration**:
   ```bash
   terraform plan
   ```

3. **Deploy Infrastructure**:
   ```bash
   terraform apply
   ```

4. **Access Outputs**:
   ```bash
   terraform output
   ```

### Configuration Patterns

#### New Infrastructure Deployment
For creating all new resources:
```yaml
settings:
  vpc:
    enabled: true
    cidr: "10.0.0.0/16"
  eks:
    config:
      enabled: true
  mysql:
    config:
      enabled: true
  # ... other services enabled
```

#### Hybrid Deployment (Mix of New and Existing)
For integrating with existing infrastructure:
```yaml
settings:
  vpc:
    enabled: false
    id: "vpc-existing123"
    cidr: "10.1.0.0/16"
  eks:
    config:
      enabled: false
      cluster:
        name: "existing-cluster"
  mysql:
    config:
      enabled: true  # Create new MySQL
  # ... mix of enabled/disabled services
```

## Advanced Features

### Validation and Error Handling
The `locals.tf` file includes comprehensive validation:
- CIDR block format validation
- Environment naming conventions
- EKS public access configuration validation
- S3 bucket naming validation

### Dynamic Resource Naming
Resources are named using a consistent pattern:
```hcl
name = "${local.customer}-${local.environment}-${service}"
```

### Conditional Resource Creation
All major resources use conditional creation:
```hcl
count = local.config.settings.service.enabled ? 1 : 0
```

### Integration Flexibility
The infrastructure supports:
- **Full Greenfield**: All resources created new
- **Full Brownfield**: All resources are existing
- **Hybrid**: Mix of new and existing resources

## Troubleshooting

### Common Issues

1. **Configuration Validation Errors**:
   - Check YAML syntax in `config.yaml`:
     ```bash
     # Validate YAML syntax
     python3 -c "import yaml; yaml.safe_load(open('config/config.yaml'))"
     
     # Or use yq if installed
     yq eval '.' config/config.yaml
     ```
   - Verify required fields are populated
   - Validate CIDR blocks and network configurations:
     ```bash
     # Check CIDR block validity
     python3 -c "import ipaddress; print(ipaddress.IPv4Network('10.0.0.0/16'))"
     ```

2. **Provider Authentication**:
   - **Diagnose AWS authentication failures**:
     ```bash
     # Step 1: Check if AWS CLI can authenticate
     aws sts get-caller-identity
     
     # Step 2: Check current AWS configuration
     aws configure list
     
     # Step 3: Check which profile is being used
     echo $AWS_PROFILE
     aws configure list-profiles
     
     # Step 4: Check if credentials are expired (for temporary credentials)
     aws sts get-session-token --duration-seconds 3600
     
     # Step 5: Test with specific profile
     aws sts get-caller-identity --profile your-profile-name
     
     # Step 6: Check environment variables that might override config
     env | grep AWS
     ```
   - **Common authentication issues and fixes**:
     ```bash
     # Issue: No credentials configured
     aws configure
     # Enter: Access Key ID, Secret Access Key, Region, Output format
     
     # Issue: Wrong profile being used
     export AWS_PROFILE=correct-profile-name
     # Or unset to use default
     unset AWS_PROFILE
     
     # Issue: Expired temporary credentials (if using STS/SSO)
     aws sso login --profile your-sso-profile
     # Or for assume role
     aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/ROLE --role-session-name session
     
     # Issue: Wrong region
     aws configure set region us-east-1
     # Or check current region
     aws configure get region
     
     # Issue: Credentials file corruption
     cat ~/.aws/credentials
     cat ~/.aws/config
     # If corrupted, reconfigure:
     rm ~/.aws/credentials ~/.aws/config
     aws configure
     ```
   - **Verify IAM permissions** after authentication works:
     ```bash
     # Test basic permissions
     aws iam get-user
     aws ec2 describe-vpcs --max-items 1
     aws eks list-clusters
     aws rds describe-db-instances --max-items 1
     
     # Check specific VPC access (replace with your VPC ID)
     aws ec2 describe-vpcs --vpc-ids vpc-0ad20d3162e42d15c
     ```
   - **Check region availability for requested services**:
     ```bash
     # List available regions
     aws ec2 describe-regions --output table
     
     # Check service availability in region
     aws ec2 describe-availability-zones --region us-east-1
     ```

3. **Resource Dependencies**:
   - Review Terraform plan for dependency issues:
     ```bash
     # Generate and review plan
     terraform plan -out=tfplan
     
     # Show detailed plan
     terraform show tfplan
     ```
   - Ensure existing resources (if referenced) exist:
     ```bash
     # Check if VPC exists (if using existing VPC)
     aws ec2 describe-vpcs --vpc-ids vpc-12345678
     
     # Check if EKS cluster exists (if using existing cluster)
     aws eks describe-cluster --name existing-cluster-name
     
     # Check if RDS instance exists (if using existing database)
     aws rds describe-db-instances --db-instance-identifier existing-db-id
     ```
   - Check security group and network configurations:
     ```bash
     # List security groups in VPC
     aws ec2 describe-security-groups --filters "Name=vpc-id,Values=vpc-12345678"
     
     # Check subnet configurations
     aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-12345678"
     ```

4. **MySQL/Debezium Configuration Issues**:
   - Run the MySQL verification script before enabling Debezium:
     ```bash
     cd config
     python3 verify_mysql_for_debezium.py --host mydb.cluster-xyz.us-east-1.rds.amazonaws.com --user admin --password mypassword --database myapp --rds-instance-id mydb
     ```
   - **Binary logging not enabled or wrong format**:
     ```sql
     -- For RDS: modify parameter group
     -- Set binlog_format = ROW
     -- Set log_bin = 1 (if not already enabled)
     ```
   - **Missing table primary keys**:
     ```sql
     -- Add primary key to tables without one
     ALTER TABLE your_table ADD COLUMN id INT AUTO_INCREMENT PRIMARY KEY;
     -- Or add composite primary key
     ALTER TABLE your_table ADD PRIMARY KEY (column1, column2);
     ```
   - **Insufficient user privileges**:
     ```sql
     GRANT SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'your_user'@'%';
     FLUSH PRIVILEGES;
     ```
   - **For RDS instances**: Modify parameter group settings and reboot instance for changes to take effect

### Debugging
- Use `terraform plan` to preview changes:
  ```bash
  # Basic plan
  terraform plan
  
  # Plan with specific target
  terraform plan -target=module.eks
  
  # Plan with variable file
  terraform plan -var-file="custom.tfvars"
  ```
- Enable Terraform debug logging:
  ```bash
  # Enable debug logging
  export TF_LOG=DEBUG
  export TF_LOG_PATH=./terraform.log
  terraform plan
  
  # Or for specific operations
  TF_LOG=DEBUG terraform apply
  ```
- Review AWS CloudTrail for API call details:
  ```bash
  # Check recent CloudTrail events
  aws logs filter-log-events --log-group-name CloudTrail/YourLogGroup --start-time $(date -d '1 hour ago' +%s)000
  ```
- Check resource-specific logs in AWS CloudWatch:
  ```bash
  # List log groups
  aws logs describe-log-groups
  
  # Get recent log events
  aws logs get-log-events --log-group-name /aws/eks/cluster-name/cluster --log-stream-name stream-name
  
  # Check EKS cluster status
  aws eks describe-cluster --name cluster-name --query 'cluster.status'
  
  # Check RDS instance status
  aws rds describe-db-instances --db-instance-identifier db-name --query 'DBInstances[0].DBInstanceStatus'
  ```

## Security Considerations

- **Secrets Management**: All sensitive data stored in AWS Secrets Manager
- **Network Security**: VPC security groups restrict access appropriately
- **Encryption**: TLS/SSL enabled for all data in transit
- **IAM**: Least privilege access patterns implemented
- **Backup**: Automated backup strategies for databases

## Maintenance and Updates

- **Configuration Changes**: Update `config.yaml` and run `terraform apply`
- **Version Updates**: Review provider version constraints in `providers.tf`
- **State Management**: Ensure Terraform state is properly backed up
- **Monitoring**: Implement CloudWatch monitoring for all resources

This infrastructure provides a robust, scalable foundation for the Frontegg platform with the flexibility to adapt to various deployment scenarios and requirements. 