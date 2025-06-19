#!/usr/bin/env python3
"""
MySQL Configuration Verification for Debezium MSK Connector

This script verifies that an RDS MySQL instance meets all the requirements
for deploying a Debezium connector with Amazon MSK.
"""

import argparse
import sys
import boto3
import pymysql
import logging
from typing import Dict, List, Tuple, Optional
import yaml
import botocore

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MySQLDebeziumVerifier:
    def __init__(self, host: str, port: int, user: str, password: str, 
                 database: str = None, rds_instance_id: str = None):
        """Initialize the verifier with connection parameters."""
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.rds_instance_id = rds_instance_id
        self.connection = None
        self.rds_client = boto3.client('rds')
        self.issues = []
        self.warnings = []

    def connect(self) -> bool:
        """Establish a connection to the MySQL database."""
        try:
            self.connection = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database if self.database else None,
                connect_timeout=10
            )
            logger.info(f"Successfully connected to MySQL at {self.host}:{self.port}")
            return True
        except Exception as e:
            self.issues.append(f"Failed to connect to MySQL: {str(e)}")
            logger.error(f"Connection failed: {str(e)}")
            return False

    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()

    def execute_query(self, query: str) -> Optional[List[Dict]]:
        """Execute a query and return the results."""
        if not self.connection:
            self.issues.append("No active database connection")
            return None
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query)
                columns = [col[0] for col in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            self.issues.append(f"Query execution failed: {str(e)}")
            logger.error(f"Query failed: {str(e)}")
            return None

    def check_binlog_format(self) -> bool:
        """Check if binary logging format is set to ROW."""
        results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'binlog_format'")
        if not results:
            return False
        
        binlog_format = results[0].get('Value', '')
        if binlog_format.upper() != 'ROW':
            self.issues.append(f"Binary log format is set to '{binlog_format}', but 'ROW' is required")
            return False
        
        logger.info("Binary log format is correctly set to ROW")
        return True

    def check_binlog_row_image(self) -> bool:
        """Check if binlog_row_image is set to FULL."""
        results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'binlog_row_image'")
        if not results:
            return False
        
        row_image = results[0].get('Value', '')
        if row_image.upper() != 'FULL':
            self.issues.append(f"binlog_row_image is set to '{row_image}', but 'FULL' is required")
            return False
        
        logger.info("binlog_row_image is correctly set to FULL")
        return True

    def check_binlog_enabled(self) -> bool:
        """Check if binary logging is enabled."""
        results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'log_bin'")
        if not results:
            return False
        
        log_bin = results[0].get('Value', '')
        if log_bin.upper() != 'ON' and log_bin != '1':
            self.issues.append("Binary logging is not enabled")
            return False
        
        logger.info("Binary logging is enabled")
        return True

    def check_binlog_expiration(self) -> bool:
        """Check binary log expiration period."""
        results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'binlog_expire_logs_seconds'")
        if not results:
            # Try the older variable if the newer one isn't available
            results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'expire_logs_days'")
            if not results:
                return False
            
            expire_days = int(results[0].get('Value', '0'))
            if expire_days < 1:
                self.issues.append("Binary logs expire immediately, which is not suitable for Debezium")
                return False
            elif expire_days < 3:
                self.warnings.append(f"Binary logs expire after {expire_days} days, which might be too short for reliable CDC")
            
            logger.info(f"Binary logs expire after {expire_days} days")
        else:
            expire_seconds = int(results[0].get('Value', '0'))
            expire_days = expire_seconds / 86400
            if expire_seconds < 86400:  # Less than 1 day
                self.issues.append(f"Binary logs expire after {expire_seconds} seconds, which is too short for Debezium")
                return False
            elif expire_days < 3:
                self.warnings.append(f"Binary logs expire after {expire_days:.1f} days, which might be too short for reliable CDC")
            
            logger.info(f"Binary logs expire after {expire_days:.1f} days")
        
        return True

    def check_user_privileges(self) -> bool:
        """Check if the user has the required privileges for Debezium."""
        required_privileges = [
            'SELECT', 'RELOAD', 'SHOW DATABASES', 'REPLICATION SLAVE', 'REPLICATION CLIENT'
        ]
        
        # Check global privileges
        results = self.execute_query(f"SHOW GRANTS FOR '{self.user}'@'%'")
        if not results:
            # Try with current host
            results = self.execute_query("SHOW GRANTS")
            if not results:
                return False
        
        # Parse grants
        has_all_privileges = False
        missing_privileges = required_privileges.copy()
        
        for grant_row in results:
            grant_str = list(grant_row.values())[0]
            
            # Check for ALL PRIVILEGES
            if "ALL PRIVILEGES" in grant_str:
                has_all_privileges = True
                missing_privileges = []
                break
            
            # Check for specific privileges
            for privilege in required_privileges:
                if privilege in grant_str:
                    if privilege in missing_privileges:
                        missing_privileges.remove(privilege)
        
        if missing_privileges:
            self.issues.append(f"User '{self.user}' is missing required privileges: {', '.join(missing_privileges)}")
            return False
        
        logger.info(f"User '{self.user}' has all required privileges")
        return True

    def check_rds_parameters(self) -> bool:
        """Check RDS parameter group settings if RDS instance ID is provided."""
        if not self.rds_instance_id:
            self.warnings.append("No RDS instance ID provided, skipping RDS parameter checks")
            return True
        
        try:
            # Get the RDS instance details
            response = self.rds_client.describe_db_instances(
                DBInstanceIdentifier=self.rds_instance_id
            )
            
            if not response['DBInstances']:
                self.issues.append(f"RDS instance '{self.rds_instance_id}' not found")
                return False
            
            instance = response['DBInstances'][0]
            parameter_group = instance['DBParameterGroups'][0]['DBParameterGroupName']
            
            # Get the parameter group details
            params_response = self.rds_client.describe_db_parameters(
                DBParameterGroupName=parameter_group
            )
            
            # Check critical parameters
            param_dict = {param['ParameterName']: param for param in params_response['Parameters']}
            
            # Check binlog format
            if 'binlog_format' in param_dict:
                binlog_format = param_dict['binlog_format'].get('ParameterValue')
                if binlog_format and binlog_format.upper() != 'ROW':
                    self.issues.append(f"RDS parameter 'binlog_format' is set to '{binlog_format}', but 'ROW' is required")
            
            # Check binlog row image
            if 'binlog_row_image' in param_dict:
                row_image = param_dict['binlog_row_image'].get('ParameterValue')
                if row_image and row_image.upper() != 'FULL':
                    self.issues.append(f"RDS parameter 'binlog_row_image' is set to '{row_image}', but 'FULL' is required")
            
            logger.info(f"Checked RDS parameter group '{parameter_group}'")
            return len(self.issues) == 0
            
        except Exception as e:
            self.warnings.append(f"Failed to check RDS parameters: {str(e)}")
            logger.error(f"RDS parameter check failed: {str(e)}")
            return True  # Don't fail the overall check for this

    def check_gtid_mode(self) -> bool:
        """Check if GTID mode is enabled (recommended for Debezium)."""
        results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'gtid_mode'")
        if not results:
            return True  # Skip this check if we can't determine
        
        gtid_mode = results[0].get('Value', '')
        if gtid_mode.upper() != 'ON':
            self.warnings.append(f"GTID mode is '{gtid_mode}', but 'ON' is recommended for reliable CDC")
            logger.warning(f"GTID mode is set to '{gtid_mode}', ON is recommended")
        else:
            logger.info("GTID mode is correctly enabled")
        
        return True

    def check_server_id(self) -> bool:
        """Check if server_id is set to a non-default value."""
        results = self.execute_query("SHOW GLOBAL VARIABLES LIKE 'server_id'")
        if not results:
            return True  # Skip this check if we can't determine
        
        server_id = results[0].get('Value', '')
        if server_id == '0' or server_id == '1':
            self.warnings.append(f"server_id is set to '{server_id}', which might be a default value")
            logger.warning(f"server_id is set to '{server_id}', consider using a unique value")
        else:
            logger.info(f"server_id is set to '{server_id}'")
        
        return True

    def check_table_primary_keys(self) -> bool:
        """Check if tables have primary keys (required for Debezium)."""
        if not self.database:
            self.warnings.append("No database specified, skipping table primary key checks")
            return True
        
        # Get all tables in the database
        tables = self.execute_query(f"SHOW TABLES FROM `{self.database}`")
        if not tables:
            return True
        
        tables_without_pk = []
        
        for table_row in tables:
            table_name = list(table_row.values())[0]
            
            # Check if the table has a primary key
            pk_check = self.execute_query(
                f"SELECT COUNT(*) as pk_count FROM information_schema.table_constraints "
                f"WHERE constraint_type = 'PRIMARY KEY' AND table_schema = '{self.database}' "
                f"AND table_name = '{table_name}'"
            )
            
            if pk_check and int(pk_check[0]['pk_count']) == 0:
                tables_without_pk.append(table_name)
        
        if tables_without_pk:
            self.issues.append(f"Tables without primary keys: {', '.join(tables_without_pk)}")
            logger.warning(f"Found {len(tables_without_pk)} tables without primary keys")
            return False
        
        logger.info(f"All tables in database '{self.database}' have primary keys")
        return True

    def run_all_checks(self) -> bool:
        """Run all verification checks."""
        if not self.connect():
            return False
        
        try:
            checks = [
                self.check_binlog_enabled,
                self.check_binlog_format,
                self.check_binlog_row_image,
                self.check_binlog_expiration,
                self.check_user_privileges,
                self.check_gtid_mode,
                self.check_server_id,
                self.check_table_primary_keys,
                self.check_rds_parameters
            ]
            
            results = [check() for check in checks]
            return all(results)
        finally:
            self.close()

    def print_summary(self):
        """Print a summary of the verification results."""
        print("\n" + "=" * 80)
        print("MYSQL CONFIGURATION VERIFICATION FOR DEBEZIUM")
        print("=" * 80)
        
        if not self.issues and not self.warnings:
            print("\n✅ All checks passed! MySQL is properly configured for Debezium.")
        else:
            if not self.issues:
                print("\n✅ No critical issues found.")
            else:
                print(f"\n❌ {len(self.issues)} critical issues found:")
                for i, issue in enumerate(self.issues, 1):
                    print(f"  {i}. {issue}")
            
            if self.warnings:
                print(f"\n⚠️  {len(self.warnings)} warnings:")
                for i, warning in enumerate(self.warnings, 1):
                    print(f"  {i}. {warning}")
        
        print("\n" + "=" * 80)
        
        if self.issues:
            print("\nRECOMMENDED ACTIONS:")
            if any("binlog_format" in issue for issue in self.issues):
                print("- Set binlog_format = ROW in MySQL configuration")
            if any("binlog_row_image" in issue for issue in self.issues):
                print("- Set binlog_row_image = FULL in MySQL configuration")
            if any("Binary logging is not enabled" in issue for issue in self.issues):
                print("- Enable binary logging by setting log_bin = ON")
            if any("expire" in issue for issue in self.issues):
                print("- Increase binlog retention period (binlog_expire_logs_seconds or expire_logs_days)")
            if any("privileges" in issue for issue in self.issues):
                print("- Grant the required privileges to the database user:")
                print("  GRANT SELECT, RELOAD, SHOW DATABASES, REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO 'user'@'%';")
            if any("primary keys" in issue for issue in self.issues):
                print("- Add primary keys to all tables that will be captured by Debezium")
            
            print("\nFor RDS instances, these changes need to be made in the parameter group.")
        
        print("=" * 80 + "\n")


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Verify MySQL configuration for Debezium MSK Connector'
    )
    parser.add_argument('--host', required=True, help='MySQL host address')
    parser.add_argument('--port', type=int, default=3306, help='MySQL port (default: 3306)')
    parser.add_argument('--user', required=True, help='MySQL username')
    parser.add_argument('--password', required=True, help='MySQL password')
    parser.add_argument('--database', help='MySQL database name (optional)')
    parser.add_argument('--rds-instance-id', help='RDS instance identifier (optional)')
    
    return parser.parse_args()


def get_bucket_region(bucket_name):
    """Return the region of the given S3 bucket."""
    s3 = boto3.client('s3')
    try:
        response = s3.get_bucket_location(Bucket=bucket_name)
        # 'LocationConstraint' is None for us-east-1
        region = response.get('LocationConstraint') or 'us-east-1'
        return region
    except botocore.exceptions.ClientError as e:
        print(f"Error fetching region for bucket {bucket_name}: {e}")
        return None

def verify_s3_bucket_region(bucket_arn, config_region):
    """Verify the S3 bucket is in the same region as config_region."""
    # Extract bucket name from ARN: arn:aws:s3:::bucket-name
    bucket_name = bucket_arn.split(':')[-1].replace(':::','').replace('::','')
    bucket_region = get_bucket_region(bucket_name)
    if not bucket_region:
        print(f"Could not determine region for bucket {bucket_name}")
        sys.exit(1)
    if bucket_region != config_region:
        print(f"\n❌ S3 bucket '{bucket_name}' is in region '{bucket_region}', but deployment region is '{config_region}'.\n")
        sys.exit(1)
    print(f"\n✅ S3 bucket '{bucket_name}' is in the correct region '{config_region}'.\n")

def main():
    """Main entry point."""
    # --- S3 region check ---
    try:
        with open('config.yaml') as f:
            config = yaml.safe_load(f)
        bucket_arn = config['settings']['msk']['config']['connector']['debezium']['s3_bucket_arn']
        deployment_region = config['global']['region']
        verify_s3_bucket_region(bucket_arn, deployment_region)
    except Exception as e:
        print(f"Error loading config.yaml or verifying S3 bucket region: {e}")
        sys.exit(1)

    args = parse_args()
    verifier = MySQLDebeziumVerifier(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
        rds_instance_id=args.rds_instance_id
    )
    verifier.run_all_checks()
    verifier.print_summary()
    # Exit with non-zero status if there are issues
    if verifier.issues:
        sys.exit(1)


if __name__ == "__main__":
    main()
